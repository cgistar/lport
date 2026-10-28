package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"lport/internal/model"
)

const (
	// dialTimeout 连接目标的超时；域名目标每个新连接 / UDP 会话都会重新解析。
	dialTimeout = 10 * time.Second
	// udpIdle UDP 会话空闲超时，与 realm 后端保持一致。
	udpIdle = 120 * time.Second
	// maxUDPSessions 每条规则的 UDP 会话上限，防止大量源地址耗尽文件描述符。
	maxUDPSessions = 4096
)

// Builtin 在 lport 进程内用标准库实现 TCP/UDP 转发，不依赖外部工具。
type Builtin struct {
	mu   sync.Mutex
	fwds map[string][]*forwarder // rule id → 每个协议一个转发器
}

func NewBuiltin() *Builtin { return &Builtin{fwds: map[string][]*forwarder{}} }

func (b *Builtin) Name() string     { return model.BackendBuiltin }
func (b *Builtin) Available() error { return nil }

func (b *Builtin) Sync(rules []model.Rule) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	want := map[string]model.Rule{}
	for _, r := range enabled(rules) {
		want[r.ID] = r
	}
	// 先停掉删除或变更的规则，释放端口
	for id, fs := range b.fwds {
		if r, ok := want[id]; ok && len(fs) > 0 && fs[0].rule().SameForward(r) {
			continue
		}
		for _, f := range fs {
			f.stop()
		}
		delete(b.fwds, id)
	}
	var errs []string
	for id, r := range want {
		if fs, ok := b.fwds[id]; ok {
			for _, f := range fs {
				f.setRule(r) // 名称等非转发字段更新
			}
			continue
		}
		var fs []*forwarder
		var failed bool
		for _, proto := range r.Protos() {
			f, err := startForwarder(r, proto)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s 启动失败（%s/%d）: %s", b.Name(), proto, r.ListenPort, err))
				failed = true
				break
			}
			fs = append(fs, f)
		}
		// 某个协议失败时整条规则不启动，由调用方回滚
		if failed {
			for _, f := range fs {
				f.stop()
			}
			continue
		}
		b.fwds[id] = fs
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "；"))
	}
	return nil
}

func (b *Builtin) Status() map[string]RuleStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := map[string]RuleStatus{}
	for id, fs := range b.fwds {
		st := RuleStatus{State: "running"}
		var errs []string
		for _, f := range fs {
			if e := f.lastErr(); e != "" {
				st.State = "error"
				errs = append(errs, fmt.Sprintf("%s: %s", f.proto, e))
			}
		}
		st.Message = strings.Join(errs, "; ")
		m[id] = st
	}
	return m
}

// PIDs 返回 lport 自身 pid：转发端口由本进程监听，端口占用检查时排除。
func (b *Builtin) PIDs() map[int]bool { return map[int]bool{os.Getpid(): true} }

func (b *Builtin) Cleanup() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, fs := range b.fwds {
		for _, f := range fs {
			f.stop()
		}
	}
	b.fwds = map[string][]*forwarder{}
	return nil
}

// forwarder 一条规则一个协议的监听及其上的全部连接。
type forwarder struct {
	proto  string
	target string
	ln     net.Listener
	pc     net.PacketConn
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	r        model.Rule
	conns    map[net.Conn]struct{} // 活动的连接（TCP 两端、UDP 上游），停止时全部关闭
	sessions map[string]*udpSession
	closed   bool
	err      string // 最近一次 accept / 读取错误，恢复后清空
}

type udpSession struct {
	conn net.Conn
	last atomic.Int64 // 最近一次收到客户端数据的时间（UnixNano）
}

func startForwarder(r model.Rule, proto string) (*forwarder, error) {
	f := &forwarder{proto: proto, target: r.Target, r: r, conns: map[net.Conn]struct{}{}, sessions: map[string]*udpSession{}}
	addr := ":" + strconv.Itoa(r.ListenPort)
	var err error
	if proto == model.ProtoUDP {
		f.pc, err = net.ListenPacket("udp4", addr)
	} else {
		f.ln, err = net.Listen("tcp4", addr)
	}
	if err != nil {
		return nil, err
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())
	f.wg.Add(1)
	if proto == model.ProtoUDP {
		go f.serveUDP()
	} else {
		go f.serveTCP()
	}
	return f, nil
}

func (f *forwarder) rule() model.Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.r
}

func (f *forwarder) setRule(r model.Rule) {
	f.mu.Lock()
	f.r = r
	f.mu.Unlock()
}

func (f *forwarder) lastErr() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func (f *forwarder) setErr(e string) {
	f.mu.Lock()
	changed := f.err != e
	f.err = e
	f.mu.Unlock()
	if changed && e != "" {
		log.Printf("builtin %s/%s: %s", f.rule().Name, f.proto, e)
	}
}

// track 登记活动连接；转发器已停止时返回 false，调用方须自行关闭。
func (f *forwarder) track(c net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.conns[c] = struct{}{}
	return true
}

func (f *forwarder) untrack(c net.Conn) {
	f.mu.Lock()
	delete(f.conns, c)
	f.mu.Unlock()
	_ = c.Close()
}

// stop 关闭监听与全部连接，并等待所有协程退出。
func (f *forwarder) stop() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	conns := make([]net.Conn, 0, len(f.conns))
	for c := range f.conns {
		conns = append(conns, c)
	}
	f.mu.Unlock()
	f.cancel()
	if f.ln != nil {
		_ = f.ln.Close()
	}
	if f.pc != nil {
		_ = f.pc.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	f.wg.Wait()
}

// retryDelay 读取 / accept 出现非关闭错误（如文件描述符耗尽）时的退避，最长 1 秒。
func retryDelay(d time.Duration) time.Duration {
	if d == 0 {
		return 5 * time.Millisecond
	}
	return min(2*d, time.Second)
}

func (f *forwarder) serveTCP() {
	defer f.wg.Done()
	var delay time.Duration
	for {
		c, err := f.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			f.setErr(err.Error())
			delay = retryDelay(delay)
			time.Sleep(delay)
			continue
		}
		if delay != 0 {
			delay = 0
			f.setErr("")
		}
		f.wg.Add(1)
		go f.handleTCP(c)
	}
}

func (f *forwarder) handleTCP(c net.Conn) {
	defer f.wg.Done()
	if !f.track(c) {
		_ = c.Close()
		return
	}
	defer f.untrack(c)
	d := net.Dialer{Timeout: dialTimeout}
	up, err := d.DialContext(f.ctx, "tcp4", f.target)
	if err != nil {
		// 与 realm 等用户态代理一致：连不上目标时直接关闭客户端连接
		return
	}
	if !f.track(up) {
		_ = up.Close()
		return
	}
	defer f.untrack(up)
	cDone := make(chan struct{})  // 客户端 → 上游方向的拷贝结束
	upDone := make(chan struct{}) // 上游 → 客户端方向的拷贝结束
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		half := pipe(c, up)
		close(upDone)
		if half {
			watchReset(up, c, cDone)
		}
	}()
	half := pipe(up, c)
	close(cDone)
	if half {
		watchReset(c, up, upDone)
	}
	<-exited
}

// resetPoll 半关闭后检查已读完一端是否被 RST 的间隔。
const resetPoll = time.Second

// tcpStateClose Linux TCP_INFO 中的 TCP_CLOSE 状态（收到 RST 后进入）。
const tcpStateClose = 7

// watchReset 在 src 已读到 EOF（对端 FIN）、另一方向仍在传输时，定期检查 src 是否已被对端 RST。
// 此时 src 上已没有读操作，RST 只有等另一方向有数据写入时才会被发现；对端一直沉默时两端连接会滞留。
// 发现 RST 时关闭两端，唤醒另一方向的拷贝。other 关闭表示另一方向的拷贝已结束。
func watchReset(src, peer net.Conn, other <-chan struct{}) {
	t := time.NewTicker(resetPoll)
	defer t.Stop()
	for {
		select {
		case <-other:
			return
		case <-t.C:
		}
		if tcpClosed(src) {
			_ = src.Close()
			_ = peer.Close()
			return
		}
	}
}

// tcpClosed 判断 TCP 连接是否已进入 CLOSE 状态；连接已关闭或无法查询时也返回 true。
func tcpClosed(c net.Conn) bool {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return false
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return true
	}
	closed := false
	if err := rc.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		closed = err != nil || info.State == tcpStateClose
	}); err != nil {
		return true
	}
	return closed
}

// pipe 把 src 的数据拷贝到 dst。src 正常读完（对端 FIN）时半关闭 dst 的写方向，保留另一方向继续传输，
// 返回 true；出错（如对端 RST）时关闭两端，唤醒阻塞在另一方向的拷贝，否则上游不关闭时连接会一直滞留。
// TCP 之间的 io.Copy 在 Linux 上走 splice，数据不经过用户态。
func pipe(dst, src net.Conn) bool {
	_, err := io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
		_ = cw.CloseWrite()
		return true
	}
	_ = dst.Close()
	_ = src.Close()
	return false
}

func (f *forwarder) serveUDP() {
	defer f.wg.Done()
	buf := make([]byte, 64*1024)
	var delay time.Duration
	for {
		n, addr, err := f.pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			f.setErr(err.Error())
			delay = retryDelay(delay)
			time.Sleep(delay)
			continue
		}
		if delay != 0 {
			delay = 0
			f.setErr("")
		}
		if s := f.udpSession(addr); s != nil {
			_, _ = s.conn.Write(buf[:n])
		}
	}
}

// udpSession 返回客户端对应的会话并续期，不存在时连接目标新建；失败或超过上限时返回 nil（丢弃该包）。
// 续期与 udpReply 的过期判断在同一把锁下进行：会话要么已续期不会被回收，要么已从表中删除而新建。
func (f *forwarder) udpSession(addr net.Addr) *udpSession {
	key := addr.String()
	f.mu.Lock()
	s, ok := f.sessions[key]
	if ok {
		s.last.Store(time.Now().UnixNano())
	}
	full := len(f.sessions) >= maxUDPSessions
	f.mu.Unlock()
	if ok {
		return s
	}
	if full {
		return nil
	}
	d := net.Dialer{Timeout: dialTimeout}
	up, err := d.DialContext(f.ctx, "udp4", f.target)
	if err != nil {
		return nil
	}
	if !f.track(up) {
		_ = up.Close()
		return nil
	}
	s = &udpSession{conn: up}
	s.last.Store(time.Now().UnixNano())
	f.mu.Lock()
	f.sessions[key] = s
	f.mu.Unlock()
	f.wg.Add(1)
	go f.udpReply(key, addr, s)
	return s
}

// udpReply 把目标的回包发回客户端，会话空闲超时或目标不可达（ICMP 拒绝）时结束。
func (f *forwarder) udpReply(key string, addr net.Addr, s *udpSession) {
	defer f.wg.Done()
	defer func() {
		f.mu.Lock()
		if f.sessions[key] == s {
			delete(f.sessions, key)
		}
		f.mu.Unlock()
		f.untrack(s.conn)
	}()
	buf := make([]byte, 64*1024)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(udpIdle))
		n, err := s.conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && !f.expire(key, s) {
				continue // 客户端仍在发送，只是目标暂时没有回包
			}
			return
		}
		if _, err := f.pc.WriteTo(buf[:n], addr); errors.Is(err, net.ErrClosed) {
			return
		}
	}
}

// expire 在锁内检查会话是否空闲超时，超时则从表中删除并返回 true。
func (f *forwarder) expire(key string, s *udpSession) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if time.Since(time.Unix(0, s.last.Load())) < udpIdle {
		return false
	}
	if f.sessions[key] == s {
		delete(f.sessions, key)
	}
	return true
}
