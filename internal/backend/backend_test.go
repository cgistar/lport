package backend

import (
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"lport/internal/model"
)

var update = flag.Bool("update", false, "用当前输出重新生成 testdata/*.golden")

// assertGolden 将输出与 testdata 中的 golden 文件比对；规则生成逻辑有预期变更时，
// 执行 go test ./internal/backend -update 重新生成，并在 git diff 中审查差异。
func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败（首次运行请加 -update 生成）: %v", path, err)
	}
	if got != string(want) {
		t.Errorf("输出与 %s 不一致，若为预期变更请加 -update 重新生成\n--- got ---\n%s", path, got)
	}
}

var testRules = []model.Rule{
	{ID: "a1", Name: "web", Proto: "tcp", ListenPort: 8080, Target: "10.0.0.5:80", Enabled: true},
	{ID: "b2", Name: "dns", Proto: "both", ListenPort: 5353, Target: "10.0.0.6:53", Enabled: true},
	{ID: "c3", Name: "off", Proto: "udp", ListenPort: 9999, Target: "10.0.0.7:99", Enabled: false},
}

func TestRealmArgs(t *testing.T) {
	got := strings.Join(RealmArgs(testRules[0], "tcp"), " ")
	if got != "-l 0.0.0.0:8080 -r 10.0.0.5:80" {
		t.Error(got)
	}
	got = strings.Join(RealmArgs(testRules[1], "udp"), " ")
	if got != "-l 0.0.0.0:5353 -r 10.0.0.6:53 -u -t --udp-timeout 120" {
		t.Error(got)
	}
}

// realm 绑定失败时以 Rust panic 退出，需取 panic 消息而不是末尾的 RUST_BACKTRACE 提示
func TestTailBufferLastLine(t *testing.T) {
	var b tailBuffer
	b.Write([]byte("thread 'tokio-runtime-worker' panicked at realm_core/src/tcp/mod.rs:37:58:\n" +
		"[tcp]failed to bind 0.0.0.0:80: Address already in use (os error 98)\n" +
		"note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n"))
	if got := b.lastLine(); got != "[tcp]failed to bind 0.0.0.0:80: Address already in use (os error 98)" {
		t.Error(got)
	}
	var c tailBuffer
	c.Write([]byte("bind: Address in use\n"))
	if got := c.lastLine(); got != "bind: Address in use" {
		t.Error(got)
	}
}

func TestIptablesScript(t *testing.T) {
	assertGolden(t, "iptables.golden", IptablesRestoreScript(testRules))
}

func TestNftLinearScript(t *testing.T) {
	assertGolden(t, "nft_linear.golden", NftLinearScript(testRules))
}

func TestNftMapScript(t *testing.T) {
	rules := append(testRules, model.Rule{ID: "d4", Proto: "tcp", ListenPort: 8081, Target: "10.0.0.5:80", Enabled: true})
	assertGolden(t, "nft_map.golden", NftMapScript(rules))
	// 无规则时 map/set 不能带空 elements（nft 语法错误）
	if strings.Contains(NftMapScript(nil), "elements") {
		t.Error("empty map should omit elements")
	}
}

// 启动即失败（端口被占用）时 Sync 须返回错误且不保留该规则，端口释放后可正常启动
func TestStartupFailure(t *testing.T) {
	for _, b := range []Backend{NewBuiltin(), NewRealm()} {
		t.Run(b.Name(), func(t *testing.T) {
			if err := b.Available(); err != nil {
				t.Skip(err)
			}
			l, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := l.Addr().(*net.TCPAddr).Port
			rule := model.Rule{ID: "busy", Proto: "both", ListenPort: port, Target: "127.0.0.1:9", Enabled: true}
			t.Cleanup(func() { _ = b.Cleanup() })

			err = b.Sync([]model.Rule{rule})
			if err == nil || !strings.Contains(err.Error(), b.Name()+" 启动失败") {
				t.Fatalf("Sync 应返回启动失败，实际: %v", err)
			}
			if st := b.Status(); len(st) != 0 {
				t.Fatalf("失败的规则不应保留: %+v", st)
			}
			// 同一规则的 udp 不能残留监听
			if u, err := net.ListenPacket("udp4", ":"+strconv.Itoa(port)); err != nil {
				t.Fatalf("udp 端口未释放: %v", err)
			} else {
				u.Close()
			}

			l.Close()
			if err := b.Sync([]model.Rule{rule}); err != nil {
				t.Fatalf("端口释放后 Sync 失败: %v", err)
			}
			if st := b.Status()["busy"]; st.State != "running" {
				t.Fatalf("status=%+v", st)
			}
		})
	}
}

// echoServer 在 127.0.0.1 同一端口上提供 tcp / udp 回显，回包带协议前缀。
func echoServer(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	u, err := net.ListenPacket("udp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(); u.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b, _ := io.ReadAll(c) // 读到客户端半关闭为止，验证 FIN 能被转发
				c.Write(append([]byte("tcp:"), b...))
			}()
		}
	}()
	go func() {
		b := make([]byte, 1500)
		for {
			n, a, err := u.ReadFrom(b)
			if err != nil {
				return
			}
			u.WriteTo(append([]byte("udp:"), b[:n]...), a)
		}
	}()
	return port
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func tcpEcho(port int, msg string) (string, error) {
	c, err := net.DialTimeout("tcp4", "127.0.0.1:"+strconv.Itoa(port), time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return "", err
	}
	_ = c.(*net.TCPConn).CloseWrite()
	b, err := io.ReadAll(c)
	return string(b), err
}

func udpEcho(port int, msg string) (string, error) {
	c, err := net.Dial("udp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return "", err
	}
	b := make([]byte, 1500)
	n, err := c.Read(b)
	return string(b[:n]), err
}

func TestBuiltinForward(t *testing.T) {
	echo := echoServer(t)
	lp, lp2 := freePort(t), freePort(t)
	b := NewBuiltin()
	t.Cleanup(func() { _ = b.Cleanup() })
	rules := []model.Rule{
		{ID: "ip", Name: "ip", Proto: "both", ListenPort: lp, Target: "127.0.0.1:" + strconv.Itoa(echo), Enabled: true},
		{ID: "dn", Name: "dn", Proto: "tcp", ListenPort: lp2, Target: "localhost:" + strconv.Itoa(echo), Enabled: true},
	}
	if err := b.Sync(rules); err != nil {
		t.Fatal(err)
	}
	if got, err := tcpEcho(lp, "hi"); got != "tcp:hi" {
		t.Errorf("tcp: %q %v", got, err)
	}
	if got, err := udpEcho(lp, "hi"); got != "udp:hi" {
		t.Errorf("udp: %q %v", got, err)
	}
	if got, err := tcpEcho(lp2, "dn"); got != "tcp:dn" {
		t.Errorf("域名目标: %q %v", got, err)
	}
	if st := b.Status()["ip"]; st.State != "running" {
		t.Errorf("status: %+v", st)
	}

	// 目标不可达：接受后立即关闭客户端连接
	rules[1].Target = "127.0.0.1:" + strconv.Itoa(freePort(t))
	if err := b.Sync(rules); err != nil {
		t.Fatal(err)
	}
	if got, err := tcpEcho(lp2, "x"); got != "" {
		t.Errorf("目标不可达时应无回包: %q %v", got, err)
	}

	// 停用规则后端口释放，已建立的连接被关闭
	c, err := net.Dial("tcp4", "127.0.0.1:"+strconv.Itoa(lp))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(50 * time.Millisecond)
	rules[0].Enabled = false
	if err := b.Sync(rules); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("停用后连接应被关闭: %v", err)
	}
	l, err := net.Listen("tcp4", ":"+strconv.Itoa(lp))
	if err != nil {
		t.Fatalf("停用后端口应释放: %v", err)
	}
	l.Close()
	if _, ok := b.Status()["ip"]; ok {
		t.Error("停用的规则不应有状态")
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// 客户端 RST 断开而上游保持连接时，代理须关闭两端，不能留下滞留的连接
func TestBuiltinClientResetReleasesUpstream(t *testing.T) {
	up, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { up.Close() })
	upClosed := make(chan struct{})
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// 上游只读不写也不主动关闭；读到 EOF 后仍保持连接，模拟忽略半关闭的服务
		io.Copy(io.Discard, c)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("late")); err == nil {
			time.Sleep(100 * time.Millisecond)
			if _, err := c.Write([]byte("late")); err != nil {
				close(upClosed)
			}
		}
	}()
	lp := freePort(t)
	b := NewBuiltin()
	t.Cleanup(func() { _ = b.Cleanup() })
	if err := b.Sync([]model.Rule{{ID: "r", Proto: "tcp", ListenPort: lp, Target: up.Addr().String(), Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp4", "127.0.0.1:"+strconv.Itoa(lp))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hi"))
	time.Sleep(100 * time.Millisecond)
	c.(*net.TCPConn).SetLinger(0) // Close 时发送 RST
	c.Close()

	f := b.fwds["r"][0]
	deadline := time.Now().Add(3 * time.Second)
	for {
		f.mu.Lock()
		n := len(f.conns)
		f.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("客户端 RST 后仍有 %d 个连接未释放", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-upClosed:
	case <-time.After(3 * time.Second):
		t.Error("上游连接未被关闭")
	}
}

// activeConns 返回转发器上的活动连接数。
func activeConns(f *forwarder) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.conns)
}

// 客户端先 FIN 再 RST、上游保持沉默时，代理须发现 RST 并关闭两端
func TestBuiltinResetAfterHalfClose(t *testing.T) {
	up, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { up.Close() })
	checked := make(chan struct{}) // 检查完成前上游保持沉默，避免回包让代理经写入发现 RST
	upClosed := make(chan struct{})
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c)
		<-checked
		// 代理已关闭上游连接时，第二次写入会因收到 RST 失败
		for i := 0; i < 2; i++ {
			time.Sleep(100 * time.Millisecond)
			if _, err := c.Write([]byte("x")); err != nil {
				close(upClosed)
				return
			}
		}
	}()
	lp := freePort(t)
	b := NewBuiltin()
	t.Cleanup(func() { _ = b.Cleanup() })
	if err := b.Sync([]model.Rule{{ID: "r", Proto: "tcp", ListenPort: lp, Target: up.Addr().String(), Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp4", "127.0.0.1:"+strconv.Itoa(lp))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hi"))
	c.(*net.TCPConn).CloseWrite()
	time.Sleep(100 * time.Millisecond)
	c.(*net.TCPConn).SetLinger(0)
	c.Close()

	f := b.fwds["r"][0]
	deadline := time.Now().Add(3 * time.Second)
	for activeConns(f) > 0 {
		if time.Now().After(deadline) {
			close(checked)
			t.Fatalf("FIN 后 RST 仍有 %d 个连接未释放", activeConns(f))
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(checked)
	select {
	case <-upClosed:
	case <-time.After(3 * time.Second):
		t.Error("上游连接未被关闭")
	}
}

// 两个方向先后正常半关闭时连接立即结束，不等待 RST 检查的轮询间隔
func TestBuiltinBothHalfCloseFinishesPromptly(t *testing.T) {
	up, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { up.Close() })
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c)
		c.Write([]byte("resp"))
		c.(*net.TCPConn).CloseWrite()
		time.Sleep(5 * time.Second) // 不主动 Close，只半关闭
	}()
	lp := freePort(t)
	b := NewBuiltin()
	t.Cleanup(func() { _ = b.Cleanup() })
	if err := b.Sync([]model.Rule{{ID: "r", Proto: "tcp", ListenPort: lp, Target: up.Addr().String(), Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp4", "127.0.0.1:"+strconv.Itoa(lp))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("req"))
	c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if string(got) != "resp" || err != nil {
		t.Fatalf("回包 %q %v", got, err)
	}
	f := b.fwds["r"][0]
	deadline := time.Now().Add(500 * time.Millisecond)
	for activeConns(f) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("两端都半关闭后 500ms 内仍有 %d 个连接未释放", activeConns(f))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
