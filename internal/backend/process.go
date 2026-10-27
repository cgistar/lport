package backend

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"lport/internal/model"
	"lport/internal/sysinfo"
)

// tailBuffer 保留子进程 stderr 的最后一部分。
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > 2048 {
		t.buf = t.buf[len(t.buf)-2048:]
	}
	return len(p), nil
}

// lastLine 返回最后一行有效输出，跳过 Rust panic 附带的 "note: run with RUST_BACKTRACE=1" 提示。
func (t *tailBuffer) lastLine() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	lines := strings.Split(strings.TrimSpace(string(t.buf)), "\n")
	for i := len(lines) - 1; i > 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" && !strings.HasPrefix(l, "note:") {
			return l
		}
	}
	return strings.TrimSpace(lines[0])
}

// startupGrace 新启动的进程 存活这么久即视为启动成功；端口被占用、权限不足等错误会在此之前退出。
const startupGrace = 500 * time.Millisecond

var errStopped = errors.New("stopped")

type proc struct {
	tool  string
	args  func(r model.Rule, proto string) []string
	rule  model.Rule
	proto string
	ready chan error // 首次启动的结果，只写入一次

	mu       sync.Mutex
	pid      int
	restarts int
	lastErr  string
	stopped  bool
	stopCh   chan struct{}
	doneCh   chan struct{}
}

func (p *proc) loop() {
	defer close(p.doneCh)
	first := true
	report := func(err error) {
		if first {
			first = false
			p.ready <- err
		}
	}
	backoff := time.Second
	for {
		p.mu.Lock()
		rule := p.rule
		p.mu.Unlock()
		bin, _ := sysinfo.ToolPath(p.tool)
		if bin == "" {
			bin = sysinfo.ToolBinary(p.tool)
		}
		cmd := exec.Command(bin, p.args(rule, p.proto)...)
		stderr := &tailBuffer{}
		cmd.Stderr = stderr
		// 独立进程组便于整组终止；lport 意外退出时子进程随之结束
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
		// 监听进程退出后，fork 出的连接子进程可能仍持有 stderr 管道；不设上限时 Wait 会一直等到
		// 这些连接结束，期间监听不会被重启
		cmd.WaitDelay = 2 * time.Second
		started := time.Now()
		err := cmd.Start()
		if err == nil {
			p.mu.Lock()
			p.pid = cmd.Process.Pid
			p.mu.Unlock()
			waitCh := make(chan error, 1)
			go func() { waitCh <- cmd.Wait() }()
			var grace <-chan time.Time
			if first {
				grace = time.After(startupGrace)
			}
		wait:
			for {
				select {
				case err = <-waitCh:
					break wait
				case <-grace:
					report(nil)
					grace = nil
				case <-p.stopCh:
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
					select {
					case <-waitCh:
					case <-time.After(3 * time.Second):
						_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
						<-waitCh
					}
					report(errStopped)
					return
				}
			}
		}
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if l := stderr.lastLine(); l != "" {
			msg = l
		}
		if msg == "" {
			msg = "进程已退出"
		}
		p.mu.Lock()
		p.pid = 0
		p.restarts++
		p.lastErr = msg
		p.mu.Unlock()
		log.Printf("%s %s/%s 退出: %s", p.tool, rule.Name, p.proto, msg)
		report(errors.New(msg))
		if time.Since(started) > 30*time.Second {
			backoff = time.Second
		}
		select {
		case <-p.stopCh:
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (p *proc) stop() {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	p.mu.Unlock()
	close(p.stopCh)
	<-p.doneCh
}

// Process 通过监管用户态转发子进程（realm）实现转发，每条规则每个协议一个进程。
type Process struct {
	name  string // 后端名，同时也是工具名
	args  func(r model.Rule, proto string) []string
	mu    sync.Mutex
	procs map[string][]*proc // rule id → 每个协议一个进程
}

func newProcess(name string, args func(model.Rule, string) []string) *Process {
	return &Process{name: name, args: args, procs: map[string][]*proc{}}
}

func (s *Process) Name() string     { return s.name }
func (s *Process) Available() error { return checkTool(s.name) }

func (s *Process) Sync(rules []model.Rule) error {
	if err := s.Available(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	want := map[string]model.Rule{}
	for _, r := range enabled(rules) {
		want[r.ID] = r
	}
	// 先停掉删除或变更的规则，释放端口
	for id, ps := range s.procs {
		if r, ok := want[id]; ok && len(ps) > 0 && ps[0].rule.SameForward(r) {
			continue
		}
		for _, p := range ps {
			p.stop()
		}
		delete(s.procs, id)
	}
	var started []string
	for id, r := range want {
		if _, ok := s.procs[id]; ok {
			for _, p := range s.procs[id] {
				p.mu.Lock()
				p.rule = r // 名称等非转发字段更新
				p.mu.Unlock()
			}
			continue
		}
		var ps []*proc
		for _, proto := range r.Protos() {
			p := &proc{tool: s.name, args: s.args, rule: r, proto: proto, ready: make(chan error, 1), stopCh: make(chan struct{}), doneCh: make(chan struct{})}
			go p.loop()
			ps = append(ps, p)
		}
		s.procs[id] = ps
		started = append(started, id)
	}
	// 等待新进程的首次启动结果：启动即失败的规则整体停止并返回错误，由调用方回滚
	var errs []string
	for _, id := range started {
		failed := false
		for _, p := range s.procs[id] {
			if err := <-p.ready; err != nil {
				failed = true
				errs = append(errs, fmt.Sprintf("%s 启动失败（%s/%d）: %s", s.name, p.proto, p.rule.ListenPort, err))
			}
		}
		if failed {
			for _, p := range s.procs[id] {
				p.stop()
			}
			delete(s.procs, id)
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "；"))
	}
	return nil
}

func (s *Process) Status() map[string]RuleStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string]RuleStatus{}
	for id, ps := range s.procs {
		st := RuleStatus{State: "running"}
		var errs []string
		for _, p := range ps {
			p.mu.Lock()
			if p.pid > 0 {
				st.PIDs = append(st.PIDs, p.pid)
			} else {
				st.State = "error"
			}
			st.Restarts += p.restarts
			if p.lastErr != "" {
				errs = append(errs, fmt.Sprintf("%s: %s", p.proto, p.lastErr))
			}
			p.mu.Unlock()
		}
		if st.State == "error" {
			st.Message = strings.Join(errs, "; ")
		}
		m[id] = st
	}
	return m
}

// PIDs 返回所有转发主进程 pid，用于端口占用检查时排除自身。
func (s *Process) PIDs() map[int]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[int]bool{}
	for _, ps := range s.procs {
		for _, p := range ps {
			p.mu.Lock()
			if p.pid > 0 {
				m[p.pid] = true
			}
			p.mu.Unlock()
		}
	}
	return m
}

func (s *Process) Cleanup() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var wg sync.WaitGroup
	for _, ps := range s.procs {
		for _, p := range ps {
			wg.Add(1)
			go func(p *proc) { defer wg.Done(); p.stop() }(p)
		}
	}
	wg.Wait()
	s.procs = map[string][]*proc{}
	return nil
}
