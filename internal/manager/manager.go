package manager

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"lport/internal/backend"
	"lport/internal/config"
	"lport/internal/model"
	"lport/internal/portcheck"
	"lport/internal/probe"
)

// Conflict 端口冲突信息。
type Conflict struct {
	Type    string `json:"type"` // rule | panel | system
	Proto   string `json:"proto"`
	Message string `json:"message"`
}

type RuleView struct {
	model.Rule
	Status backend.RuleStatus `json:"status"`
}

// Manager 编排配置存储与转发后端。
type Manager struct {
	store *config.Store

	mu      sync.Mutex // 串行化所有变更操作
	backend backend.Backend
	syncErr string
	cancel  context.CancelFunc
	// blocked 启动时与系统已占用端口冲突的规则（rule id → 冲突说明），暂不应用；
	// 编辑或重新启用该规则时重新校验
	blocked map[string]string
}

// MaintainInterval 内核后端重新解析域名、修复规则的间隔。
const MaintainInterval = 60 * time.Second

func New(store *config.Store) *Manager {
	return &Manager{store: store}
}

// NewOffline 创建只修改配置、不应用转发的 Manager，用于服务未运行时在命令行增删规则，
// 校验逻辑与运行时一致，规则在服务启动后生效。
func NewOffline(store *config.Store) *Manager {
	return &Manager{store: store, backend: offlineBackend{}}
}

type offlineBackend struct{}

func (offlineBackend) Name() string                          { return "offline" }
func (offlineBackend) Available() error                      { return nil }
func (offlineBackend) Sync([]model.Rule) error               { return nil }
func (offlineBackend) Status() map[string]backend.RuleStatus { return nil }
func (offlineBackend) Cleanup() error                        { return nil }

// Start 清理残留并按配置应用规则。后端不可用时记录错误但不阻止启动，便于在界面中安装依赖。
func (m *Manager) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.store.Get()
	for _, name := range []string{model.BackendIptables, model.BackendNftables} {
		b, _ := backend.New(name)
		if err := b.Cleanup(); err != nil {
			log.Printf("清理残留的 %s 转发规则失败: %v", name, err)
		}
	}
	m.backend, _ = backend.New(cfg.Backend)
	// 停机期间端口可能已被其它服务占用；内核后端不绑定端口，直接应用会把发往该服务的流量转走，
	// 因此与在线启用规则一样检查系统占用，冲突的规则暂不应用
	m.blocked = map[string]string{}
	for _, r := range cfg.Rules {
		if !r.Enabled {
			continue
		}
		var sys []Conflict
		for _, c := range checkPort(cfg, r.Proto, r.ListenPort, r.ID, true, nil) {
			if c.Type == "system" {
				sys = append(sys, c)
			}
		}
		if err := conflictErr(sys); err != nil {
			m.blocked[r.ID] = err.Error()
			log.Printf("规则「%s」未应用: %v", r.Name, err)
		}
	}
	m.applyLocked(cfg.Rules)
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	go m.maintainLoop(ctx)
}

func (m *Manager) maintainLoop(ctx context.Context) {
	t := time.NewTicker(MaintainInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		m.mu.Lock()
		if mt, ok := m.backend.(backend.Maintainer); ok {
			if m.syncErr != "" {
				// 上次应用失败（如依赖刚装好、网络刚恢复），整体重试
				m.applyLocked(m.store.Get().Rules)
			} else if err := mt.Maintain(); err != nil {
				log.Printf("维护转发规则失败: %v", err)
			}
		}
		m.mu.Unlock()
	}
}

// effective 返回实际交给后端的规则：启动时检测到端口冲突的规则按停用处理。
func (m *Manager) effective(rules []model.Rule) []model.Rule {
	if len(m.blocked) == 0 {
		return rules
	}
	out := append([]model.Rule(nil), rules...)
	for i := range out {
		if m.blocked[out[i].ID] != "" {
			out[i].Enabled = false
		}
	}
	return out
}

func (m *Manager) applyLocked(rules []model.Rule) {
	if err := m.backend.Sync(m.effective(rules)); err != nil {
		m.syncErr = err.Error()
		log.Printf("应用转发规则失败: %v", err)
		return
	}
	m.syncErr = ""
}

// Stop 清除所有转发。
func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backend != nil {
		if err := m.backend.Cleanup(); err != nil {
			log.Printf("清除转发规则失败: %v", err)
		}
	}
}

func (m *Manager) BackendName() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.backend.Name()
}

// BackendMode 返回后端的运行模式（目前仅 nftables 有 map / linear 之分）。
func (m *Manager) BackendMode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n, ok := m.backend.(*backend.Nftables); ok {
		return n.Mode()
	}
	return ""
}

func (m *Manager) SyncError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncErr
}

// Reapply 重新应用规则（例如安装依赖后）。
func (m *Manager) Reapply() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applyLocked(m.store.Get().Rules)
	if m.syncErr != "" {
		return errors.New(m.syncErr)
	}
	return nil
}

func (m *Manager) Rules() []RuleView {
	m.mu.Lock()
	st := m.backend.Status()
	blocked := make(map[string]string, len(m.blocked))
	for id, msg := range m.blocked {
		blocked[id] = msg
	}
	m.mu.Unlock()
	rules := m.store.Get().Rules
	out := make([]RuleView, 0, len(rules))
	for _, r := range rules {
		s, ok := st[r.ID]
		if r.Enabled && blocked[r.ID] != "" {
			s, ok = backend.RuleStatus{State: "error", Message: blocked[r.ID]}, true
		}
		if !ok {
			s = backend.RuleStatus{State: "stopped"}
			if r.Enabled {
				s = backend.RuleStatus{State: "error", Message: m.SyncError()}
			}
		}
		out = append(out, RuleView{Rule: r, Status: s})
	}
	return out
}

func panelPort(listen string) int {
	_, ps, _ := net.SplitHostPort(listen)
	p, _ := strconv.Atoi(ps)
	return p
}

// CheckPort 检查监听端口冲突。checkSystem 为 false 时只检查规则与面板端口。
func (m *Manager) CheckPort(proto string, port int, excludeID string, checkSystem bool) []Conflict {
	m.mu.Lock()
	own := m.ownPIDsLocked()
	m.mu.Unlock()
	return checkPort(m.store.Get(), proto, port, excludeID, checkSystem, own)
}

// ownPIDsLocked 返回本工具的转发进程 pid，其占用的端口不算系统占用（规则间冲突另行检查）。
func (m *Manager) ownPIDsLocked() map[int]bool {
	if s, ok := m.backend.(*backend.Process); ok {
		return s.PIDs()
	}
	return nil
}

func checkPort(cfg config.Config, proto string, port int, excludeID string, checkSystem bool, own map[int]bool) []Conflict {
	var out []Conflict
	for _, r := range cfg.Rules {
		if r.ID != excludeID && r.ListenPort == port && model.ProtoOverlap(r.Proto, proto) {
			out = append(out, Conflict{Type: "rule", Proto: r.Proto, Message: fmt.Sprintf("与规则「%s」(%s/%d) 冲突", r.Name, r.Proto, r.ListenPort)})
		}
	}
	if port == panelPort(cfg.Listen) && model.ProtoOverlap(proto, model.ProtoTCP) {
		out = append(out, Conflict{Type: "panel", Proto: "tcp", Message: "与管理面板端口冲突"})
	}
	if !checkSystem {
		return out
	}
	listeners := portcheck.Listeners(true)
	for _, p := range (model.Rule{Proto: proto}).Protos() {
		found := false
		for _, l := range listeners {
			if l.Proto != p || l.Port != port || !l.BlocksIPv4() {
				continue
			}
			found = true
			if l.PID > 0 && (own[l.PID] || own[portcheck.ParentPID(l.PID)]) {
				continue
			}
			who := "未知进程"
			if l.Process != "" {
				who = fmt.Sprintf("%s (pid %d)", l.Process, l.PID)
			}
			out = append(out, Conflict{Type: "system", Proto: p, Message: fmt.Sprintf("%s 端口 %d 已被 %s 占用 (%s)", p, port, who, l.Addr)})
			break
		}
		if !found {
			if err := portcheck.BindTest(p, port); err != nil {
				out = append(out, Conflict{Type: "system", Proto: p, Message: fmt.Sprintf("%s 端口 %d 无法绑定: %v", p, port, err)})
			}
		}
	}
	return out
}

func conflictErr(cs []Conflict) error {
	if len(cs) == 0 {
		return nil
	}
	msgs := make([]string, len(cs))
	for i, c := range cs {
		msgs[i] = c.Message
	}
	return fmt.Errorf("端口冲突: %s", strings.Join(msgs, "；"))
}

// mutate 在锁内修改规则（id 为被修改的规则，新建时为空）、校验、同步后端并保存。
// 同步失败或同步后保存失败时都恢复为旧规则，保证运行状态与配置一致；恢复也失败时记入 syncErr。
func (m *Manager) mutate(id string, fn func(c *config.Config) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.store.Get().Rules
	// 被修改的规则会经 validateRule 重新校验系统端口占用，不再沿用启动时的冲突标记
	blockedMsg, wasBlocked := m.blocked[id]
	delete(m.blocked, id)
	synced := false
	err := m.store.Update(func(c *config.Config) error {
		if err := fn(c); err != nil {
			return err
		}
		synced = true
		if err := m.backend.Sync(m.effective(c.Rules)); err != nil {
			return fmt.Errorf("应用规则失败: %w", err)
		}
		return nil
	})
	if err != nil {
		if wasBlocked {
			m.blocked[id] = blockedMsg
		}
		if synced {
			m.applyLocked(old)
		}
		return err
	}
	m.syncErr = ""
	return nil
}

// validateRule 校验规则与端口冲突，需在持有 m.mu 时调用；停用的规则不检查系统占用。
func (m *Manager) validateRule(c *config.Config, r *model.Rule) error {
	if err := r.Validate(c.Backend); err != nil {
		return err
	}
	if !model.UserSpace(c.Backend) && r.Enabled {
		host, _, _ := r.TargetHostPort()
		if _, err := backend.ResolveHost(host, ""); err != nil {
			return err
		}
	}
	return conflictErr(checkPort(*c, r.Proto, r.ListenPort, r.ID, r.Enabled, m.ownPIDsLocked()))
}

func (m *Manager) Create(r model.Rule) (model.Rule, error) {
	r.ID = config.NewID()
	r.CreatedAt = time.Now().Truncate(time.Second)
	if r.Name == "" {
		r.Name = "rule-" + strconv.Itoa(r.ListenPort)
	}
	err := m.mutate("", func(c *config.Config) error {
		if err := m.validateRule(c, &r); err != nil {
			return err
		}
		c.Rules = append(c.Rules, r)
		return nil
	})
	return r, err
}

func findRule(c *config.Config, id string) (int, error) {
	for i, r := range c.Rules {
		if r.ID == id {
			return i, nil
		}
	}
	return -1, errors.New("规则不存在")
}

func (m *Manager) Update(id string, r model.Rule) (model.Rule, error) {
	err := m.mutate(id, func(c *config.Config) error {
		i, err := findRule(c, id)
		if err != nil {
			return err
		}
		r.ID, r.CreatedAt = id, c.Rules[i].CreatedAt
		if r.Name == "" {
			r.Name = "rule-" + strconv.Itoa(r.ListenPort)
		}
		if err := m.validateRule(c, &r); err != nil {
			return err
		}
		c.Rules[i] = r
		return nil
	})
	return r, err
}

func (m *Manager) Toggle(id string, enabled bool) error {
	return m.mutate(id, func(c *config.Config) error {
		i, err := findRule(c, id)
		if err != nil {
			return err
		}
		r := c.Rules[i]
		r.Enabled = enabled
		if enabled {
			if err := m.validateRule(c, &r); err != nil {
				return err
			}
		}
		c.Rules[i] = r
		return nil
	})
}

func (m *Manager) Delete(id string) error {
	return m.mutate(id, func(c *config.Config) error {
		i, err := findRule(c, id)
		if err != nil {
			return err
		}
		c.Rules = append(c.Rules[:i], c.Rules[i+1:]...)
		return nil
	})
}

// SetBackend 切换转发后端，失败时回滚到原后端。
func (m *Manager) SetBackend(name string) error {
	if !model.ValidBackend(name) {
		return fmt.Errorf("未知后端: %s", name)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if name == m.backend.Name() {
		return nil
	}
	nb, _ := backend.New(name)
	if err := nb.Available(); err != nil {
		return err
	}
	cfg := m.store.Get()
	for _, r := range cfg.Rules {
		if err := r.Validate(name); err != nil {
			return fmt.Errorf("规则「%s」不适用于 %s 后端: %w", r.Name, name, err)
		}
	}
	// 旧后端清理失败时不能继续：残留的旧转发会与新后端同时生效。恢复旧后端的完整规则后返回错误
	if err := m.backend.Cleanup(); err != nil {
		m.applyLocked(cfg.Rules)
		return fmt.Errorf("切换到 %s 失败: %w", name, err)
	}
	rollback := func() {
		if err := nb.Cleanup(); err != nil {
			log.Printf("回滚时清除 %s 转发规则失败: %v", name, err)
		}
		m.applyLocked(cfg.Rules)
	}
	if err := nb.Sync(m.effective(cfg.Rules)); err != nil {
		rollback()
		return fmt.Errorf("切换到 %s 失败: %w", name, err)
	}
	if err := m.store.Update(func(c *config.Config) error { c.Backend = name; return nil }); err != nil {
		rollback()
		return err
	}
	m.backend = nb
	m.syncErr = ""
	return nil
}

// ProbeResult 规则连通性检测结果。
type ProbeResult struct {
	Local  []probe.Result `json:"local"`  // 经本机监听端口（走转发路径）
	Target []probe.Result `json:"target"` // 直连目标
}

const probeTimeout = 3 * time.Second

// Probe 检测规则的本机监听端口与目标端口。本机检测连接本机出口 IP 而非 127.0.0.1，
// 使流量经过与外部客户端相同的用户态进程 / DNAT 规则（DNAT 后源地址为回环会被内核丢弃）。
func (m *Manager) Probe(id string) (*ProbeResult, error) {
	cfg := m.store.Get()
	i, err := findRule(&cfg, id)
	if err != nil {
		return nil, err
	}
	r := cfg.Rules[i]
	host, port, _ := r.TargetHostPort()
	targetIP, resolveErr := backend.ResolveHost(host, "")
	if resolveErr != nil && model.UserSpace(cfg.Backend) {
		// 用户态后端可转发到回环地址/域名，回环地址解析结果被 ResolveHost 排除，这里直接使用原始主机名
		targetIP, resolveErr = host, nil
	}
	localIP := probe.LocalIP(targetIP)
	if localIP == "" {
		localIP = "127.0.0.1"
	}
	protos := r.Protos()
	res := &ProbeResult{Local: make([]probe.Result, len(protos)), Target: make([]probe.Result, len(protos))}
	run := func(proto, addr string) probe.Result {
		if proto == model.ProtoUDP {
			return probe.UDP(addr, probeTimeout)
		}
		return probe.TCP(addr, probeTimeout)
	}
	runLocal := run
	if model.UserSpace(cfg.Backend) {
		runLocal = func(proto, addr string) probe.Result {
			if proto == model.ProtoUDP {
				return probe.UDP(addr, probeTimeout)
			}
			return probe.TCPHold(addr, probeTimeout, 1500*time.Millisecond)
		}
	}
	var wg sync.WaitGroup
	for k, proto := range protos {
		localAddr := net.JoinHostPort(localIP, strconv.Itoa(r.ListenPort))
		if r.Enabled {
			wg.Add(1)
			go func(k int, proto string) { defer wg.Done(); res.Local[k] = runLocal(proto, localAddr) }(k, proto)
		} else {
			res.Local[k] = probe.Skipped(proto, localAddr, "规则未启用")
		}
		if resolveErr != nil {
			res.Target[k] = probe.Result{Proto: proto, Addr: r.Target, State: probe.StateFail, Message: resolveErr.Error()}
			continue
		}
		targetAddr := net.JoinHostPort(targetIP, strconv.Itoa(port))
		wg.Add(1)
		go func(k int, proto string) { defer wg.Done(); res.Target[k] = run(proto, targetAddr) }(k, proto)
	}
	wg.Wait()
	return res, nil
}
