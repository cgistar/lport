package manager

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"lport/internal/backend"
	"lport/internal/config"
	"lport/internal/model"
)

// fakeBackend 记录最近一次 Sync 的规则，可模拟清理失败。
type fakeBackend struct {
	synced     []model.Rule
	cleanupErr error
}

func (f *fakeBackend) Name() string     { return "fake" }
func (f *fakeBackend) Available() error { return nil }
func (f *fakeBackend) Sync(r []model.Rule) error {
	f.synced = append([]model.Rule(nil), r...)
	return nil
}
func (f *fakeBackend) Status() map[string]backend.RuleStatus { return nil }
func (f *fakeBackend) Cleanup() error                        { return f.cleanupErr }

func newStore(t *testing.T, cfg string) (*config.Store, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	store, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return store, dir
}

const baseCfg = `listen: 127.0.0.1:18999
backend: builtin
admin: {password: test-password}
rules:
  - {id: keep, proto: tcp, listen_port: 18501, target: "127.0.0.1:9", enabled: true}
`

// 后端同步成功后保存配置失败：配置保持旧状态，运行中的转发也须恢复为旧规则
func TestMutateRollsBackWhenSaveFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 不受目录权限限制，无法模拟保存失败")
	}
	store, dir := newStore(t, baseCfg)
	fb := &fakeBackend{}
	m := &Manager{store: store, backend: fb}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	_, err := m.Create(model.Rule{Proto: "tcp", ListenPort: 18502, Target: "127.0.0.1:9", Enabled: true})
	if err == nil {
		t.Fatal("保存失败时 Create 应返回错误")
	}
	if n := len(store.Get().Rules); n != 1 {
		t.Fatalf("配置应保持 1 条规则，实际 %d", n)
	}
	if len(fb.synced) != 1 || fb.synced[0].ID != "keep" {
		t.Fatalf("后端应恢复为旧规则，实际: %+v", fb.synced)
	}
}

// 旧后端清理失败时不能切换，且须重新应用旧规则
func TestSetBackendAbortsWhenCleanupFails(t *testing.T) {
	cfg := strings.NewReplacer("backend: builtin", "backend: nftables", "127.0.0.1:9", "10.0.0.5:80").Replace(baseCfg)
	store, _ := newStore(t, cfg)
	fb := &fakeBackend{cleanupErr: errors.New("boom")}
	m := &Manager{store: store, backend: fb}

	if err := m.SetBackend(model.BackendBuiltin); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("应返回清理错误，实际: %v", err)
	}
	if m.backend != fb || store.Get().Backend != model.BackendNftables {
		t.Fatal("清理失败后不应切换后端")
	}
	if len(fb.synced) != 1 {
		t.Fatalf("应重新应用旧规则，实际: %+v", fb.synced)
	}
}

// 启动时端口已被其它服务占用的规则暂不应用并显示原因，端口释放后重新启用即可生效
func TestStartBlocksSystemPortConflicts(t *testing.T) {
	l, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	busy := l.Addr().(*net.TCPAddr).Port
	store, _ := newStore(t, baseCfg+`  - {id: busy, proto: tcp, listen_port: `+itoa(busy)+`, target: "127.0.0.1:9", enabled: true}
`)
	m := New(store)
	m.Start()
	t.Cleanup(m.Stop)

	if e := m.SyncError(); e != "" {
		t.Fatalf("冲突规则不应导致整体应用失败: %s", e)
	}
	views := map[string]RuleView{}
	for _, v := range m.Rules() {
		views[v.ID] = v
	}
	if st := views["busy"].Status; st.State != "error" || !strings.Contains(st.Message, "端口冲突") {
		t.Errorf("busy 规则状态: %+v", st)
	}
	if st := views["keep"].Status; st.State != "running" {
		t.Errorf("keep 规则应正常运行: %+v", st)
	}

	// 端口仍被占用时重新启用会被拒绝，冲突标记保留
	if err := m.Toggle("busy", true); err == nil {
		t.Error("端口仍被占用时启用应失败")
	}
	l.Close()
	time.Sleep(50 * time.Millisecond)
	if err := m.Toggle("busy", true); err != nil {
		t.Fatalf("端口释放后启用失败: %v", err)
	}
	for _, v := range m.Rules() {
		if v.ID == "busy" && v.Status.State != "running" {
			t.Errorf("端口释放后 busy 应运行: %+v", v.Status)
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
