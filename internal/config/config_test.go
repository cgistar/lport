package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func writeCfg(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func stubEnv(t *testing.T, root bool, tools ...string) {
	t.Helper()
	oldTool, oldRoot := toolInstalled, isRoot
	t.Cleanup(func() { toolInstalled, isRoot = oldTool, oldRoot })
	isRoot = func() bool { return root }
	toolInstalled = func(name string) bool {
		for _, x := range tools {
			if x == name {
				return true
			}
		}
		return false
	}
}

func TestAutoBackend(t *testing.T) {
	cases := []struct {
		root  bool
		tools []string
		cfg   string
		want  string
	}{
		{true, []string{"iptables", "nftables"}, "", "nftables"},
		{true, []string{"iptables"}, "", "iptables"},
		{true, nil, "", "builtin"},
		{false, []string{"iptables", "nftables"}, "", "builtin"},
		// 已有回环目标规则，内核后端不适用；域名目标可用于内核后端
		{true, []string{"nftables"}, "rules:\n  - {proto: tcp, listen_port: 1000, target: example.com:80}\n", "nftables"},
		{true, []string{"nftables"}, "rules:\n  - {proto: tcp, listen_port: 1000, target: 127.0.0.1:80}\n", "builtin"},
		// 显式指定的后端不被覆盖
		{true, []string{"nftables"}, "backend: iptables\n", "iptables"},
	}
	for i, c := range cases {
		stubEnv(t, c.root, c.tools...)
		s, _, err := Load(writeCfg(t, c.cfg))
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if got := s.Get().Backend; got != c.want {
			t.Errorf("case %d: backend=%s want %s", i, got, c.want)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	stubEnv(t, false)
	p := filepath.Join(t.TempDir(), "sub", "config.yaml")
	s, res, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if res.GeneratedPassword == "" {
		t.Fatal("expected generated password")
	}
	c := s.Get()
	if c.Listen != "0.0.0.0:8080" || c.Backend != "builtin" || c.Admin.Username != "admin" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if bcrypt.CompareHashAndPassword([]byte(c.Admin.PasswordHash), []byte(res.GeneratedPassword)) != nil {
		t.Fatal("hash mismatch")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("config file not written")
	}
	// 再次加载不应重新生成密码
	_, res2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if res2.GeneratedPassword != "" || res2.Changed {
		t.Fatalf("second load should be stable: %+v", res2)
	}
}

func TestPlainPasswordAndIDFill(t *testing.T) {
	p := writeCfg(t, `
backend: builtin
admin:
  username: root
  password: secret123
rules:
  - proto: tcp
    listen_port: 18080
    target: 127.0.0.1:80
    enabled: true
`)
	s, res, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if res.GeneratedPassword != "" {
		t.Fatal("should not generate password")
	}
	c := s.Get()
	if c.Admin.Password != "" || bcrypt.CompareHashAndPassword([]byte(c.Admin.PasswordHash), []byte("secret123")) != nil {
		t.Fatal("plain password not converted")
	}
	if c.Rules[0].ID == "" || c.Rules[0].Name != "rule-18080" {
		t.Fatalf("rule not normalized: %+v", c.Rules[0])
	}
	data, _ := os.ReadFile(p)
	if strings.Contains(string(data), "secret123") {
		t.Fatal("plain password still in file")
	}
}

func TestInvalidConfigs(t *testing.T) {
	cases := map[string]string{
		"backend": "backend: foo\n",
		"proto": `rules:
  - {proto: icmp, listen_port: 1000, target: 1.2.3.4:80}`,
		"conflict": `rules:
  - {proto: tcp, listen_port: 1000, target: 1.2.3.4:80}
  - {proto: both, listen_port: 1000, target: 1.2.3.4:81}`,
		"loopback-kernel": `backend: iptables
rules:
  - {proto: tcp, listen_port: 1000, target: 127.0.0.1:80}`,
		"panel-port": `listen: 0.0.0.0:9000
rules:
  - {proto: tcp, listen_port: 9000, target: 1.2.3.4:80}`,
	}
	for name, content := range cases {
		if _, _, err := Load(writeCfg(t, content)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	ok := `rules:
  - {proto: tcp, listen_port: 1000, target: 1.2.3.4:80}
  - {proto: udp, listen_port: 1000, target: 1.2.3.4:81}`
	if _, _, err := Load(writeCfg(t, ok)); err != nil {
		t.Errorf("tcp+udp same port should be allowed: %v", err)
	}
}

// ID 会写入 iptables 规则注释，含引号、换行等字符的 ID 须在加载时重新生成
func TestInvalidRuleIDRegenerated(t *testing.T) {
	stubEnv(t, false)
	p := writeCfg(t, `backend: builtin
rules:
  - {id: "x\" -j ACCEPT\n-A", proto: tcp, listen_port: 18080, target: "10.0.0.5:80"}
  - {id: ok_id-1, proto: tcp, listen_port: 18081, target: "10.0.0.5:80"}
`)
	s, _, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	rules := s.Get().Rules
	if !idRe.MatchString(rules[0].ID) || strings.ContainsAny(rules[0].ID, "\" \n") {
		t.Errorf("非法 ID 未重新生成: %q", rules[0].ID)
	}
	if rules[1].ID != "ok_id-1" {
		t.Errorf("合法 ID 不应改变: %q", rules[1].ID)
	}
}

// 已移除的 socat 后端在加载时迁移为内置转发并写回配置
func TestLegacySocatMigrated(t *testing.T) {
	p := writeCfg(t, "backend: socat\nadmin: {password: secret123}\n")
	s, res, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.Get().Backend != "builtin" || !res.Changed {
		t.Fatalf("backend=%s changed=%v", s.Get().Backend, res.Changed)
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), "backend: builtin") {
		t.Errorf("迁移结果未写回配置: %s", b)
	}
}
