package config

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"

	"lport/internal/model"
	"lport/internal/sysinfo"
)

const DefaultPath = "/etc/lport/config.yaml"

type Admin struct {
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`      // 手动填写明文，启动时自动转为 hash 并清空
	PasswordHash string `yaml:"password_hash"` // bcrypt
}

type Config struct {
	Listen        string       `yaml:"listen"`
	Backend       string       `yaml:"backend"`
	Admin         Admin        `yaml:"admin"`
	SessionSecret string       `yaml:"session_secret"`
	Rules         []model.Rule `yaml:"rules"`
}

// Store 负责配置文件的加载、校验与写回。
type Store struct {
	path string
	mu   sync.RWMutex
	cfg  Config
}

// LoadResult 记录加载时自动做的修正，便于调用方打印提示。
type LoadResult struct {
	GeneratedPassword string // 非空表示首次启动生成了随机密码
	BackendAuto       bool   // 配置未指定 backend，已自动选择
	Changed           bool   // 是否需要写回文件
}

var idRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

func NewID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomString(n int) string {
	const chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

// Load 读取配置；文件不存在时使用默认配置。会补全缺省值并校验，校验失败返回错误；有补全时写回文件。
func Load(path string) (*Store, *LoadResult, error) {
	return load(path, true)
}

// LoadNoSave 同 Load，但不写回文件，由调用方在合适时机调用 Save（如交互式安装完成问答后）。
func LoadNoSave(path string) (*Store, *LoadResult, error) {
	return load(path, false)
}

func load(path string, save bool) (*Store, *LoadResult, error) {
	s := &Store{path: path}
	res := &LoadResult{}
	data, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		res.Changed = true
	case err != nil:
		return nil, nil, err
	default:
		if err := yaml.Unmarshal(data, &s.cfg); err != nil {
			return nil, nil, fmt.Errorf("解析配置文件 %s 失败: %w", path, err)
		}
	}
	if err := s.normalize(res); err != nil {
		return nil, nil, fmt.Errorf("配置文件 %s 校验失败: %w", path, err)
	}
	if res.Changed && save {
		if err := s.save(); err != nil {
			return nil, nil, err
		}
	}
	return s, res, nil
}

func (s *Store) normalize(res *LoadResult) error {
	c := &s.cfg
	if c.Listen == "" {
		c.Listen = "0.0.0.0:8080"
		res.Changed = true
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen 格式错误 %q，应为 ip:port", c.Listen)
	}
	if c.Backend == "" {
		c.Backend = autoBackend(c.Rules)
		res.BackendAuto = true
		res.Changed = true
	}
	if c.Backend == model.LegacyBackendSocat {
		log.Printf("socat 后端已移除，改用内置转发（builtin）")
		c.Backend = model.BackendBuiltin
		res.Changed = true
	}
	if !model.ValidBackend(c.Backend) {
		return fmt.Errorf("backend 必须是 builtin / realm / iptables / nftables，当前为 %q", c.Backend)
	}
	if c.Admin.Username == "" {
		c.Admin.Username = "admin"
		res.Changed = true
	}
	if c.Admin.Password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(c.Admin.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		c.Admin.PasswordHash = string(h)
		c.Admin.Password = ""
		res.Changed = true
	}
	if c.Admin.PasswordHash == "" {
		pw := randomString(12)
		h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		c.Admin.PasswordHash = string(h)
		res.GeneratedPassword = pw
		res.Changed = true
	}
	if len(c.SessionSecret) < 16 {
		c.SessionSecret = randomString(32)
		res.Changed = true
	}
	ids := map[string]bool{}
	for i := range c.Rules {
		r := &c.Rules[i]
		// ID 会写入 iptables 规则注释，只允许安全字符，手工编辑出的非法 ID 重新生成
		if !idRe.MatchString(r.ID) || ids[r.ID] {
			r.ID = NewID()
			res.Changed = true
		}
		ids[r.ID] = true
		if r.CreatedAt.IsZero() {
			r.CreatedAt = time.Now().Truncate(time.Second)
			res.Changed = true
		}
		if r.Name == "" {
			r.Name = "rule-" + strconv.Itoa(r.ListenPort)
			res.Changed = true
		}
		if err := r.Validate(c.Backend); err != nil {
			return fmt.Errorf("第 %d 条规则 (%s): %w", i+1, r.Name, err)
		}
	}
	if err := CheckRuleConflicts(c.Rules); err != nil {
		return err
	}
	if _, ps, _ := net.SplitHostPort(c.Listen); ps != "" {
		lp, _ := strconv.Atoi(ps)
		for _, r := range c.Rules {
			if r.ListenPort == lp && model.ProtoOverlap(r.Proto, model.ProtoTCP) {
				return fmt.Errorf("规则 %s 的监听端口 %d 与管理面板端口冲突", r.Name, lp)
			}
		}
	}
	return nil
}

// 便于测试替换
var (
	toolInstalled = sysinfo.ToolInstalled
	isRoot        = func() bool { return os.Geteuid() == 0 }
)

// autoBackend 为未指定后端的配置选择默认值：root 下优先 nftables，其次 iptables，
// 且需所有已有规则都适用于该后端；否则使用内置转发。
func autoBackend(rules []model.Rule) string {
	if !isRoot() {
		return model.BackendBuiltin
	}
	for _, b := range []string{model.BackendNftables, model.BackendIptables} {
		if !toolInstalled(b) {
			continue
		}
		ok := true
		for _, r := range rules {
			if r.Validate(b) != nil {
				ok = false
				break
			}
		}
		if ok {
			return b
		}
	}
	return model.BackendBuiltin
}

// CheckRuleConflicts 检查规则之间是否存在同协议同端口。
func CheckRuleConflicts(rules []model.Rule) error {
	for i := range rules {
		for j := i + 1; j < len(rules); j++ {
			a, b := rules[i], rules[j]
			if a.ListenPort == b.ListenPort && model.ProtoOverlap(a.Proto, b.Proto) {
				return fmt.Errorf("规则 %s 与 %s 的监听端口 %d 冲突", a.Name, b.Name, a.ListenPort)
			}
		}
	}
	return nil
}

func (s *Store) save() error {
	var buf bytes.Buffer
	buf.WriteString("# lport 配置文件，可手动编辑，重启服务后生效。\n# admin.password 可填写明文密码，启动时会自动转换为 password_hash。\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&s.cfg); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) Path() string { return s.path }

// Save 写回当前配置。
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save()
}

// Get 返回配置副本。
func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg
	c.Rules = append([]model.Rule(nil), s.cfg.Rules...)
	return c
}

// Update 在锁内修改配置并写回；fn 返回错误则不保存并回滚。
func (s *Store) Update(fn func(c *Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.cfg
	old.Rules = append([]model.Rule(nil), s.cfg.Rules...)
	if err := fn(&s.cfg); err != nil {
		s.cfg = old
		return err
	}
	if err := s.save(); err != nil {
		s.cfg = old
		return fmt.Errorf("保存配置失败: %w", err)
	}
	return nil
}

// HashPassword 生成 bcrypt hash。
func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

// RandomPassword 生成随机密码。
func RandomPassword() string { return randomString(12) }
