package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"lport/internal/config"
)

const (
	CookieName = "lport_session"
	SessionTTL = 24 * time.Hour
)

type Auth struct {
	store *config.Store

	mu       sync.Mutex
	failures map[string][]time.Time
}

func New(store *config.Store) *Auth {
	return &Auth{store: store, failures: map[string][]time.Time{}}
}

// key 绑定密码 hash，修改密码后旧会话自动失效。
func (a *Auth) key() []byte {
	c := a.store.Get()
	return []byte(c.SessionSecret + "|" + c.Admin.PasswordHash)
}

func (a *Auth) sign(payload string) string {
	h := hmac.New(sha256.New, a.key())
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// limited 判断 IP 是否因失败过多被限制（每分钟 5 次）。
func (a *Auth) limited(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := time.Now().Add(-time.Minute)
	var kept []time.Time
	for _, t := range a.failures[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	a.failures[ip] = kept
	return len(kept) >= 5
}

func (a *Auth) fail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failures[ip] = append(a.failures[ip], time.Now())
}

var ErrTooMany = errors.New("登录失败次数过多，请一分钟后再试")
var ErrBadCredential = errors.New("用户名或密码错误")

// Login 校验用户名密码，成功返回会话 token。
func (a *Auth) Login(ip, user, pass string) (string, error) {
	if a.limited(ip) {
		return "", ErrTooMany
	}
	c := a.store.Get()
	okUser := subtle.ConstantTimeCompare([]byte(user), []byte(c.Admin.Username)) == 1
	okPass := bcrypt.CompareHashAndPassword([]byte(c.Admin.PasswordHash), []byte(pass)) == nil
	if !okUser || !okPass {
		a.fail(ip)
		return "", ErrBadCredential
	}
	exp := strconv.FormatInt(time.Now().Add(SessionTTL).Unix(), 10)
	payload := base64.RawURLEncoding.EncodeToString([]byte(user + "|" + exp))
	return payload + "." + a.sign(payload), nil
}

// Verify 校验 token，返回用户名。
func (a *Auth) Verify(token string) (string, bool) {
	payload, sig, ok := strings.Cut(token, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(a.sign(payload))) {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", false
	}
	user, expS, ok := strings.Cut(string(raw), "|")
	exp, err := strconv.ParseInt(expS, 10, 64)
	if !ok || err != nil || time.Now().Unix() > exp {
		return "", false
	}
	if user != a.store.Get().Admin.Username {
		return "", false
	}
	return user, true
}

// ChangePassword 校验旧密码后设置新密码。
func (a *Auth) ChangePassword(oldPass, newPass string) error {
	if len(newPass) < 6 {
		return errors.New("新密码至少 6 位")
	}
	c := a.store.Get()
	if bcrypt.CompareHashAndPassword([]byte(c.Admin.PasswordHash), []byte(oldPass)) != nil {
		return errors.New("原密码错误")
	}
	h, err := config.HashPassword(newPass)
	if err != nil {
		return err
	}
	return a.store.Update(func(c *config.Config) error {
		c.Admin.PasswordHash = h
		return nil
	})
}
