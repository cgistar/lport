package api

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"path"
	"path/filepath"
	"strings"

	"lport/internal/auth"
	"lport/internal/config"
	"lport/internal/manager"
)

type Server struct {
	store *config.Store
	mgr   *manager.Manager
	auth  *auth.Auth
	web   fs.FS
}

func New(store *config.Store, mgr *manager.Manager, a *auth.Auth, web fs.FS) *Server {
	return &Server{store: store, mgr: mgr, auth: a, web: web}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)

	authed := http.NewServeMux()
	authed.HandleFunc("GET /api/me", s.me)
	authed.HandleFunc("GET /api/system", s.system)
	authed.HandleFunc("POST /api/system/install", s.install)
	authed.HandleFunc("GET /api/settings", s.getSettings)
	authed.HandleFunc("PUT /api/settings", s.putSettings)
	authed.HandleFunc("PUT /api/settings/password", s.changePassword)
	authed.HandleFunc("GET /api/rules", s.listRules)
	authed.HandleFunc("POST /api/rules", s.createRule)
	authed.HandleFunc("PUT /api/rules/{id}", s.updateRule)
	authed.HandleFunc("DELETE /api/rules/{id}", s.deleteRule)
	authed.HandleFunc("POST /api/rules/{id}/toggle", s.toggleRule)
	authed.HandleFunc("POST /api/rules/{id}/probe", s.probeRule)
	authed.HandleFunc("GET /api/ports/check", s.checkPort)
	authed.HandleFunc("GET /api/ports/listening", s.listening)
	mux.Handle("/api/", s.requireAuth(authed))

	mux.Handle("/", s.spa())
	return localize(mux)
}

// SocketPath 返回本机控制套接字路径，放在配置目录下（0700），仅 root 可访问。
func SocketPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "lport.sock")
}

// LocalHandler 供控制套接字使用的规则接口（lport add/remove/list），由文件权限保证访问控制，无需登录。
func (s *Server) LocalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /rules", s.listRules)
	mux.HandleFunc("POST /rules", s.createRule)
	mux.HandleFunc("DELETE /rules/{id}", s.deleteRule)
	return mux
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(auth.CookieName)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, errors.New("未登录"))
			return
		}
		if _, ok := s.auth.Verify(c.Value); !ok {
			writeErr(w, http.StatusUnauthorized, errors.New("登录已过期"))
			return
		}
		// 变更请求要求 JSON，配合 SameSite=Strict 防御 CSRF
		if r.Method != http.MethodGet && r.ContentLength > 0 && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeErr(w, http.StatusUnsupportedMediaType, errors.New("Content-Type 必须为 application/json"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// spa 提供嵌入的前端文件，未知路径回落到 index.html。
func (s *Server) spa() http.Handler {
	fileServer := http.FileServerFS(s.web)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(s.web, p); err != nil {
			r.URL.Path = "/"
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		return errors.New("请求格式错误")
	}
	return nil
}

// fromTrustedProxy 请求是否来自本机反向代理（如同机部署的 nginx）。只信任回环地址发来的
// X-Forwarded-* 头，其它来源可以任意伪造这些头。
func fromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	return err == nil && ip != nil && ip.IsLoopback()
}

// clientIP 返回客户端 IP，用于登录失败限制。经本机反向代理时取 X-Forwarded-For 的最后一项
// （代理追加的、实际连接它的地址，前面的项可由客户端伪造），其次 X-Real-IP。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !fromTrustedProxy(r) {
		return host
	}
	if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
		parts := strings.Split(xff[len(xff)-1], ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(ip) != nil {
			return ip
		}
	}
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(ip) != nil {
		return ip
	}
	return host
}

// isHTTPS 浏览器到面板的连接是否为 HTTPS，包括由本机反向代理终止 TLS 的情况。
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || fromTrustedProxy(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
