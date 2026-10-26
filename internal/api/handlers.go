package api

import (
	"errors"
	"net/http"
	"strconv"

	"lport/internal/auth"
	"lport/internal/model"
	"lport/internal/portcheck"
	"lport/internal/sysinfo"
)

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	token, err := s.auth.Login(clientIP(r), req.Username, req.Password)
	if err != nil {
		code := http.StatusUnauthorized
		if errors.Is(err, auth.ErrTooMany) {
			code = http.StatusTooManyRequests
		}
		writeErr(w, code, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: auth.CookieName, Value: token, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: int(auth.SessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]string{"username": req.Username})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: auth.CookieName, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"username": s.store.Get().Admin.Username})
}

func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"info":         sysinfo.Detect(),
		"backend":      s.mgr.BackendName(),
		"backend_mode": s.mgr.BackendMode(),
		"sync_error":   s.mgr.SyncError(),
		"config_path":  s.store.Path(),
		"listen":       s.store.Get().Listen,
	})
}

func (s *Server) install(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tools []string `json:"tools"`
	}
	if err := readJSON(r, &req); err != nil || len(req.Tools) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("请指定要安装的工具"))
		return
	}
	cmd, out, err := sysinfo.Install(req.Tools)
	resp := map[string]any{"command": cmd, "output": out, "ok": err == nil}
	if err != nil {
		resp["error"] = err.Error()
	} else if s.mgr.SyncError() != "" {
		// 依赖装好后自动重新应用规则
		_ = s.mgr.Reapply()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	c := s.store.Get()
	writeJSON(w, http.StatusOK, map[string]any{
		"backend":  s.mgr.BackendName(),
		"backends": model.Backends,
		"listen":   c.Listen,
		"username": c.Admin.Username,
	})
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Backend string `json:"backend"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.mgr.SetBackend(req.Backend); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.getSettings(w, r)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.auth.ChangePassword(req.OldPassword, req.NewPassword); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.Rules())
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	var rule model.Rule
	if err := readJSON(r, &rule); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	created, err := s.mgr.Create(rule)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, created)
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	var rule model.Rule
	if err := readJSON(r, &rule); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	updated, err := s.mgr.Update(r.PathValue("id"), rule)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.Delete(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) toggleRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.mgr.Toggle(r.PathValue("id"), req.Enabled); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) probeRule(w http.ResponseWriter, r *http.Request) {
	res, err := s.mgr.Probe(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) checkPort(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	port, err := strconv.Atoi(q.Get("port"))
	if err != nil || port < 1 || port > 65535 {
		writeErr(w, http.StatusBadRequest, errors.New("端口必须在 1-65535 之间"))
		return
	}
	proto := q.Get("proto")
	if proto != model.ProtoTCP && proto != model.ProtoUDP && proto != model.ProtoBoth {
		writeErr(w, http.StatusBadRequest, errors.New("协议必须是 tcp / udp / both"))
		return
	}
	cs := s.mgr.CheckPort(proto, port, q.Get("exclude"), true)
	writeJSON(w, http.StatusOK, map[string]any{"available": len(cs) == 0, "conflicts": cs})
}

func (s *Server) listening(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, portcheck.Listeners(true))
}
