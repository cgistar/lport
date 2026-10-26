package api

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func req(remote string, headers map[string]string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name, remote string
		headers      map[string]string
		want         string
	}{
		{"直连", "203.0.113.5:4000", nil, "203.0.113.5"},
		{"直连伪造 XFF 无效", "203.0.113.5:4000", map[string]string{"X-Forwarded-For": "1.2.3.4"}, "203.0.113.5"},
		{"本机代理取 XFF 最后一项", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "6.6.6.6, 198.51.100.7"}, "198.51.100.7"},
		{"本机代理 IPv6 回环", "[::1]:5000", map[string]string{"X-Forwarded-For": "198.51.100.7"}, "198.51.100.7"},
		{"本机代理 X-Real-IP", "127.0.0.1:5000", map[string]string{"X-Real-IP": "198.51.100.8"}, "198.51.100.8"},
		{"本机代理无头", "127.0.0.1:5000", nil, "127.0.0.1"},
		{"本机代理非法值", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "garbage"}, "127.0.0.1"},
	}
	for _, c := range cases {
		if got := clientIP(req(c.remote, c.headers)); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestIsHTTPS(t *testing.T) {
	proto := map[string]string{"X-Forwarded-Proto": "https"}
	if !isHTTPS(req("127.0.0.1:5000", proto)) {
		t.Error("本机代理声明 https 时应视为 HTTPS")
	}
	if isHTTPS(req("203.0.113.5:4000", proto)) {
		t.Error("非本机来源的 X-Forwarded-Proto 不可信")
	}
	if isHTTPS(req("127.0.0.1:5000", nil)) {
		t.Error("无 TLS、无代理头时不是 HTTPS")
	}
	r := req("203.0.113.5:4000", nil)
	r.TLS = &tls.ConnectionState{}
	if !isHTTPS(r) {
		t.Error("直接 TLS 连接应视为 HTTPS")
	}
}
