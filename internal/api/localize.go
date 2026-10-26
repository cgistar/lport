package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"lport/internal/i18n"
)

// messageKeys 响应 JSON 中需要翻译的字段：错误、端口冲突 / 连通性检测 / 规则状态的消息、规则应用错误。
var messageKeys = map[string]bool{"error": true, "message": true, "sync_error": true}

// localize 按请求语言翻译 /api/ 响应中的消息字段；中文请求直接透传。
func localize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := i18n.FromRequest(r)
		if lang == i18n.ZH || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		bw := &bufferedWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(bw, r)
		body := bw.buf.Bytes()
		if strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			var v any
			dec := json.NewDecoder(bytes.NewReader(body))
			dec.UseNumber()
			if dec.Decode(&v) == nil {
				var out bytes.Buffer
				if json.NewEncoder(&out).Encode(translateJSON(v, lang)) == nil {
					body = out.Bytes()
				}
			}
		}
		w.WriteHeader(bw.code)
		_, _ = w.Write(body)
	})
}

func translateJSON(v any, lang string) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok && messageKeys[k] {
				x[k] = i18n.Translate(s, lang)
			} else {
				x[k] = translateJSON(val, lang)
			}
		}
	case []any:
		for i := range x {
			x[i] = translateJSON(x[i], lang)
		}
	}
	return v
}

type bufferedWriter struct {
	http.ResponseWriter
	code int
	buf  bytes.Buffer
}

func (b *bufferedWriter) WriteHeader(code int) { b.code = code }

func (b *bufferedWriter) Write(p []byte) (int, error) { return b.buf.Write(p) }
