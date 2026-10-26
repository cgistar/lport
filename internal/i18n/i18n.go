// Package i18n 把后端返回给 Web 界面的中文消息翻译为其他语言。
//
// 后端代码中的消息仍直接用中文书写（命令行输出也是中文）。API 响应时按请求语言，用 catalog 中的
// 中文格式串匹配已生成的消息、提取参数（参数中的嵌套消息递归翻译），再套用译文格式重新生成。
// 新增中文消息时需在 catalog 中补充译文，TestCatalogCoversSource 会检查遗漏。
package i18n

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	ZH = "zh"
	EN = "en"
)

// listSep 拼接多条消息时使用的分隔符（如多个端口冲突），翻译时先按它拆分。
const listSep = "；"

var verbRe = regexp.MustCompile(`%[sdvwq]`)

type entry struct {
	re      *regexp.Regexp
	verbs   []string // 原文中各参数的格式动词
	en      []string // 译文按动词拆开的字面量片段，len = len(verbs)+1
	prefix  int      // 原文开头字面量的长度
	literal int      // 原文字面量总长度
}

var entries = func() []entry {
	out := make([]entry, 0, len(catalog))
	for zh, en := range catalog {
		out = append(out, compile(zh, en))
	}
	// 匹配顺序：开头字面量越长越优先（外层包装消息以固定文字开头、内层错误在末尾，
	// 先试外层才能正确拆分嵌套消息），其次字面量越长越具体
	sort.Slice(out, func(i, j int) bool {
		if out[i].prefix != out[j].prefix {
			return out[i].prefix > out[j].prefix
		}
		if out[i].literal != out[j].literal {
			return out[i].literal > out[j].literal
		}
		return out[i].re.String() < out[j].re.String()
	})
	return out
}()

func compile(zh, en string) entry {
	e := entry{verbs: verbRe.FindAllString(zh, -1), en: verbRe.Split(en, -1)}
	var b strings.Builder
	b.WriteString("^")
	for i, lit := range verbRe.Split(zh, -1) {
		if i == 0 {
			e.prefix = len(lit)
		}
		e.literal += len(lit)
		b.WriteString(regexp.QuoteMeta(lit))
		if i < len(e.verbs) {
			switch e.verbs[i] {
			case "%d":
				b.WriteString(`(-?\d+)`)
			case "%q":
				b.WriteString(`("(?:[^"\\]|\\.)*")`)
			default:
				b.WriteString(`(.*?)`)
			}
		}
	}
	b.WriteString("$")
	e.re = regexp.MustCompile(b.String())
	return e
}

// Translate 把后端生成的中文消息翻译为 lang；无对应译文的部分保持原样。
func Translate(s, lang string) string {
	if lang != EN {
		return s
	}
	out, _ := translate(s)
	return out
}

// translate 返回译文及其中残留的中文字符数。一条消息可能被多个格式匹配（如嵌套消息的外层与内层
// 都以参数开头或结尾），按 entries 顺序逐个尝试，取残留中文最少的拆法（相同时取先试到的）；
// 拆错时参数通常无法完整翻译，残留会更多。
func translate(s string) (string, int) {
	residual := cjkCount(s)
	if residual == 0 {
		return s, 0
	}
	if strings.Contains(s, listSep) {
		parts := strings.Split(s, listSep)
		total := 0
		for i, p := range parts {
			var n int
			parts[i], n = translate(p)
			total += n
		}
		return strings.Join(parts, "; "), total
	}
	best := s
	for _, e := range entries {
		m := e.re.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		var b strings.Builder
		left := 0
		for i, lit := range e.en {
			b.WriteString(lit)
			if i < len(e.verbs) {
				arg := m[i+1]
				if e.verbs[i] != "%d" && e.verbs[i] != "%q" {
					var n int
					arg, n = translate(arg)
					left += n
				} else {
					left += cjkCount(arg)
				}
				b.WriteString(arg)
			}
		}
		if left < residual {
			best, residual = b.String(), left
			if left == 0 {
				break
			}
		}
	}
	return best, residual
}

func cjkCount(s string) int {
	n := 0
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			n++
		}
	}
	return n
}

// FromRequest 返回请求使用的语言：优先 Web 界面发送的 X-Lport-Lang，其次 Accept-Language；
// 都没有时（如命令行经控制套接字访问）为中文。
func FromRequest(r *http.Request) string {
	switch strings.ToLower(r.Header.Get("X-Lport-Lang")) {
	case EN:
		return EN
	case ZH:
		return ZH
	}
	al := strings.TrimSpace(r.Header.Get("Accept-Language"))
	if al == "" || strings.HasPrefix(strings.ToLower(al), "zh") {
		return ZH
	}
	return EN
}
