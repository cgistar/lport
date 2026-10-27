package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTranslate(t *testing.T) {
	cases := []struct{ in, want string }{
		{"规则不存在", "Rule not found"},
		{"目标端口无效: abc", "Invalid target port: abc"},
		{"与规则「web」(tcp/8080) 冲突", `Conflicts with rule "web" (tcp/8080)`},
		{"tcp 端口 22 已被 sshd (pid 1) 占用 (0.0.0.0:22)", "tcp port 22 is in use by sshd (pid 1) (0.0.0.0:22)"},
		{"udp 端口 53 已被 未知进程 占用 (0.0.0.0:53)", "udp port 53 is in use by an unknown process (0.0.0.0:53)"},
		// 多条冲突用「；」拼接，第一条带前缀
		{
			"端口冲突: 与规则「a」(tcp/80) 冲突；与规则「b」(udp/80) 冲突；与管理面板端口冲突",
			`Port conflict: Conflicts with rule "a" (tcp/80); Conflicts with rule "b" (udp/80); Conflicts with the admin panel port`,
		},
		// 嵌套消息逐层翻译，系统错误原样保留
		{
			"应用规则失败: nftables 未安装，请先在概览页安装",
			"Failed to apply rules: nftables is not installed; install it from the Overview page first",
		},
		{
			"规则「x」不适用于 nftables 后端: nftables 后端不能转发到回环地址 127.0.0.1，请改用 builtin 或 realm 后端",
			`Rule "x" is not compatible with the nftables backend: The nftables backend cannot forward to loopback address 127.0.0.1; use the builtin or realm backend instead`,
		},
		{"解析 foo.example 失败: lookup foo.example: no such host", "Failed to resolve foo.example: lookup foo.example: no such host"},
		{`listen 格式错误 "abc"，应为 ip:port`, `Invalid listen address "abc"; expected ip:port`},
		// 无译文或不含中文时原样返回
		{"tcp: connection reset", "tcp: connection reset"},
		{"某条未收录的消息", "某条未收录的消息"},
	}
	for _, c := range cases {
		if got := Translate(c.in, EN); got != c.want {
			t.Errorf("Translate(%q)\n got: %q\nwant: %q", c.in, got, c.want)
		}
		if got := Translate(c.in, ZH); got != c.in {
			t.Errorf("Translate(%q, zh) = %q，应原样返回", c.in, got)
		}
	}
}

func TestCatalogVerbs(t *testing.T) {
	for zh, en := range catalog {
		a, b := verbRe.FindAllString(zh, -1), verbRe.FindAllString(en, -1)
		if strings.Join(a, "") != strings.Join(b, "") {
			t.Errorf("%q 与译文 %q 的参数不一致: %v vs %v", zh, en, a, b)
		}
		if strings.Contains(zh, listSep) {
			t.Errorf("%q 含列表分隔符 %q，会被拆分导致无法匹配", zh, listSep)
		}
		if strings.Contains(en, "%[") {
			t.Errorf("译文 %q 不支持带序号的参数", en)
		}
	}
}

// 仅用于命令行或日志、不会返回给 Web 界面的中文字面量
var notUserFacing = map[string]bool{
	listSep: true,
	"# lport 配置文件，可手动编辑，重启服务后生效。\n# admin.password 可填写明文密码，启动时会自动转换为 password_hash。\n": true,
}

// TestCatalogCoversSource 检查 internal/ 下所有中文字符串字面量（日志与测试除外）都有译文。
func TestCatalogCoversSource(t *testing.T) {
	root := filepath.Join("..")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testnet" || d.Name() == "i18n") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "log" {
						return false
					}
				}
			}
			if field, ok := n.(*ast.Field); ok && field.Tag != nil {
				field.Tag = nil
			}
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil || cjkCount(s) == 0 || notUserFacing[s] {
				return true
			}
			if _, ok := catalog[s]; !ok {
				t.Errorf("%s: %q 缺少英文译文，请添加到 internal/i18n/catalog.go", fset.Position(lit.Pos()), s)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFromRequest(t *testing.T) {
	cases := []struct {
		header, accept, want string
	}{
		{"en", "zh-CN,zh", EN},
		{"zh", "en-US", ZH},
		{"", "en-US,en;q=0.9", EN},
		{"", "zh-CN,zh;q=0.9", ZH},
		{"", "", ZH},
	}
	for _, c := range cases {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		if c.header != "" {
			r.Header.Set("X-Lport-Lang", c.header)
		}
		if c.accept != "" {
			r.Header.Set("Accept-Language", c.accept)
		}
		if got := FromRequest(r); got != c.want {
			t.Errorf("X-Lport-Lang=%q Accept-Language=%q: got %s, want %s", c.header, c.accept, got, c.want)
		}
	}
}
