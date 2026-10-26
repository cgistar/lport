package backend

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lport/internal/model"
)

var update = flag.Bool("update", false, "用当前输出重新生成 testdata/*.golden")

// assertGolden 将输出与 testdata 中的 golden 文件比对；规则生成逻辑有预期变更时，
// 执行 go test ./internal/backend -update 重新生成，并在 git diff 中审查差异。
func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败（首次运行请加 -update 生成）: %v", path, err)
	}
	if got != string(want) {
		t.Errorf("输出与 %s 不一致，若为预期变更请加 -update 重新生成\n--- got ---\n%s", path, got)
	}
}

var testRules = []model.Rule{
	{ID: "a1", Name: "web", Proto: "tcp", ListenPort: 8080, Target: "10.0.0.5:80", Enabled: true},
	{ID: "b2", Name: "dns", Proto: "both", ListenPort: 5353, Target: "10.0.0.6:53", Enabled: true},
	{ID: "c3", Name: "off", Proto: "udp", ListenPort: 9999, Target: "10.0.0.7:99", Enabled: false},
}

func TestSocatArgs(t *testing.T) {
	got := strings.Join(SocatArgs(testRules[0], "tcp"), " ")
	if got != "TCP4-LISTEN:8080,fork,reuseaddr TCP4:10.0.0.5:80" {
		t.Error(got)
	}
	got = strings.Join(SocatArgs(testRules[1], "udp"), " ")
	if got != "-T 120 UDP4-LISTEN:5353,fork,reuseaddr UDP4:10.0.0.6:53" {
		t.Error(got)
	}
}

func TestIptablesScript(t *testing.T) {
	assertGolden(t, "iptables.golden", IptablesRestoreScript(testRules))
}

func TestNftLinearScript(t *testing.T) {
	assertGolden(t, "nft_linear.golden", NftLinearScript(testRules))
}

func TestNftMapScript(t *testing.T) {
	rules := append(testRules, model.Rule{ID: "d4", Proto: "tcp", ListenPort: 8081, Target: "10.0.0.5:80", Enabled: true})
	assertGolden(t, "nft_map.golden", NftMapScript(rules))
	// 无规则时 map/set 不能带空 elements（nft 语法错误）
	if strings.Contains(NftMapScript(nil), "elements") {
		t.Error("empty map should omit elements")
	}
}
