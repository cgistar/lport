//go:build integration

package backend

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"lport/internal/model"
	"lport/internal/testnet"
)

const domainTarget = "target.lport.test"

func itRules() []model.Rule {
	return []model.Rule{
		{ID: "tcp", Name: "tcp", Proto: "tcp", ListenPort: 18080, Target: "10.200.0.2:9000", Enabled: true},
		{ID: "udp", Name: "udp", Proto: "udp", ListenPort: 18081, Target: "10.200.0.2:9001", Enabled: true},
		{ID: "dns", Name: "dns", Proto: "tcp", ListenPort: 18082, Target: domainTarget + ":9000", Enabled: true},
		{ID: "both", Name: "both", Proto: "both", ListenPort: 18083, Target: "10.200.0.2:9000", Enabled: true},
		{ID: "off", Name: "off", Proto: "tcp", ListenPort: 18084, Target: "10.200.0.2:9000", Enabled: false},
	}
}

func expectReply(t *testing.T, what string, got string, err error, want string) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: 连接失败: %v", what, err)
	} else if got != want {
		t.Errorf("%s: 应答 %q，期望 %q", what, got, want)
	}
}

func expectFail(t *testing.T, what string, got string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: 期望失败，实际收到 %q", what, got)
	}
}

func output(args ...string) string {
	out, _ := exec.Command(args[0], args[1:]...).CombinedOutput()
	return string(out)
}

// TestIntegrationBackends 在真实内核上验证各后端：外部客户端经 PREROUTING/FORWARD（FORWARD 默认 DROP，
// 模拟 Docker）访问、本机经 OUTPUT 访问、UDP、双协议、域名目标、途经转发的流量不被劫持、DNS 变化后自动更新、
// 规则（FORWARD 放行、NAT 表 / 链）被外部清除后自动修复与清理。
func TestIntegrationBackends(t *testing.T) {
	testnet.Setup(t)
	testnet.ForwardDrop(t)

	cases := []struct {
		name   string
		tool   string
		new    func() Backend
		kernel bool
	}{
		{"nftables-map", "nft", func() Backend { return &Nftables{} }, true},
		{"nftables-linear", "nft", func() Backend { return &Nftables{mode: nftModeLinear} }, true},
		{"iptables", "iptables", func() Backend { return &Iptables{} }, true},
		{"socat", "socat", func() Backend { return NewSocat() }, false},
		{"realm", "realm", func() Backend { return NewRealm() }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testnet.RequireTool(t, c.tool)
			stubDNS(t, map[string][]string{domainTarget: {testnet.TargetIP}})
			b := c.new()
			rules := itRules()
			if !c.kernel {
				rules = rules[:2] // 用户态后端自行解析域名，不受 stubDNS 影响；其余场景已由内核后端覆盖
			}
			if err := b.Sync(rules); err != nil {
				t.Fatalf("Sync: %v", err)
			}
			t.Cleanup(func() { _ = b.Cleanup() })
			if n, ok := b.(*Nftables); ok {
				t.Logf("nftables 模式: %s", n.Mode())
			}
			waitSocat(t, b)

			viaHost := testnet.Reply(testnet.TargetIP, testnet.HostTargetSide)
			got, err := testnet.FromClient("tcp", 18080)
			expectReply(t, "外部客户端 TCP", got, err, viaHost)
			got, err = testnet.FromClient("udp", 18081)
			expectReply(t, "外部客户端 UDP", got, err, viaHost)
			got, err = testnet.FromHost(testnet.HostClientSide + ":18080")
			expectReply(t, "本机经 OUTPUT", got, err, viaHost)
			if !c.kernel {
				return
			}

			got, err = testnet.FromClient("tcp", 18082)
			expectReply(t, "域名目标", got, err, viaHost)
			got, err = testnet.FromClient("tcp", 18083)
			expectReply(t, "both 规则 TCP", got, err, viaHost)
			got, err = testnet.FromClient("tcp", 18084)
			expectFail(t, "停用规则", got, err)
			// 本机兼作网关时，途经本机发往其它主机同端口的流量不能被 DNAT 劫持
			got, err = testnet.FromClientTo("tcp", testnet.TargetIP, 18080)
			expectFail(t, "途经转发的流量", got, err)
			if st := b.Status()["dns"]; st.State != "applied" || !strings.Contains(st.Message, testnet.TargetIP) {
				t.Errorf("域名规则状态: %+v", st)
			}

			// 域名解析结果变化 → Maintain 重新应用
			stubDNS(t, map[string][]string{domainTarget: {testnet.TargetIP2}})
			if err := b.(Maintainer).Maintain(); err != nil {
				t.Fatalf("Maintain: %v", err)
			}
			got, err = testnet.FromClient("tcp", 18082)
			expectReply(t, "DNS 变化后", got, err, testnet.Reply(testnet.TargetIP2, testnet.HostTargetSide))

			// FORWARD 放行规则被外部清除（如防火墙重载）→ 转发失败 → Maintain 自动修复
			switch b.(type) {
			case *Nftables:
				_ = removeForwardAccept()
			case *Iptables:
				_ = exec.Command("iptables", "-w", "-D", "FORWARD", "-j", chainFwd).Run()
			}
			got, err = testnet.FromClient("tcp", 18080)
			expectFail(t, "FORWARD 放行被清除后", got, err)
			if err := b.(Maintainer).Maintain(); err != nil {
				t.Fatalf("Maintain: %v", err)
			}
			got, err = testnet.FromClient("tcp", 18080)
			expectReply(t, "Maintain 修复后", got, err, viaHost)

			// NAT 表 / 自有链被外部删除或清空（如 nft flush ruleset、防火墙重载）→ Maintain 全量重建
			switch b.(type) {
			case *Nftables:
				_ = exec.Command("nft", "delete", "table", "ip", nftTable).Run()
			case *Iptables:
				_ = exec.Command("iptables", "-w", "-t", "nat", "-F", chainPre).Run()
			}
			got, err = testnet.FromClient("tcp", 18080)
			expectFail(t, "NAT 规则被清除后", got, err)
			if err := b.(Maintainer).Maintain(); err != nil {
				t.Fatalf("Maintain: %v", err)
			}
			got, err = testnet.FromClient("tcp", 18080)
			expectReply(t, "NAT 重建后", got, err, viaHost)

			// 清理后不再转发，且不留残余
			if err := b.Cleanup(); err != nil {
				t.Fatalf("Cleanup: %v", err)
			}
			got, err = testnet.FromClient("tcp", 18080)
			expectFail(t, "Cleanup 后", got, err)
			if out := output("nft", "list", "tables"); strings.Contains(out, "table ip lport") {
				t.Errorf("Cleanup 后仍有 lport 表: %s", out)
			}
			if out := output("iptables", "-w", "-S", "FORWARD"); strings.Contains(out, "lport") || strings.Contains(out, chainFwd) {
				t.Errorf("Cleanup 后 FORWARD 仍有残留: %s", out)
			}
		})
	}
}

// waitSocat 等待用户态转发进程开始监听测试端口。
func waitSocat(t *testing.T, b Backend) {
	t.Helper()
	if _, ok := b.(*Process); !ok {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(output("ss", "-lnt"), ":18080 ") && strings.Contains(output("ss", "-lnu"), ":18081 ") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal(b.Name() + " 未能启动监听")
}
