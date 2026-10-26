//go:build integration

package manager

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lport/internal/config"
	"lport/internal/probe"
	"lport/internal/testnet"
)

// TestIntegrationProbe 在真实转发上验证连通性检测：本机检测经转发路径，目标检测直连；
// socat 后端下目标不可达时，本机检测须识别出「接受后立即关闭」而不是误报成功。
func TestIntegrationProbe(t *testing.T) {
	testnet.Setup(t)
	testnet.ForwardDrop(t)
	for _, c := range []struct{ backend, tool string }{{"nftables", "nft"}, {"iptables", "iptables"}, {"socat", "socat"}} {
		t.Run(c.backend, func(t *testing.T) {
			testnet.RequireTool(t, c.tool)
			path := filepath.Join(t.TempDir(), "config.yaml")
			cfg := fmt.Sprintf(`listen: 127.0.0.1:18999
backend: %s
admin: {password: it-password}
rules:
  - {id: ok, proto: tcp, listen_port: 18090, target: "%[2]s:9000", enabled: true}
  - {id: dead, proto: tcp, listen_port: 18091, target: "%[2]s:9999", enabled: true}
  - {id: udp, proto: udp, listen_port: 18092, target: "%[2]s:9001", enabled: true}
  - {id: off, proto: tcp, listen_port: 18093, target: "%[2]s:9000", enabled: false}
`, c.backend, testnet.TargetIP)
			if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			store, _, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			m := New(store)
			m.Start()
			t.Cleanup(m.Stop)
			if e := m.SyncError(); e != "" {
				t.Fatalf("应用规则失败: %s", e)
			}

			expect := func(id string, local, target string) {
				t.Helper()
				var res *ProbeResult
				// socat 进程启动需要一点时间，最多等待 5 秒
				for deadline := time.Now().Add(5 * time.Second); ; {
					res, err = m.Probe(id)
					if err != nil {
						t.Fatal(err)
					}
					if res.Local[0].State == local || time.Now().After(deadline) {
						break
					}
					time.Sleep(200 * time.Millisecond)
				}
				if res.Local[0].State != local || res.Target[0].State != target {
					t.Errorf("规则 %s: 本机=%s(%s) 目标=%s(%s)，期望 本机=%s 目标=%s", id,
						res.Local[0].State, res.Local[0].Message, res.Target[0].State, res.Target[0].Message, local, target)
				}
			}
			expect("ok", probe.StateOK, probe.StateOK)
			expect("dead", probe.StateFail, probe.StateFail)
			expect("udp", probe.StateOK, probe.StateOK)
			expect("off", probe.StateSkipped, probe.StateOK)
		})
	}
}
