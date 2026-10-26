package backend

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"lport/internal/model"
)

func stubDNS(t *testing.T, table map[string][]string) {
	t.Helper()
	old := lookupIPv4
	t.Cleanup(func() { lookupIPv4 = old })
	lookupIPv4 = func(_ context.Context, host string) ([]net.IP, error) {
		addrs, ok := table[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var ips []net.IP
		for _, a := range addrs {
			ips = append(ips, net.ParseIP(a))
		}
		return ips, nil
	}
}

func TestResolveHost(t *testing.T) {
	stubDNS(t, map[string][]string{
		"rr.example":    {"1.1.1.1", "2.2.2.2"},
		"local.example": {"127.0.0.1"},
	})
	if ip, _ := ResolveHost("10.0.0.1", ""); ip != "10.0.0.1" {
		t.Error("literal IP should pass through", ip)
	}
	if ip, _ := ResolveHost("rr.example", ""); ip != "1.1.1.1" {
		t.Error("expected first address", ip)
	}
	// 上次解析的地址仍有效时保持不变，避免 DNS 轮询导致规则抖动
	if ip, _ := ResolveHost("rr.example", "2.2.2.2"); ip != "2.2.2.2" {
		t.Error("expected preferred address", ip)
	}
	if _, err := ResolveHost("local.example", ""); err == nil {
		t.Error("loopback-only host should fail")
	}
	if _, err := ResolveHost("missing.example", ""); err == nil {
		t.Error("unresolvable host should fail")
	}
}

func TestResolveRulesAndDNSChange(t *testing.T) {
	stubDNS(t, map[string][]string{"a.example": {"1.1.1.1"}})
	rules := []model.Rule{
		{ID: "1", Proto: "tcp", ListenPort: 1000, Target: "a.example:80", Enabled: true},
		{ID: "2", Proto: "tcp", ListenPort: 1001, Target: "9.9.9.9:80", Enabled: true},
		{ID: "3", Proto: "tcp", ListenPort: 1002, Target: "bad.example:80", Enabled: true},
		{ID: "4", Proto: "tcp", ListenPort: 1003, Target: "a.example:81", Enabled: false},
	}
	out, ips, errs := resolveRules(rules, nil)
	if len(out) != 2 || out[0].Target != "1.1.1.1:80" || out[1].Target != "9.9.9.9:80" {
		t.Fatalf("unexpected resolved rules: %+v", out)
	}
	if ips["1"] != "1.1.1.1" || errs["3"] == "" || len(ips) != 1 || len(errs) != 1 {
		t.Fatalf("ips=%v errs=%v", ips, errs)
	}
	k := kernelState{rules: rules, ips: ips, errs: errs}
	st := k.status()
	if st["1"].State != "applied" || !strings.Contains(st["1"].Message, "1.1.1.1") || st["3"].State != "error" || st["4"].State != "stopped" {
		t.Fatalf("status=%+v", st)
	}
	if k.dnsChanged() {
		t.Fatal("no change expected")
	}
	stubDNS(t, map[string][]string{"a.example": {"3.3.3.3"}})
	if !k.dnsChanged() {
		t.Fatal("IP change should be detected")
	}
	stubDNS(t, map[string][]string{"a.example": {"1.1.1.1"}, "bad.example": {"4.4.4.4"}})
	if !k.dnsChanged() {
		t.Fatal("recovered resolution should be detected")
	}
}
