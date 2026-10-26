package backend

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"lport/internal/model"
	"lport/internal/sysinfo"
)

const (
	chainPre  = "LPORT_PRE"
	chainOut  = "LPORT_OUT"
	chainPost = "LPORT_POST"
	chainFwd  = "LPORT_FWD"
)

// jump 描述把自有链挂到内置链上的规则。
type jump struct {
	table, chain string
	match        []string
	target       string
}

var iptJumps = []jump{
	{"nat", "PREROUTING", nil, chainPre},
	{"nat", "OUTPUT", []string{"-m", "addrtype", "--dst-type", "LOCAL"}, chainOut},
	{"nat", "POSTROUTING", nil, chainPost},
	{"filter", "FORWARD", nil, chainFwd},
}

func (j jump) args(op string) []string {
	a := []string{"-w", "-t", j.table, op, j.chain}
	if op == "-I" {
		a = append(a, "1")
	}
	a = append(a, j.match...)
	return append(a, "-j", j.target)
}

// IptablesRestoreScript 生成 iptables-restore --noflush 的输入；
// 声明自有链会将其清空，因此整份脚本以原子方式替换自有链内容。
func IptablesRestoreScript(rules []model.Rule) string {
	var nat, filter strings.Builder
	for _, r := range enabled(rules) {
		host, port, _ := r.TargetHostPort()
		dst := host + ":" + strconv.Itoa(port)
		lp := strconv.Itoa(r.ListenPort)
		tp := strconv.Itoa(port)
		comment := fmt.Sprintf(`-m comment --comment "lport:%s"`, r.ID)
		for _, proto := range r.Protos() {
			fmt.Fprintf(&nat, "-A %s -p %s --dport %s %s -j DNAT --to-destination %s\n", chainPre, proto, lp, comment, dst)
			fmt.Fprintf(&nat, "-A %s -p %s --dport %s %s -j DNAT --to-destination %s\n", chainOut, proto, lp, comment, dst)
			fmt.Fprintf(&nat, "-A %s -p %s -d %s --dport %s -m conntrack --ctstate DNAT %s -j MASQUERADE\n", chainPost, proto, host, tp, comment)
			fmt.Fprintf(&filter, "-A %s -p %s -d %s --dport %s -m conntrack --ctstate DNAT %s -j ACCEPT\n", chainFwd, proto, host, tp, comment)
			fmt.Fprintf(&filter, "-A %s -p %s -s %s --sport %s -m conntrack --ctstate DNAT %s -j ACCEPT\n", chainFwd, proto, host, tp, comment)
		}
	}
	return fmt.Sprintf("*nat\n:%s - [0:0]\n:%s - [0:0]\n:%s - [0:0]\n%sCOMMIT\n*filter\n:%s - [0:0]\n%sCOMMIT\n",
		chainPre, chainOut, chainPost, nat.String(), chainFwd, filter.String())
}

// Iptables 使用自有链实现转发，不改动用户已有规则。
type Iptables struct {
	mu sync.Mutex
	kernelState
}

func (b *Iptables) Name() string     { return model.BackendIptables }
func (b *Iptables) Available() error { return checkTool("iptables") }

func (b *Iptables) Sync(rules []model.Rule) error {
	if err := b.Available(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(enabled(rules)) > 0 {
		if err := sysinfo.EnableIPForward(); err != nil {
			return err
		}
	}
	resolved, ips, errs := resolveRules(rules, b.ips)
	if err := run(IptablesRestoreScript(resolved), "iptables-restore", "-w", "--noflush"); err != nil {
		return err
	}
	if err := ensureJumps(); err != nil {
		return err
	}
	b.kernelState = kernelState{rules: rules, ips: ips, errs: errs}
	return nil
}

func ensureJumps() error {
	for _, j := range iptJumps {
		if run("", "iptables", j.args("-C")...) != nil {
			if err := run("", "iptables", j.args("-I")...); err != nil {
				return err
			}
		}
	}
	return nil
}

// Maintain 需与 Sync 串行调用（由 manager 保证）。
func (b *Iptables) Maintain() error {
	b.mu.Lock()
	k := b.kernelState
	b.mu.Unlock()
	if k.dnsChanged() {
		return b.Sync(k.rules)
	}
	return ensureJumps()
}

func (b *Iptables) Status() map[string]RuleStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.status()
}

func (b *Iptables) Cleanup() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.kernelState = kernelState{}
	if !sysinfo.ToolInstalled("iptables") {
		return nil
	}
	for _, j := range iptJumps {
		for i := 0; i < 10 && run("", "iptables", j.args("-D")...) == nil; i++ {
		}
	}
	for _, c := range []struct{ table, chain string }{
		{"nat", chainPre}, {"nat", chainOut}, {"nat", chainPost}, {"filter", chainFwd},
	} {
		_ = run("", "iptables", "-w", "-t", c.table, "-F", c.chain)
		_ = run("", "iptables", "-w", "-t", c.table, "-X", c.chain)
	}
	return nil
}
