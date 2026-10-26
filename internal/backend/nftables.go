package backend

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"lport/internal/model"
	"lport/internal/sysinfo"
)

const nftTable = "lport"

const (
	nftModeUnknown = ""
	nftModeMap     = "map"    // map 查找，规则数量不影响匹配开销（nft >= 0.9.4，内核 >= 5.6）
	nftModeLinear  = "linear" // 每条转发一条规则，兼容老版本 nft / 内核
)

// ConnMark 标记 lport 做了 DNAT 的连接，供 filter FORWARD 链放行（Docker 等会把 FORWARD 默认策略设为 DROP，
// 而独立 nft 表中的 accept 无法覆盖其它表的 drop）。只占用 ct mark 的一个比特位。
const ConnMark = 0x01000000

// nftForward 一条展开后的转发（both 已拆分）。
type nftForward struct {
	proto      string
	listenPort int
	host       string
	port       int
}

func nftForwards(rules []model.Rule) []nftForward {
	var out []nftForward
	for _, r := range enabled(rules) {
		host, port, _ := r.TargetHostPort()
		for _, proto := range r.Protos() {
			out = append(out, nftForward{proto, r.ListenPort, host, port})
		}
	}
	return out
}

func nftScript(body string) string {
	// 先建后删再建：保证表存在时可被删除，整个脚本在一个事务内原子生效
	return fmt.Sprintf("table ip %[1]s {}\ndelete table ip %[1]s\ntable ip %[1]s {\n%[2]s}\n", nftTable, body)
}

// NftMapScript 生成基于 map 的规则：每个协议一条 DNAT 规则，通过哈希查找目标。
func NftMapScript(rules []model.Rule) string {
	dnat := map[string][]string{}    // proto → "listenPort : host . port"
	lports := map[string][]string{}  // proto → listenPort
	targets := map[string][]string{} // proto → "host . port"，用于 SNAT 匹配
	seen := map[string]bool{}
	for _, f := range nftForwards(rules) {
		dnat[f.proto] = append(dnat[f.proto], fmt.Sprintf("%d : %s . %d", f.listenPort, f.host, f.port))
		lports[f.proto] = append(lports[f.proto], strconv.Itoa(f.listenPort))
		t := fmt.Sprintf("%s . %d", f.host, f.port)
		if !seen[f.proto+t] {
			seen[f.proto+t] = true
			targets[f.proto] = append(targets[f.proto], t)
		}
	}
	elements := func(items []string) string {
		if len(items) == 0 {
			return ""
		}
		return "\t\telements = { " + strings.Join(items, ", ") + " }\n"
	}
	protos := []string{model.ProtoTCP, model.ProtoUDP}
	var b strings.Builder
	for _, p := range protos {
		fmt.Fprintf(&b, "\tset lports_%s {\n\t\ttype inet_service\n%s\t}\n", p, elements(lports[p]))
		fmt.Fprintf(&b, "\tmap fwd_%s {\n\t\ttype inet_service : ipv4_addr . inet_service\n%s\t}\n", p, elements(dnat[p]))
		fmt.Fprintf(&b, "\tset dst_%s {\n\t\ttype ipv4_addr . inet_service\n%s\t}\n", p, elements(targets[p]))
	}
	// prerouting 只处理目的地址为本机的流量：本机兼作网关 / VPN / 容器宿主时，途经转发的流量不受影响
	b.WriteString("\tchain prerouting {\n\t\ttype nat hook prerouting priority -100; policy accept;\n")
	for _, p := range protos {
		fmt.Fprintf(&b, "\t\tfib daddr type local %s dport @lports_%s counter ct mark set ct mark or 0x%08x\n", p, p, ConnMark)
		fmt.Fprintf(&b, "\t\tfib daddr type local dnat ip addr . port to %s dport map @fwd_%s\n", p, p)
	}
	b.WriteString("\t}\n\tchain output {\n\t\ttype nat hook output priority -100; policy accept;\n")
	for _, p := range protos {
		fmt.Fprintf(&b, "\t\tfib daddr type local dnat ip addr . port to %s dport map @fwd_%s\n", p, p)
	}
	b.WriteString("\t}\n\tchain postrouting {\n\t\ttype nat hook postrouting priority 100; policy accept;\n")
	for _, p := range protos {
		fmt.Fprintf(&b, "\t\tct status dnat ip daddr . %s dport @dst_%s masquerade\n", p, p)
	}
	b.WriteString("\t}\n")
	return nftScript(b.String())
}

// NftLinearScript 生成每条转发一条规则的脚本，兼容老版本 nft。
// 使用数值优先级以兼容较老版本的 nft。
func NftLinearScript(rules []model.Rule) string {
	var pre, out, post strings.Builder
	for _, f := range nftForwards(rules) {
		dst := f.host + ":" + strconv.Itoa(f.port)
		fmt.Fprintf(&pre, "\t\tfib daddr type local %s dport %d counter ct mark set ct mark or 0x%08x dnat to %s\n", f.proto, f.listenPort, ConnMark, dst)
		fmt.Fprintf(&out, "\t\tfib daddr type local %s dport %d dnat to %s\n", f.proto, f.listenPort, dst)
		fmt.Fprintf(&post, "\t\tct status dnat ip daddr %s %s dport %d masquerade\n", f.host, f.proto, f.port)
	}
	return nftScript(fmt.Sprintf(`	chain prerouting {
		type nat hook prerouting priority -100; policy accept;
%s	}
	chain output {
		type nat hook output priority -100; policy accept;
%s	}
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
%s	}
`, pre.String(), out.String(), post.String()))
}

// fwdAcceptArgs 是插入 filter FORWARD 链的放行规则（通过 iptables 命令维护，兼容 iptables-nft / legacy）。
func fwdAcceptArgs(op string) []string {
	a := []string{"-w", "-t", "filter", op, "FORWARD"}
	if op == "-I" {
		a = append(a, "1")
	}
	mark := fmt.Sprintf("0x%x/0x%x", ConnMark, ConnMark)
	return append(a, "-m", "connmark", "--mark", mark, "-m", "comment", "--comment", "lport", "-j", "ACCEPT")
}

// ensureForwardAccept 在 filter FORWARD 链首放行带 lport 标记的连接。系统没有 iptables 时跳过
// （此时通常也没有其它会 drop 转发流量的 iptables 规则）。
func ensureForwardAccept() error {
	if !sysinfo.ToolInstalled("iptables") {
		return nil
	}
	if run("", "iptables", fwdAcceptArgs("-C")...) == nil {
		return nil
	}
	return run("", "iptables", fwdAcceptArgs("-I")...)
}

func removeForwardAccept() error {
	if !sysinfo.ToolInstalled("iptables") {
		return nil
	}
	for i := 0; i < 10 && run("", "iptables", fwdAcceptArgs("-D")...) == nil; i++ {
	}
	if run("", "iptables", fwdAcceptArgs("-C")...) == nil {
		return errors.New("删除 FORWARD 放行规则失败")
	}
	return nil
}

// Nftables 使用独立的 ip lport 表实现转发。
type Nftables struct {
	mu   sync.Mutex
	mode string
	kernelState
}

func (b *Nftables) Name() string     { return model.BackendNftables }
func (b *Nftables) Available() error { return checkTool("nftables") }

// Mode 返回当前使用的规则模式（map / linear），未应用过时为空。
func (b *Nftables) Mode() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.mode
}

func (b *Nftables) Sync(rules []model.Rule) error {
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
	if err := b.apply(resolved); err != nil {
		return err
	}
	if err := ensureForwardAccept(); err != nil {
		return fmt.Errorf("添加 FORWARD 放行规则失败: %w", err)
	}
	b.kernelState = kernelState{rules: rules, ips: ips, errs: errs}
	return nil
}

func (b *Nftables) apply(rules []model.Rule) error {
	if b.mode == nftModeLinear {
		return run(NftLinearScript(rules), "nft", "-f", "-")
	}
	mapErr := run(NftMapScript(rules), "nft", "-f", "-")
	if mapErr == nil {
		if b.mode == nftModeUnknown {
			log.Printf("nftables: 使用 map 查找模式")
		}
		b.mode = nftModeMap
		return nil
	}
	if b.mode == nftModeMap {
		return mapErr
	}
	// 首次失败时尝试兼容模式；nft -f 为事务，失败不会留下部分规则
	if err := run(NftLinearScript(rules), "nft", "-f", "-"); err != nil {
		return err
	}
	log.Printf("nftables: 当前 nft/内核不支持 map 方式 DNAT，已改用兼容模式: %v", mapErr)
	b.mode = nftModeLinear
	return nil
}

// Maintain 定期全量重新应用：重新解析域名，并修复被外部清除（如防火墙重载、nft flush ruleset）的
// lport 表与 FORWARD 放行规则。nft -f 在一个事务内替换整张表，不影响已建立的连接。
// 需与 Sync 串行调用（由 manager 保证）。
func (b *Nftables) Maintain() error {
	b.mu.Lock()
	rules := b.rules
	b.mu.Unlock()
	return b.Sync(rules)
}

func (b *Nftables) Status() map[string]RuleStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.status()
}

func (b *Nftables) Cleanup() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.kernelState = kernelState{}
	fwdErr := removeForwardAccept()
	if !sysinfo.ToolInstalled("nftables") {
		return fwdErr
	}
	// 先建后删，表不存在时也不会报错，因此这里的错误都是真实的删除失败
	if err := run("table ip "+nftTable+" {}\ndelete table ip "+nftTable+"\n", "nft", "-f", "-"); err != nil {
		return fmt.Errorf("删除 nftables 表失败: %w", err)
	}
	return fwdErr
}
