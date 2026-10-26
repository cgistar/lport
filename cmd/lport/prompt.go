package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"

	"lport/internal/model"
	"lport/internal/sysinfo"
)

// prompter 负责安装时的交互问答；非交互模式下所有问题直接取默认值。
type prompter struct {
	interactive bool
	in          *bufio.Reader
}

func newPrompter(allow bool) *prompter {
	return &prompter{
		interactive: allow && term.IsTerminal(int(os.Stdin.Fd())),
		in:          bufio.NewReader(os.Stdin),
	}
}

// line 读取一行；输入结束（如 Ctrl-D）时取消安装，此时配置尚未写入。
func (p *prompter) line(prompt string) string {
	fmt.Print(prompt)
	s, err := p.in.ReadString('\n')
	if err != nil && strings.TrimSpace(s) == "" {
		fmt.Println("\n输入已结束，安装已取消")
		os.Exit(1)
	}
	return strings.TrimSpace(s)
}

// confirm 询问是否，def 为直接回车时的默认值。
func (p *prompter) confirm(question string, def bool) bool {
	if !p.interactive {
		return def
	}
	hint := "[Y/n]"
	if !def {
		hint = "[y/N]"
	}
	for {
		switch strings.ToLower(p.line(question + " " + hint + ": ")) {
		case "":
			return def
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
	}
}

// password 读取并确认新密码；直接回车返回空字符串，表示使用随机密码。
func (p *prompter) password() (string, error) {
	fd := int(os.Stdin.Fd())
	for {
		fmt.Print("设置管理员密码（至少 6 位，直接回车随机生成）: ")
		a, err := term.ReadPassword(fd)
		fmt.Println()
		if err != nil {
			return "", err
		}
		if len(a) == 0 {
			return "", nil
		}
		if len(a) < 6 {
			fmt.Println("  密码至少 6 位，请重新输入")
			continue
		}
		fmt.Print("再次输入密码: ")
		b, err := term.ReadPassword(fd)
		fmt.Println()
		if err != nil {
			return "", err
		}
		if string(a) != string(b) {
			fmt.Println("  两次输入不一致，请重新输入")
			continue
		}
		return string(a), nil
	}
}

// chooseBackend 让用户选择转发工具，默认 nftables；会拒绝与已有规则不兼容的后端。
func (p *prompter) chooseBackend(rules []model.Rule) string {
	const def = model.BackendNftables
	order := []string{model.BackendNftables, model.BackendIptables, model.BackendSocat}
	fmt.Println("选择默认转发工具:")
	for i, b := range order {
		state := "未安装，选择后可自动安装"
		if sysinfo.ToolInstalled(b) {
			state = "已安装"
		}
		fmt.Printf("  %d) %-9s %s\n", i+1, b, state)
	}
	for {
		ans := strings.ToLower(p.line(fmt.Sprintf("请选择 nftables / iptables / socat [%s]: ", def)))
		b := ans
		if ans == "" {
			b = def
		} else if n, err := strconv.Atoi(ans); err == nil && n >= 1 && n <= len(order) {
			b = order[n-1]
		}
		if !model.ValidBackend(b) {
			fmt.Println("  无效的选择")
			continue
		}
		if err := rulesCompatible(rules, b); err != nil {
			fmt.Println(" ", err)
			continue
		}
		return b
	}
}

func rulesCompatible(rules []model.Rule, backend string) error {
	for _, r := range rules {
		if err := r.Validate(backend); err != nil {
			return fmt.Errorf("规则「%s」不适用于 %s: %w", r.Name, backend, err)
		}
	}
	return nil
}
