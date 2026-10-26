package backend

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"lport/internal/model"
	"lport/internal/sysinfo"
)

// RuleStatus 规则运行状态。
type RuleStatus struct {
	State    string `json:"state"` // running | stopped | error | applied
	Message  string `json:"message,omitempty"`
	PIDs     []int  `json:"pids,omitempty"`
	Restarts int    `json:"restarts,omitempty"`
}

type Backend interface {
	Name() string
	Available() error
	// Sync 按启用的规则全量同步（幂等）。
	Sync(rules []model.Rule) error
	Status() map[string]RuleStatus
	// Cleanup 清除本工具创建的所有转发。
	Cleanup() error
}

// Maintainer 由内核后端实现，定期调用：域名解析结果变化时重新应用规则，并修复被外部清除的规则。
type Maintainer interface {
	Maintain() error
}

func New(name string) (Backend, error) {
	switch name {
	case model.BackendSocat:
		return NewSocat(), nil
	case model.BackendIptables:
		return &Iptables{}, nil
	case model.BackendNftables:
		return &Nftables{}, nil
	}
	return nil, fmt.Errorf("未知后端: %s", name)
}

func checkTool(tool string) error {
	if !sysinfo.ToolInstalled(tool) {
		return fmt.Errorf("%s 未安装，请先在概览页安装", tool)
	}
	return nil
}

func enabled(rules []model.Rule) []model.Rule {
	var out []model.Rule
	for _, r := range rules {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out
}

func run(stdin string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(buf.String()))
	}
	return nil
}
