package model

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	ProtoTCP  = "tcp"
	ProtoUDP  = "udp"
	ProtoBoth = "both"
)

const (
	BackendSocat    = "socat"
	BackendIptables = "iptables"
	BackendNftables = "nftables"
)

var Backends = []string{BackendSocat, BackendIptables, BackendNftables}

func ValidBackend(b string) bool {
	for _, x := range Backends {
		if x == b {
			return true
		}
	}
	return false
}

// Rule 一条端口转发规则：本机 ListenPort → Target(host:port)。
type Rule struct {
	ID         string    `yaml:"id" json:"id"`
	Name       string    `yaml:"name" json:"name"`
	Proto      string    `yaml:"proto" json:"proto"`
	ListenPort int       `yaml:"listen_port" json:"listen_port"`
	Target     string    `yaml:"target" json:"target"`
	Enabled    bool      `yaml:"enabled" json:"enabled"`
	Remark     string    `yaml:"remark,omitempty" json:"remark"`
	CreatedAt  time.Time `yaml:"created_at,omitempty" json:"created_at"`
}

// Protos 把 both 展开成 tcp/udp。
func (r Rule) Protos() []string {
	if r.Proto == ProtoBoth {
		return []string{ProtoTCP, ProtoUDP}
	}
	return []string{r.Proto}
}

// TargetHostPort 拆分目标地址。
func (r Rule) TargetHostPort() (string, int, error) {
	host, ps, err := net.SplitHostPort(strings.TrimSpace(r.Target))
	if err != nil {
		return "", 0, fmt.Errorf("目标地址格式应为 host:port")
	}
	p, err := strconv.Atoi(ps)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("目标端口无效: %s", ps)
	}
	if host == "" {
		return "", 0, fmt.Errorf("目标主机不能为空")
	}
	return host, p, nil
}

// ProtoOverlap 判断两个协议设置是否有交集。
func ProtoOverlap(a, b string) bool {
	return a == b || a == ProtoBoth || b == ProtoBoth
}

var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// Validate 校验规则本身的合法性（不含端口冲突检查）。
func (r *Rule) Validate(backend string) error {
	r.Name = strings.TrimSpace(r.Name)
	r.Target = strings.TrimSpace(r.Target)
	r.Proto = strings.ToLower(strings.TrimSpace(r.Proto))
	switch r.Proto {
	case ProtoTCP, ProtoUDP, ProtoBoth:
	default:
		return fmt.Errorf("协议必须是 tcp / udp / both")
	}
	if r.ListenPort < 1 || r.ListenPort > 65535 {
		return fmt.Errorf("监听端口必须在 1-65535 之间")
	}
	host, port, err := r.TargetHostPort()
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() != nil {
		// 统一为点分十进制，避免 ::ffff:1.2.3.4 这类 IPv4 映射地址原样进入 iptables / nft / socat 参数
		host = ip.To4().String()
		r.Target = net.JoinHostPort(host, strconv.Itoa(port))
	}
	if ip == nil {
		// 域名：socat 直接使用；内核后端解析为 IPv4 后应用，并定期重新解析
		if !hostnameRe.MatchString(host) {
			return fmt.Errorf("目标主机既不是 IP 也不是合法域名: %s", host)
		}
		return nil
	}
	if ip.To4() == nil {
		return fmt.Errorf("目前仅支持 IPv4 目标地址")
	}
	if backend == BackendSocat {
		return nil
	}
	if ip.IsLoopback() {
		return fmt.Errorf("%s 后端不能转发到回环地址 %s，请改用 socat 后端", backend, host)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("目标地址不能是 0.0.0.0")
	}
	return nil
}

// SameForward 判断两条规则的实际转发配置是否一致（用于 socat diff）。
func (r Rule) SameForward(o Rule) bool {
	return r.Proto == o.Proto && r.ListenPort == o.ListenPort && r.Target == o.Target
}
