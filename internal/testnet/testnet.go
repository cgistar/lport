//go:build integration

// Package testnet 为集成测试搭建网络命名空间拓扑（需要 root）：
//
//	lpit-client (10.201.0.2) ── veth ── 本机 (10.201.0.1 | 10.200.0.1) ── veth ── lpit-target (10.200.0.2, 10.200.0.3)
//
// client 模拟外部客户端，流量经本机 PREROUTING → FORWARD → POSTROUTING 到达 target，
// 与真实转发路径一致。target 命名空间不设默认路由，回包只能依赖 MASQUERADE，可以验证 SNAT 是否生效。
package testnet

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	ClientNS = "lpit-client"
	TargetNS = "lpit-target"

	HostClientSide = "10.201.0.1" // 客户端访问的本机地址
	ClientIP       = "10.201.0.2"
	HostTargetSide = "10.200.0.1" // MASQUERADE 后目标看到的源地址
	TargetIP       = "10.200.0.2"
	TargetIP2      = "10.200.0.3" // 用于模拟域名解析结果变化

	TCPPort = 9000 // target 上的 TCP 服务：连接后返回 "lport-it <本端地址> <对端地址>"
	UDPPort = 9001 // target 上的 UDP 服务：回复 "lport-it <本端地址> <对端地址>"
)

func sh(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v: %s", strings.Join(args, " "), err, out)
	}
}

func quiet(args ...string) { _ = exec.Command(args[0], args[1:]...).Run() }

// RequireRoot 非 root 时跳过测试。
func RequireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("集成测试需要 root")
	}
}

// RequireTool 缺少命令时跳过测试。
func RequireTool(t *testing.T, bins ...string) {
	t.Helper()
	for _, b := range bins {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("未安装 %s", b)
		}
	}
}

func teardown() {
	quiet("ip", "netns", "del", ClientNS)
	quiet("ip", "netns", "del", TargetNS)
	quiet("ip", "link", "del", "lpit-h0")
	quiet("ip", "link", "del", "lpit-h1")
}

const serverScript = `
import socket, threading
def tcp():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", %d)); s.listen(64)
    while True:
        c, a = s.accept()
        try: c.sendall(("lport-it %%s %%s\n" %% (c.getsockname()[0], a[0])).encode())
        finally: c.close()
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, 8, 1)  # IP_PKTINFO：取得报文实际的目的地址
    s.bind(("0.0.0.0", %d))
    while True:
        d, anc, _, a = s.recvmsg(2048, 256)
        dst = "?"
        for lvl, typ, data in anc:
            if lvl == socket.IPPROTO_IP and typ == 8: dst = socket.inet_ntoa(data[8:12])
        s.sendto(("lport-it %%s %%s\n" %% (dst, a[0])).encode(), a)
threading.Thread(target=udp, daemon=True).start()
print("ready", flush=True)
tcp()
`

// Setup 创建拓扑并在 target 中启动 TCP/UDP 服务，测试结束时自动清理。
func Setup(t *testing.T) {
	t.Helper()
	RequireRoot(t)
	RequireTool(t, "ip", "python3")
	teardown()
	t.Cleanup(teardown)

	sh(t, "ip", "netns", "add", TargetNS)
	sh(t, "ip", "netns", "add", ClientNS)
	sh(t, "ip", "link", "add", "lpit-h0", "type", "veth", "peer", "name", "lpit-t0")
	sh(t, "ip", "link", "set", "lpit-t0", "netns", TargetNS)
	sh(t, "ip", "addr", "add", HostTargetSide+"/24", "dev", "lpit-h0")
	sh(t, "ip", "link", "set", "lpit-h0", "up")
	sh(t, "ip", "-n", TargetNS, "addr", "add", TargetIP+"/24", "dev", "lpit-t0")
	sh(t, "ip", "-n", TargetNS, "addr", "add", TargetIP2+"/24", "dev", "lpit-t0")
	sh(t, "ip", "-n", TargetNS, "link", "set", "lpit-t0", "up")
	sh(t, "ip", "-n", TargetNS, "link", "set", "lo", "up")

	sh(t, "ip", "link", "add", "lpit-h1", "type", "veth", "peer", "name", "lpit-c0")
	sh(t, "ip", "link", "set", "lpit-c0", "netns", ClientNS)
	sh(t, "ip", "addr", "add", HostClientSide+"/24", "dev", "lpit-h1")
	sh(t, "ip", "link", "set", "lpit-h1", "up")
	sh(t, "ip", "-n", ClientNS, "addr", "add", ClientIP+"/24", "dev", "lpit-c0")
	sh(t, "ip", "-n", ClientNS, "link", "set", "lpit-c0", "up")
	sh(t, "ip", "-n", ClientNS, "link", "set", "lo", "up")
	sh(t, "ip", "-n", ClientNS, "route", "add", "default", "via", HostClientSide)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", TargetNS, "python3", "-u", "-c", fmt.Sprintf(serverScript, TCPPort, UDPPort))
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	buf := make([]byte, 16)
	if n, _ := stdout.Read(buf); !strings.HasPrefix(string(buf[:n]), "ready") {
		t.Fatalf("target 服务启动失败: %q", buf[:n])
	}
}

// ForwardDrop 将 filter FORWARD 默认策略设为 DROP（模拟 Docker），测试结束后恢复。
func ForwardDrop(t *testing.T) {
	t.Helper()
	RequireTool(t, "iptables")
	out, _ := exec.Command("iptables", "-w", "-S", "FORWARD").Output()
	old := "ACCEPT"
	if strings.Contains(string(out), "-P FORWARD DROP") {
		old = "DROP"
	}
	sh(t, "iptables", "-w", "-P", "FORWARD", "DROP")
	t.Cleanup(func() { quiet("iptables", "-w", "-P", "FORWARD", old) })
}

const clientScript = `
import socket, sys
proto, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
if proto == "tcp":
    s = socket.create_connection((host, port), timeout=3)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.sendto(b"ping", (host, port))
print(s.recv(256).decode().strip())
`

// FromClient 在 client 命名空间中连接 本机:port，返回 target 的应答（"lport-it <目标地址> <源地址>"）。
func FromClient(proto string, port int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "netns", "exec", ClientNS, "python3", "-c", clientScript,
		proto, HostClientSide, fmt.Sprint(port)).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// FromHost 在本机连接 addr（经 OUTPUT 链），返回 TCP 应答。
func FromHost(addr string) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

// Reply 期望的应答内容。
func Reply(target, source string) string { return "lport-it " + target + " " + source }
