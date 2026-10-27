// Package probe 提供 TCP/UDP 端口连通性检测，用于排查转发故障。
package probe

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

const (
	StateOK      = "ok"
	StateFail    = "fail"
	StateUnknown = "unknown" // UDP 无响应，无法判断
	StateSkipped = "skipped"
)

type Result struct {
	Proto     string `json:"proto"`
	Addr      string `json:"addr"`
	State     string `json:"state"`
	LatencyMs int64  `json:"latency_ms"`
	Message   string `json:"message"`
}

func Skipped(proto, addr, msg string) Result {
	return Result{Proto: proto, Addr: addr, State: StateSkipped, Message: msg}
}

// TCP 尝试建立 TCP 连接。
func TCP(addr string, timeout time.Duration) Result {
	return tcp(addr, timeout, 0)
}

// TCPHold 建立连接后再观察 hold 时长：用户态代理（内置转发 / realm）会先接受连接再连目标，
// 目标不可达时会立即关闭连接，仅看握手会误判为成功。
func TCPHold(addr string, timeout, hold time.Duration) Result {
	return tcp(addr, timeout, hold)
}

func tcp(addr string, timeout, hold time.Duration) Result {
	r := Result{Proto: "tcp", Addr: addr}
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, timeout)
	r.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		r.State, r.Message = StateFail, describe(err)
		return r
	}
	defer c.Close()
	r.State, r.Message = StateOK, "连接成功"
	if hold <= 0 {
		return r
	}
	_ = c.SetReadDeadline(time.Now().Add(hold))
	n, err := c.Read(make([]byte, 1))
	switch {
	case n > 0:
		r.Message = "连接成功，收到数据"
	case errors.Is(err, os.ErrDeadlineExceeded):
		// 连接保持中，视为成功
	default:
		r.State, r.Message = StateFail, "连接建立后立即被关闭（转发进程无法连接目标）"
	}
	return r
}

// UDP 发送一个探测包：收到回复为成功，收到 ICMP 端口不可达为失败，超时无响应则无法判断。
func UDP(addr string, timeout time.Duration) Result {
	r := Result{Proto: "udp", Addr: addr}
	start := time.Now()
	c, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		r.State, r.Message = StateFail, describe(err)
		return r
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte("lport-probe\n")); err != nil {
		r.State, r.Message = StateFail, describe(err)
		return r
	}
	buf := make([]byte, 512)
	_, err = c.Read(buf)
	r.LatencyMs = time.Since(start).Milliseconds()
	switch {
	case err == nil:
		r.State, r.Message = StateOK, "收到响应"
	case errors.Is(err, os.ErrDeadlineExceeded):
		r.State, r.Message = StateUnknown, "无响应（UDP 无法确认端口是否开放，服务可能只响应特定协议数据）"
	default:
		r.State, r.Message = StateFail, describe(err)
	}
	return r
}

func describe(err error) string {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "连接被拒绝（端口未监听）"
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "连接超时（可能被防火墙丢弃或主机不可达）"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "主机不可达"
	case errors.Is(err, syscall.ENETUNREACH):
		return "网络不可达"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "连接超时（可能被防火墙丢弃或主机不可达）"
	}
	return err.Error()
}

// LocalIP 返回访问目标时使用的本机出口 IPv4；通过 UDP "连接"（不发送数据）让内核选路得到。
func LocalIP(targetIP string) string {
	c, err := net.Dial("udp4", net.JoinHostPort(targetIP, "9"))
	if err == nil {
		defer c.Close()
		if a, ok := c.LocalAddr().(*net.UDPAddr); ok && !a.IP.IsLoopback() {
			return a.IP.String()
		}
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			return n.IP.String()
		}
	}
	return ""
}
