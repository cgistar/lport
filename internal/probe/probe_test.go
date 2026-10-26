package probe

import (
	"net"
	"testing"
	"time"
)

func TestTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if r := TCP(addr, time.Second); r.State != StateOK {
		t.Errorf("open port: %+v", r)
	}
	l.Close()
	if r := TCP(addr, time.Second); r.State != StateFail {
		t.Errorf("closed port: %+v", r)
	}
}

func TestTCPHold(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// 模拟 socat 连不上目标：接受后立即关闭
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if r := TCPHold(l.Addr().String(), time.Second, 500*time.Millisecond); r.State != StateFail {
		t.Errorf("immediate close should fail: %+v", r)
	}
	// 保持连接不关闭 → 成功
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l2.Close()
	go func() {
		c, err := l2.Accept()
		if err == nil {
			time.Sleep(time.Second)
			c.Close()
		}
	}()
	if r := TCPHold(l2.Addr().String(), time.Second, 300*time.Millisecond); r.State != StateOK {
		t.Errorf("held connection should succeed: %+v", r)
	}
}

func TestUDP(t *testing.T) {
	// 回显服务 → 成功
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 64)
		n, a, err := pc.ReadFrom(buf)
		if err == nil {
			pc.WriteTo(buf[:n], a)
		}
	}()
	if r := UDP(pc.LocalAddr().String(), time.Second); r.State != StateOK {
		t.Errorf("echo: %+v", r)
	}
	// 监听但不回复 → 无法判断
	silent, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer silent.Close()
	if r := UDP(silent.LocalAddr().String(), 300*time.Millisecond); r.State != StateUnknown {
		t.Errorf("silent: %+v", r)
	}
	// 未监听 → ICMP 端口不可达 → 失败
	addr := pc.LocalAddr().String()
	pc.Close()
	if r := UDP(addr, time.Second); r.State != StateFail {
		t.Errorf("closed: %+v", r)
	}
}
