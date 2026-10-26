package portcheck

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Listener 系统中一个被占用的端口。
type Listener struct {
	Proto   string `json:"proto"` // tcp | udp
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Inode   uint64 `json:"-"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
}

// BlocksIPv4 判断该监听是否占用 IPv4 端口。转发只监听 / DNAT IPv4，绑定在具体 IPv6 地址（如 ::1）上的
// 监听互不影响；[::] 通常为双栈（net.ipv6.bindv6only=0），按占用处理。
func (l Listener) BlocksIPv4() bool {
	ip := net.ParseIP(l.Addr)
	return ip == nil || ip.To4() != nil || ip.IsUnspecified()
}

// ParseProcNet 解析 /proc/net/{tcp,tcp6,udp,udp6} 的内容。
// TCP 只返回 LISTEN(0A) 状态；UDP 返回全部已绑定端口。
func ParseProcNet(r io.Reader, proto string, v6 bool) ([]Listener, error) {
	var out []Listener
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		if proto == "tcp" && f[3] != "0A" {
			continue
		}
		hexAddr, hexPort, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil || port == 0 {
			continue
		}
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, Listener{Proto: proto, Addr: decodeAddr(hexAddr, v6), Port: int(port), Inode: inode})
	}
	return out, sc.Err()
}

// decodeAddr 将 /proc/net 中小端序的十六进制地址转为可读形式。
func decodeAddr(h string, v6 bool) string {
	b := make([]byte, len(h)/2)
	for i := range b {
		v, err := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
		if err != nil {
			return h
		}
		b[i] = byte(v)
	}
	// 每 4 字节为一个小端序的 32 位整数
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	if !v6 && len(b) == 4 {
		return net.IP(b).String()
	}
	if len(b) == 16 {
		return net.IP(b).String()
	}
	return h
}

// SocketOwners 扫描 /proc/*/fd 建立 socket inode → pid 映射。
func SocketOwners() map[uint64]int {
	m := map[uint64]int{}
	procs, _ := filepath.Glob("/proc/[0-9]*")
	for _, p := range procs {
		pid, err := strconv.Atoi(filepath.Base(p))
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(p + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(p + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
			if err == nil {
				m[ino] = pid
			}
		}
	}
	return m
}

func procName(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ParentPID 读取进程的父进程 pid。
func ParentPID(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(b)
	// comm 字段可能含空格，从最后一个 ')' 之后开始解析
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(f[1])
	return ppid
}

// Listeners 返回系统所有监听/绑定端口（去重，附带进程信息）。
func Listeners(withProcess bool) []Listener {
	var all []Listener
	for _, src := range []struct {
		file, proto string
		v6          bool
	}{
		{"/proc/net/tcp", "tcp", false},
		{"/proc/net/tcp6", "tcp", true},
		{"/proc/net/udp", "udp", false},
		{"/proc/net/udp6", "udp", true},
	} {
		f, err := os.Open(src.file)
		if err != nil {
			continue
		}
		ls, _ := ParseProcNet(f, src.proto, src.v6)
		f.Close()
		all = append(all, ls...)
	}
	if withProcess {
		owners := SocketOwners()
		for i := range all {
			if pid, ok := owners[all[i].Inode]; ok {
				all[i].PID = pid
				all[i].Process = procName(pid)
			}
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Port != all[j].Port {
			return all[i].Port < all[j].Port
		}
		if all[i].Proto != all[j].Proto {
			return all[i].Proto < all[j].Proto
		}
		return all[i].Addr < all[j].Addr
	})
	return all
}

// BindTest 尝试绑定 IPv4 端口，作为 /proc 解析之外的兜底检测。
func BindTest(proto string, port int) error {
	addr := ":" + strconv.Itoa(port)
	if proto == "udp" {
		c, err := net.ListenPacket("udp4", addr)
		if err != nil {
			return err
		}
		return c.Close()
	}
	l, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	return l.Close()
}
