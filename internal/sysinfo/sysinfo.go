package sysinfo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Tool 描述一个转发依赖工具。
type Tool struct {
	Name      string `json:"name"`    // socat | realm | iptables | nftables
	Binary    string `json:"binary"`  // 可执行文件名
	Package   string `json:"package"` // 包名；为空表示不走包管理器，从发布页下载
	Installed bool   `json:"installed"`
	Path      string `json:"path"`
	Version   string `json:"version"`
}

type Info struct {
	OSID           string `json:"os_id"`
	OSLike         string `json:"os_like"`
	OSName         string `json:"os_name"`
	Family         string `json:"family"` // alpine | debian | rhel | unknown
	PackageManager string `json:"package_manager"`
	Kernel         string `json:"kernel"`
	IsRoot         bool   `json:"is_root"`
	IPForward      bool   `json:"ip_forward"`
	InitSystem     string `json:"init_system"`
	Tools          []Tool `json:"tools"`
	InstallCommand string `json:"install_command"` // 安装缺失工具的命令，全部已装时为空
}

var toolDefs = []Tool{
	{Name: "socat", Binary: "socat", Package: "socat"},
	{Name: "realm", Binary: "realm"},
	{Name: "iptables", Binary: "iptables", Package: "iptables"},
	{Name: "nftables", Binary: "nft", Package: "nftables"},
}

// ToolBinary 返回工具对应的可执行文件名。
func ToolBinary(name string) string {
	if t, ok := toolDef(name); ok {
		return t.Binary
	}
	return name
}

func toolDef(name string) (Tool, bool) {
	for _, t := range toolDefs {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// ToolPath 查找工具的可执行文件。除 PATH 外还查找下载安装目录，
// 服务管理器提供的 PATH 可能不含 /usr/local/bin。
func ToolPath(name string) (string, error) {
	bin := ToolBinary(name)
	p, err := exec.LookPath(bin)
	if err == nil {
		return p, nil
	}
	if p := filepath.Join(downloadDir, bin); isExecutable(p) {
		return p, nil
	}
	return "", err
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0
}

// ParseOSRelease 解析 /etc/os-release 内容。
func ParseOSRelease(content string) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		m[k] = strings.Trim(v, `"'`)
	}
	return m
}

// Family 根据 ID / ID_LIKE 判断发行版家族。
func Family(id, like string) string {
	for _, f := range append([]string{id}, strings.Fields(like)...) {
		switch f {
		case "alpine":
			return "alpine"
		case "debian", "ubuntu", "linuxmint", "raspbian", "kali":
			return "debian"
		case "centos", "rhel", "fedora", "rocky", "almalinux", "ol", "amzn", "anolis", "openEuler", "opencloudos":
			return "rhel"
		}
	}
	return "unknown"
}

// PackageManager 返回包管理器名称；lookPath 便于测试注入。
func PackageManager(family string, lookPath func(string) (string, error)) string {
	switch family {
	case "alpine":
		return "apk"
	case "debian":
		return "apt"
	case "rhel":
		if _, err := lookPath("dnf"); err == nil {
			return "dnf"
		}
		return "yum"
	}
	for _, pm := range []string{"apk", "apt-get", "dnf", "yum"} {
		if _, err := lookPath(pm); err == nil {
			if pm == "apt-get" {
				return "apt"
			}
			return pm
		}
	}
	return ""
}

// InstallCommand 生成安装命令（shell 字符串）。
func InstallCommand(pm string, pkgs []string) string {
	if len(pkgs) == 0 || pm == "" {
		return ""
	}
	p := strings.Join(pkgs, " ")
	switch pm {
	case "apk":
		return "apk add --no-cache " + p
	case "apt":
		return "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y " + p
	case "dnf":
		return "dnf install -y " + p
	case "yum":
		return "yum install -y " + p
	}
	return ""
}

func toolVersion(path, name string) string {
	args := []string{"--version"}
	switch name {
	case "socat":
		args = []string{"-V"}
	case "realm":
		args = []string{"-v"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if name == "socat" && !strings.Contains(line, "version") {
			continue
		}
		return line
	}
	return ""
}

func detectInit() string {
	if fi, err := os.Stat("/run/systemd/system"); err == nil && fi.IsDir() {
		return "systemd"
	}
	if _, err := exec.LookPath("openrc-run"); err == nil {
		return "openrc"
	}
	if _, err := os.Stat("/sbin/openrc-run"); err == nil {
		return "openrc"
	}
	return "unknown"
}

// IPForwardEnabled 读取 net.ipv4.ip_forward。
func IPForwardEnabled() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

const sysctlConf = "/etc/sysctl.d/99-lport.conf"

// EnableIPForward 开启并持久化 ip_forward。运行值与持久化分别处理：运行值已是 1 时也补写持久化配置；
// 持久化失败只记录日志，不影响本次转发（lport 启动时会重新开启运行值）。
func EnableIPForward() error {
	if !IPForwardEnabled() {
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
			return fmt.Errorf("开启 ip_forward 失败: %w", err)
		}
	}
	const want = "net.ipv4.ip_forward = 1\n"
	if b, err := os.ReadFile(sysctlConf); err == nil && string(b) == want {
		return nil
	}
	if fi, err := os.Stat("/etc/sysctl.d"); err != nil || !fi.IsDir() {
		return nil
	}
	if err := os.WriteFile(sysctlConf, []byte(want), 0o644); err != nil {
		log.Printf("持久化 ip_forward 失败（重启后需由 lport 重新开启）: %v", err)
	}
	return nil
}

// Detect 采集系统信息。
func Detect() Info {
	info := Info{IsRoot: os.Geteuid() == 0, IPForward: IPForwardEnabled(), InitSystem: detectInit()}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		m := ParseOSRelease(string(b))
		info.OSID, info.OSLike, info.OSName = m["ID"], m["ID_LIKE"], m["PRETTY_NAME"]
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = strings.TrimSpace(string(b))
	}
	info.Family = Family(info.OSID, info.OSLike)
	info.PackageManager = PackageManager(info.Family, exec.LookPath)
	var missing []string
	for _, t := range toolDefs {
		if p, err := ToolPath(t.Name); err == nil {
			t.Installed, t.Path, t.Version = true, p, toolVersion(p, t.Name)
		} else {
			missing = append(missing, t.Name)
		}
		info.Tools = append(info.Tools, t)
	}
	info.InstallCommand = ToolsInstallCommand(info.PackageManager, missing)
	return info
}

// ToolsInstallCommand 生成安装若干工具的完整命令：包管理器安装的合并为一条，需下载的各自追加。
// 包管理器未知时只返回下载部分。
func ToolsInstallCommand(pm string, tools []string) string {
	var pkgs, parts []string
	for _, name := range tools {
		if t, ok := toolDef(name); ok && t.Package != "" {
			pkgs = append(pkgs, t.Package)
		}
	}
	if c := InstallCommand(pm, pkgs); c != "" {
		parts = append(parts, c)
	}
	for _, name := range tools {
		if t, ok := toolDef(name); ok && t.Package == "" {
			if c := downloadCommand(t); c != "" {
				parts = append(parts, c)
			}
		}
	}
	return strings.Join(parts, " && ")
}

// ToolInstalled 判断某个工具是否可用。
func ToolInstalled(name string) bool {
	_, err := ToolPath(name)
	return err == nil
}

var installMu sync.Mutex

// Install 安装指定工具，返回命令输出。同一时间只允许一个安装任务。
func Install(tools []string) (string, string, error) {
	if !installMu.TryLock() {
		return "", "", errors.New("已有安装任务正在进行，请稍后再试")
	}
	defer installMu.Unlock()
	if os.Geteuid() != 0 {
		return "", "", errors.New("需要 root 权限才能安装软件包")
	}
	var pkgs []string
	var downloads []Tool
	for _, name := range tools {
		t, ok := toolDef(name)
		switch {
		case !ok:
			return "", "", fmt.Errorf("未知工具: %s", name)
		case t.Package == "":
			downloads = append(downloads, t)
		default:
			pkgs = append(pkgs, t.Package)
		}
	}
	var cmds []string
	var out strings.Builder
	if len(pkgs) > 0 {
		cmdline := InstallCommand(Detect().PackageManager, pkgs)
		if cmdline == "" {
			return "", "", errors.New("无法识别当前系统的包管理器，请手动安装")
		}
		cmds = append(cmds, cmdline)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", cmdline)
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		b, err := cmd.CombinedOutput()
		out.Write(b)
		if err != nil {
			return cmdline, out.String(), fmt.Errorf("安装失败: %w", err)
		}
	}
	for _, t := range downloads {
		url, err := downloadURL(t)
		if err != nil {
			return strings.Join(cmds, " && "), out.String(), err
		}
		cmds = append(cmds, "download "+url)
		fmt.Fprintf(&out, "downloading %s\n", url)
		dst, err := download(url, t.Binary)
		if err != nil {
			return strings.Join(cmds, " && "), out.String(), fmt.Errorf("安装失败: %w", err)
		}
		fmt.Fprintf(&out, "installed to %s\n", dst)
	}
	return strings.Join(cmds, " && "), out.String(), nil
}
