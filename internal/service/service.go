package service

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	BinPath     = "/usr/local/bin/lport"
	systemdUnit = "/etc/systemd/system/lport.service"
	openrcInit  = "/etc/init.d/lport"
)

func systemdFile(configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=lport port forwarding manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s serve --config %s
Restart=on-failure
RestartSec=3
KillMode=mixed

[Install]
WantedBy=multi-user.target
`, BinPath, configPath)
}

func openrcFile(configPath string) string {
	return fmt.Sprintf(`#!/sbin/openrc-run
name="lport"
description="lport port forwarding manager"
command="%s"
command_args="serve --config %s"
supervisor=supervise-daemon
output_log="/var/log/lport.log"
error_log="/var/log/lport.log"

depend() {
	need net
	after firewall
}
`, BinPath, configPath)
}

// InitSystem 返回 systemd / openrc / 空字符串。
func InitSystem() string {
	if fi, err := os.Stat("/run/systemd/system"); err == nil && fi.IsDir() {
		return "systemd"
	}
	if _, err := os.Stat("/sbin/openrc-run"); err == nil {
		return "openrc"
	}
	return ""
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

// CopySelf 将当前程序复制到 BinPath（原子替换，运行中的服务不受影响）。
func CopySelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	if exe == BinPath {
		return nil
	}
	src, err := os.Open(exe)
	if err != nil {
		return err
	}
	defer src.Close()
	tmp := BinPath + ".tmp"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, BinPath)
}

// Install 复制二进制并注册、启动系统服务。
func Install(configPath string) error {
	init := InitSystem()
	if init == "" {
		return errors.New("未检测到 systemd 或 OpenRC，请手动运行: lport serve")
	}
	// 若服务已在运行，先停止以便覆盖二进制
	if Installed() {
		_ = Stop()
	}
	if err := CopySelf(); err != nil {
		return fmt.Errorf("复制程序到 %s 失败: %w", BinPath, err)
	}
	switch init {
	case "systemd":
		if err := os.WriteFile(systemdUnit, []byte(systemdFile(configPath)), 0o644); err != nil {
			return err
		}
		if err := run("systemctl", "daemon-reload"); err != nil {
			return err
		}
		return run("systemctl", "enable", "--now", "lport")
	default:
		if err := os.WriteFile(openrcInit, []byte(openrcFile(configPath)), 0o755); err != nil {
			return err
		}
		if err := run("rc-update", "add", "lport", "default"); err != nil {
			return err
		}
		return run("rc-service", "lport", "start")
	}
}

func Installed() bool {
	for _, p := range []string{systemdUnit, openrcInit} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// Running 判断已安装的服务是否正在运行。
func Running() bool {
	switch InitSystem() {
	case "systemd":
		return exec.Command("systemctl", "is-active", "--quiet", "lport").Run() == nil
	case "openrc":
		return exec.Command("rc-service", "lport", "status").Run() == nil
	}
	return false
}

func Start() error {
	switch InitSystem() {
	case "systemd":
		return run("systemctl", "start", "lport")
	case "openrc":
		return run("rc-service", "lport", "start")
	}
	return nil
}

func Stop() error {
	switch InitSystem() {
	case "systemd":
		return run("systemctl", "stop", "lport")
	case "openrc":
		return run("rc-service", "lport", "stop")
	}
	return nil
}

// Restart 重启已安装的服务（用于命令行修改配置后生效）。
func Restart() error {
	if !Installed() {
		return nil
	}
	switch InitSystem() {
	case "systemd":
		return run("systemctl", "restart", "lport")
	case "openrc":
		return run("rc-service", "lport", "restart")
	}
	return nil
}

// Uninstall 停止并移除服务；purge 时同时删除配置目录。
func Uninstall(configPath string, purge bool) error {
	switch InitSystem() {
	case "systemd":
		_ = run("systemctl", "disable", "--now", "lport")
		_ = os.Remove(systemdUnit)
		_ = run("systemctl", "daemon-reload")
	case "openrc":
		_ = run("rc-service", "lport", "stop")
		_ = run("rc-update", "del", "lport", "default")
		_ = os.Remove(openrcInit)
	}
	_ = os.Remove(BinPath)
	if purge {
		return os.RemoveAll(filepath.Dir(configPath))
	}
	return nil
}
