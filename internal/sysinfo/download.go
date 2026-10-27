package sysinfo

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"time"
)

// downloadDir 下载安装的工具存放目录。
const downloadDir = "/usr/local/bin"

// realmTargets GOARCH → realm 发布包的 Rust target。均为静态链接的 musl 版本，glibc 与 Alpine 通用；
// arm 统一使用 armv6 硬浮点版本，armv7 也可运行。
var realmTargets = map[string]string{
	"amd64": "x86_64-unknown-linux-musl",
	"arm64": "aarch64-unknown-linux-musl",
	"arm":   "arm-unknown-linux-musleabihf",
}

// downloadURL 返回当前架构下工具发布包的下载地址。
func downloadURL(t Tool) (string, error) {
	if t.Name != "realm" {
		return "", fmt.Errorf("%s 不支持下载安装", t.Name)
	}
	target, ok := realmTargets[runtime.GOARCH]
	if !ok {
		return "", fmt.Errorf("realm 未提供 %s 架构的预编译版本，请手动安装", runtime.GOARCH)
	}
	return "https://github.com/zhboner/realm/releases/latest/download/realm-" + target + ".tar.gz", nil
}

// downloadCommand 生成手动下载安装的 shell 命令，当前架构无预编译版本时返回空。
func downloadCommand(t Tool) string {
	url, err := downloadURL(t)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("curl -fsSL %s | tar -xz -C %s %s", url, downloadDir, t.Binary)
}

// maxBinarySize 解压出的可执行文件大小上限。
const maxBinarySize = 64 << 20

// download 下载 tar.gz 发布包并把其中名为 binary 的文件安装到 downloadDir，返回安装路径。
// 先写临时文件再改名，不会留下半个可执行文件，也能替换正在运行的旧版本。
func download(url, binary string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载失败: HTTP %d", resp.StatusCode)
	}
	return extract(resp.Body, binary, downloadDir)
}

// extract 从 tar.gz 流中取出名为 binary 的文件安装到 dir。先写临时文件，读完整个 gzip 流
// （完成 CRC 与长度校验）后才改名替换，损坏或截断的发布包不会覆盖已有版本。
func extract(r io.Reader, binary, dir string) (string, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return "", fmt.Errorf("解压失败: %w", err)
	}
	tr := tar.NewReader(gz)
	var h *tar.Header
	for {
		h, err = tr.Next()
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("发布包中没有 %s", binary)
		}
		if err != nil {
			return "", fmt.Errorf("解压失败: %w", err)
		}
		if h.Typeflag == tar.TypeReg && path.Base(h.Name) == binary {
			break
		}
	}
	if h.Size > maxBinarySize {
		return "", fmt.Errorf("%s 超过大小上限", binary)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "."+binary+"-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, err = io.Copy(f, tr)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("写入失败: %w", err)
	}
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return "", fmt.Errorf("解压失败: %w", err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, binary)
	if err := os.Rename(tmp, dst); err != nil {
		return "", err
	}
	return dst, nil
}
