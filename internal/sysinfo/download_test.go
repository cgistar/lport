package sysinfo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"README", "realm"} {
		body, ok := files[name]
		if !ok {
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestExtract(t *testing.T) {
	dir := t.TempDir()
	dst, err := extract(bytes.NewReader(tarGz(t, map[string]string{"README": "x", "realm": "new"})), "realm", dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "new" {
		t.Fatalf("content=%q", b)
	}
	if fi, _ := os.Stat(dst); fi.Mode()&0o111 == 0 {
		t.Error("应可执行")
	}

	if _, err := extract(bytes.NewReader(tarGz(t, map[string]string{"README": "x"})), "realm", dir); err == nil {
		t.Error("缺少文件时应失败")
	}
}

// gzip 尾部（CRC）损坏时，即使 realm 已完整解出也不能覆盖已有版本，且不留下临时文件
func TestExtractCorruptTrailer(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "realm")
	if err := os.WriteFile(old, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	data := tarGz(t, map[string]string{"realm": "new"})
	data[len(data)-8] ^= 0xff // 破坏 CRC32
	if _, err := extract(bytes.NewReader(data), "realm", dir); err == nil {
		t.Fatal("CRC 错误时应失败")
	}
	if b, _ := os.ReadFile(old); string(b) != "old" {
		t.Errorf("已有版本被覆盖: %q", b)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("残留临时文件: %v", entries)
	}
}
