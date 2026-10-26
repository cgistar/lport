package sysinfo

import (
	"errors"
	"testing"
)

func TestFamilyAndPM(t *testing.T) {
	has := func(names ...string) func(string) (string, error) {
		return func(n string) (string, error) {
			for _, x := range names {
				if x == n {
					return "/usr/bin/" + n, nil
				}
			}
			return "", errors.New("not found")
		}
	}
	cases := []struct {
		osRelease string
		family    string
		pm        string
		look      func(string) (string, error)
	}{
		{"ID=alpine\nVERSION_ID=3.20.0", "alpine", "apk", has()},
		{"ID=debian\nVERSION_ID=\"12\"", "debian", "apt", has()},
		{"ID=ubuntu\nID_LIKE=debian", "debian", "apt", has()},
		{"ID=\"centos\"\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"7\"", "rhel", "yum", has("yum")},
		{"ID=\"centos\"\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"9\"", "rhel", "dnf", has("dnf", "yum")},
		{"ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"", "rhel", "dnf", has("dnf")},
		{"ID=weird", "unknown", "apk", has("apk")},
	}
	for _, c := range cases {
		m := ParseOSRelease(c.osRelease)
		f := Family(m["ID"], m["ID_LIKE"])
		if f != c.family {
			t.Errorf("%q: family=%s want %s", c.osRelease, f, c.family)
		}
		if pm := PackageManager(f, c.look); pm != c.pm {
			t.Errorf("%q: pm=%s want %s", c.osRelease, pm, c.pm)
		}
	}
}

func TestInstallCommand(t *testing.T) {
	if got := InstallCommand("apk", []string{"socat", "nftables"}); got != "apk add --no-cache socat nftables" {
		t.Error(got)
	}
	if got := InstallCommand("apt", []string{"socat"}); got != "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y socat" {
		t.Error(got)
	}
	if got := InstallCommand("dnf", nil); got != "" {
		t.Error(got)
	}
}
