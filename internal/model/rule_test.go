package model

import "testing"

func TestValidateNormalizesTarget(t *testing.T) {
	cases := []struct{ in, want string }{
		{"[::ffff:192.0.2.1]:443", "192.0.2.1:443"}, // IPv4 映射地址统一为点分十进制
		{" 10.0.0.5:80 ", "10.0.0.5:80"},
		{"example.com:80", "example.com:80"},
	}
	for _, c := range cases {
		r := Rule{Proto: "tcp", ListenPort: 8080, Target: c.in}
		if err := r.Validate(BackendNftables); err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if r.Target != c.want {
			t.Errorf("%q: target = %q, want %q", c.in, r.Target, c.want)
		}
	}
	r := Rule{Proto: "tcp", ListenPort: 8080, Target: "[2001:db8::1]:80"}
	if r.Validate(BackendNftables) == nil {
		t.Error("IPv6 目标应被拒绝")
	}
}
