package backend

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"lport/internal/model"
)

// 便于测试替换
var lookupIPv4 = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip4", host)
}

// ResolveHost 将域名解析为 IPv4；prefer 仍在解析结果中时优先保留，避免 DNS 轮询导致规则反复变化。
func ResolveHost(host, prefer string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := lookupIPv4(ctx, host)
	if err != nil {
		return "", fmt.Errorf("解析 %s 失败: %v", host, err)
	}
	var first string
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil || v4.IsLoopback() || v4.IsUnspecified() {
			continue
		}
		s := v4.String()
		if s == prefer {
			return s, nil
		}
		if first == "" {
			first = s
		}
	}
	if first == "" {
		return "", fmt.Errorf("%s 没有可用的 IPv4 地址（不能是回环地址）", host)
	}
	return first, nil
}

// kernelState 内核后端的公共状态：域名解析结果与最近一次应用的规则。
type kernelState struct {
	rules []model.Rule      // 最近一次应用的原始规则
	ips   map[string]string // rule id → 域名解析出的 IPv4
	errs  map[string]string // rule id → 解析错误
}

// resolveRules 把启用规则中的域名目标替换为 IP；解析失败的规则被跳过并记录错误。
func resolveRules(rules []model.Rule, prev map[string]string) (out []model.Rule, ips, errs map[string]string) {
	ips, errs = map[string]string{}, map[string]string{}
	type result struct {
		ip  string
		err error
	}
	// 同一域名只解析一次，不同域名并发解析
	hosts := map[string]*result{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, r := range enabled(rules) {
		host, _, _ := r.TargetHostPort()
		if net.ParseIP(host) != nil || hosts[host] != nil {
			continue
		}
		res := &result{}
		hosts[host] = res
		wg.Add(1)
		go func(host, prefer string) {
			defer wg.Done()
			ip, err := ResolveHost(host, prefer)
			mu.Lock()
			res.ip, res.err = ip, err
			mu.Unlock()
		}(host, prev[r.ID])
	}
	wg.Wait()
	for _, r := range enabled(rules) {
		host, port, _ := r.TargetHostPort()
		if res, ok := hosts[host]; ok {
			if res.err != nil {
				errs[r.ID] = res.err.Error()
				continue
			}
			ips[r.ID] = res.ip
			r.Target = net.JoinHostPort(res.ip, strconv.Itoa(port))
		}
		out = append(out, r)
	}
	return out, ips, errs
}

func (k *kernelState) status() map[string]RuleStatus {
	m := map[string]RuleStatus{}
	for _, r := range k.rules {
		switch {
		case !r.Enabled:
			m[r.ID] = RuleStatus{State: "stopped"}
		case k.errs[r.ID] != "":
			m[r.ID] = RuleStatus{State: "error", Message: k.errs[r.ID]}
		case k.ips[r.ID] != "":
			host, _, _ := r.TargetHostPort()
			m[r.ID] = RuleStatus{State: "applied", Message: host + " → " + k.ips[r.ID]}
		default:
			m[r.ID] = RuleStatus{State: "applied"}
		}
	}
	return m
}
