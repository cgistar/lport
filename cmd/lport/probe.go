package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"sync"

	"golang.org/x/term"

	"lport/internal/config"
	"lport/internal/manager"
	"lport/internal/model"
	"lport/internal/probe"
)

var probeLabels = map[string]struct{ color, text string }{
	probe.StateOK:      {"32", "成功"},
	probe.StateFail:    {"31", "失败"},
	probe.StateUnknown: {"33", "无法确定"},
	probe.StateSkipped: {"90", "跳过"},
}

// cmdProbe 在命令行检测规则连通性，与 Web 界面「连通性」使用同一套逻辑；只读配置，不影响运行中的服务。
func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "配置文件路径")
	_ = fs.Parse(args)

	store, _, err := config.LoadNoSave(*cfgPath)
	if err != nil {
		return err
	}
	cfg := store.Get()
	rules, err := selectRules(cfg.Rules, fs.Args())
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		fmt.Println("没有转发规则")
		return nil
	}

	mgr := manager.New(store)
	results := make([]*manager.ProbeResult, len(rules))
	errs := make([]error, len(rules))
	var wg sync.WaitGroup
	for i, r := range rules {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			results[i], errs[i] = mgr.Probe(id)
		}(i, r.ID)
	}
	wg.Wait()

	color := term.IsTerminal(int(os.Stdout.Fd()))
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return "\033[" + code + "m" + s + "\033[0m"
	}
	failed := false
	for i, r := range rules {
		state := "启用"
		if !r.Enabled {
			state = "停用"
		}
		fmt.Printf("%s  %s :%d → %s  [%s, %s]\n", paint("1", r.Name), r.Proto, r.ListenPort, r.Target, cfg.Backend, state)
		if errs[i] != nil {
			fmt.Printf("  %s %v\n", paint("31", "●"), errs[i])
			failed = true
			continue
		}
		res := results[i]
		for _, group := range []struct {
			label string
			items []probe.Result
		}{{"本机", res.Local}, {"目标", res.Target}} {
			for _, it := range group.items {
				l := probeLabels[it.State]
				latency := ""
				if it.State == probe.StateOK || it.State == probe.StateFail {
					latency = strconv.FormatInt(it.LatencyMs, 10) + "ms"
				}
				fmt.Printf("  %s  %s %s %-3s %-22s %6s  %s\n", group.label, paint(l.color, "●"), padWidth(l.text, 8), it.Proto, it.Addr, latency, it.Message)
				if it.State == probe.StateFail {
					failed = true
				}
			}
		}
		if hint := probeHint(res); hint != "" {
			fmt.Printf("  %s\n", paint("90", "提示: "+hint))
		}
		fmt.Println()
	}
	if failed {
		return errors.New("存在检测失败的项")
	}
	return nil
}

func worst(items []probe.Result) string {
	s := probe.StateOK
	for _, it := range items {
		switch {
		case it.State == probe.StateFail:
			return probe.StateFail
		case it.State != probe.StateOK:
			s = it.State
		}
	}
	return s
}

func probeHint(res *manager.ProbeResult) string {
	local, target := worst(res.Local), worst(res.Target)
	switch {
	case local == probe.StateFail && target == probe.StateOK:
		return "目标可达但经本机转发失败：请检查规则状态、转发后端与防火墙"
	case target == probe.StateFail:
		return "本机无法直连目标：目标服务未启动、地址错误或目标防火墙拦截"
	case local == probe.StateOK && target == probe.StateOK:
		return "本机检测不经过 FORWARD 链；若外部仍无法访问，请检查云安全组与 FORWARD 防火墙规则"
	}
	return ""
}

// padWidth 按终端显示宽度（中文占 2 列）右补空格。
func padWidth(s string, w int) string {
	n := 0
	for _, r := range s {
		if r > 0x2E80 {
			n += 2
		} else {
			n++
		}
	}
	for ; n < w; n++ {
		s += " "
	}
	return s
}

// selectRules 按名称、ID 或监听端口筛选规则；未指定时返回全部。
func selectRules(rules []model.Rule, keys []string) ([]model.Rule, error) {
	if len(keys) == 0 {
		return rules, nil
	}
	var out []model.Rule
	for _, k := range keys {
		found := false
		for _, r := range rules {
			if r.Name == k || r.ID == k || strconv.Itoa(r.ListenPort) == k {
				out = append(out, r)
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("未找到规则: %s（可用名称、ID 或监听端口）", k)
		}
	}
	return out, nil
}
