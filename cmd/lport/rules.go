package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"syscall"
	"time"

	"lport/internal/api"
	"lport/internal/config"
	"lport/internal/manager"
	"lport/internal/model"
	"lport/internal/service"
)

// ruleOps 规则增删查：服务运行中时经控制套接字由服务执行（立即生效），否则直接修改配置文件。
type ruleOps interface {
	List() ([]manager.RuleView, error)
	Create(r model.Rule) (model.Rule, error)
	Update(id string, r model.Rule) (model.Rule, error)
	Delete(id string) error
	Online() bool
}

// openRules 优先连接运行中的服务；连接不上且服务确实未运行时退回离线模式。
func openRules(cfgPath string) (ruleOps, error) {
	sock := api.SocketPath(cfgPath)
	c := &ctlClient{http: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}},
	}}
	_, err := os.Stat(sock)
	if err == nil {
		_, err = c.List()
	}
	switch {
	case err == nil:
		return c, nil
	case errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED):
	case errors.Is(err, syscall.EACCES):
		return nil, errors.New("需要 root 权限运行")
	default:
		return nil, err
	}
	if service.Running() {
		return nil, fmt.Errorf("服务正在运行，但无法连接控制套接字 %s，请重启服务（systemctl restart lport）后重试", sock)
	}
	store, err := loadConfig(cfgPath, "")
	if err != nil {
		return nil, err
	}
	return offlineRules{store: store, mgr: manager.NewOffline(store)}, nil
}

type ctlClient struct{ http *http.Client }

func (c *ctlClient) Online() bool { return true }

func (c *ctlClient) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://lport"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("服务返回 %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *ctlClient) List() ([]manager.RuleView, error) {
	var rs []manager.RuleView
	return rs, c.do(http.MethodGet, "/rules", nil, &rs)
}

func (c *ctlClient) Create(r model.Rule) (model.Rule, error) {
	var out model.Rule
	return out, c.do(http.MethodPost, "/rules", r, &out)
}

func (c *ctlClient) Update(id string, r model.Rule) (model.Rule, error) {
	var out model.Rule
	return out, c.do(http.MethodPut, "/rules/"+url.PathEscape(id), r, &out)
}

func (c *ctlClient) Delete(id string) error {
	return c.do(http.MethodDelete, "/rules/"+url.PathEscape(id), nil, nil)
}

type offlineRules struct {
	store *config.Store
	mgr   *manager.Manager
}

func (o offlineRules) Online() bool { return false }

func (o offlineRules) List() ([]manager.RuleView, error) {
	var out []manager.RuleView
	for _, r := range o.store.Get().Rules {
		out = append(out, manager.RuleView{Rule: r})
	}
	return out, nil
}

func (o offlineRules) Create(r model.Rule) (model.Rule, error) { return o.mgr.Create(r) }
func (o offlineRules) Update(id string, r model.Rule) (model.Rule, error) {
	return o.mgr.Update(id, r)
}
func (o offlineRules) Delete(id string) error { return o.mgr.Delete(id) }

// parseInterspersed 解析参数，允许选项出现在位置参数之后（如 lport add 8080 1.2.3.4:80 --proto udp）。
func parseInterspersed(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		_ = fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			return pos
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

var stateText = map[string]string{
	"running": "运行中",
	"applied": "已生效",
	"stopped": "已停用",
	"error":   "错误",
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "配置文件路径")
	_ = fs.Parse(args)
	ops, err := openRules(*cfgPath)
	if err != nil {
		return err
	}
	rules, err := ops.List()
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		fmt.Println("没有转发规则")
		return nil
	}
	fmt.Printf("%-8s  %s  %s %s %s %s\n", "ID", padWidth("名称", 16), padWidth("协议", 5), padWidth("端口", 6), padWidth("目标", 26), "状态")
	for _, r := range rules {
		state := "未启用"
		if r.Enabled {
			state = "已启用"
		}
		if ops.Online() {
			state = r.Status.State
			if t, ok := stateText[state]; ok {
				state = t
			}
			if r.Status.Message != "" {
				state += ": " + r.Status.Message
			}
		}
		fmt.Printf("%-8s  %s  %-5s %-6d %-26s %s\n", r.ID, padWidth(r.Name, 16), r.Proto, r.ListenPort, r.Target, state)
	}
	if !ops.Online() {
		fmt.Println("\n服务未运行，以上为配置文件中的规则")
	}
	return nil
}

func cmdAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "配置文件路径")
	proto := fs.String("proto", model.ProtoTCP, "协议 tcp | udp | both")
	name := fs.String("name", "", "规则名称（默认 rule-<端口>）")
	remark := fs.String("remark", "", "备注")
	disabled := fs.Bool("disabled", false, "添加但不启用")
	pos := parseInterspersed(fs, args)
	if len(pos) != 2 {
		return errors.New("用法: lport add [--proto tcp|udp|both] [--name NAME] 监听端口 目标地址:端口")
	}
	port, err := strconv.Atoi(pos[0])
	if err != nil {
		return fmt.Errorf("监听端口无效: %s", pos[0])
	}
	ops, err := openRules(*cfgPath)
	if err != nil {
		return err
	}
	r, err := ops.Create(model.Rule{
		Name: *name, Proto: *proto, ListenPort: port, Target: pos[1], Remark: *remark, Enabled: !*disabled,
	})
	if err != nil {
		return err
	}
	fmt.Printf("已添加规则 %s (%s): %s :%d → %s\n", r.Name, r.ID, r.Proto, r.ListenPort, r.Target)
	if !ops.Online() {
		fmt.Println("服务未运行，规则已写入配置，启动服务后生效")
	}
	return nil
}

func cmdEdit(args []string) error {
	fs := flag.NewFlagSet("edit", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "配置文件路径")
	port := fs.Int("port", 0, "新的监听端口")
	target := fs.String("target", "", "新的目标地址:端口")
	proto := fs.String("proto", "", "协议 tcp | udp | both")
	name := fs.String("name", "", "规则名称")
	remark := fs.String("remark", "", "备注")
	enable := fs.Bool("enable", false, "启用规则")
	disable := fs.Bool("disable", false, "停用规则")
	keys := parseInterspersed(fs, args)
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	delete(set, "config")
	if len(keys) != 1 || len(set) == 0 {
		return errors.New("用法: lport edit [--port PORT] [--target HOST:PORT] [--proto tcp|udp|both] [--name NAME] [--remark TEXT] [--enable|--disable] 规则名|ID|端口")
	}
	if *enable && *disable {
		return errors.New("--enable 与 --disable 不能同时使用")
	}
	ops, err := openRules(*cfgPath)
	if err != nil {
		return err
	}
	views, err := ops.List()
	if err != nil {
		return err
	}
	rules := make([]model.Rule, len(views))
	for i, v := range views {
		rules[i] = v.Rule
	}
	selected, err := selectRules(rules, keys)
	if err != nil {
		return err
	}
	if len(selected) > 1 {
		return fmt.Errorf("%s 匹配到 %d 条规则，请改用 ID 指定（lport list 查看）", keys[0], len(selected))
	}
	r := selected[0]
	if set["port"] {
		// 沿用默认名称的规则随端口一起改名
		if !set["name"] && r.Name == "rule-"+strconv.Itoa(r.ListenPort) {
			r.Name = "rule-" + strconv.Itoa(*port)
		}
		r.ListenPort = *port
	}
	if set["target"] {
		r.Target = *target
	}
	if set["proto"] {
		r.Proto = *proto
	}
	if set["name"] {
		r.Name = *name
	}
	if set["remark"] {
		r.Remark = *remark
	}
	if *enable {
		r.Enabled = true
	}
	if *disable {
		r.Enabled = false
	}
	r, err = ops.Update(r.ID, r)
	if err != nil {
		return err
	}
	fmt.Printf("已修改规则 %s (%s): %s :%d → %s\n", r.Name, r.ID, r.Proto, r.ListenPort, r.Target)
	if !ops.Online() {
		fmt.Println("服务未运行，已写入配置，启动服务后生效")
	}
	return nil
}

func cmdRemove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "配置文件路径")
	keys := parseInterspersed(fs, args)
	if len(keys) == 0 {
		return errors.New("用法: lport remove 规则名|ID|端口 ...")
	}
	ops, err := openRules(*cfgPath)
	if err != nil {
		return err
	}
	views, err := ops.List()
	if err != nil {
		return err
	}
	rules := make([]model.Rule, len(views))
	for i, v := range views {
		rules[i] = v.Rule
	}
	selected, err := selectRules(rules, keys)
	if err != nil {
		return err
	}
	removed := map[string]bool{}
	for _, r := range selected {
		if removed[r.ID] {
			continue
		}
		if err := ops.Delete(r.ID); err != nil {
			return fmt.Errorf("删除规则 %s 失败: %w", r.Name, err)
		}
		removed[r.ID] = true
		fmt.Printf("已删除规则 %s (%s): %s :%d → %s\n", r.Name, r.ID, r.Proto, r.ListenPort, r.Target)
	}
	if !ops.Online() {
		fmt.Println("服务未运行，已从配置中删除")
	}
	return nil
}
