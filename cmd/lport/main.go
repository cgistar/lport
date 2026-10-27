package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lport/internal/api"
	"lport/internal/auth"
	"lport/internal/config"
	"lport/internal/manager"
	"lport/internal/model"
	"lport/internal/portcheck"
	"lport/internal/service"
	"lport/internal/sysinfo"
	"lport/web"
)

var version = "dev"

const usage = `lport - 端口转发管理工具 (%s)

用法:
  lport serve     [--config PATH] [--listen ADDR]   启动 Web 管理服务
  lport install   [--config PATH] [--listen ADDR] [--backend NAME] [-y]
                                                    安装程序与系统服务（交互式；-y 或无终端时使用默认值）
  lport uninstall [--config PATH] [--purge]         卸载系统服务，--purge 同时删除配置
  lport start | stop | restart                      启动 / 停止 / 重启系统服务
  lport passwd    [--config PATH] [新密码]          重置管理员密码（不填则随机生成）
  lport list      [--config PATH]                   列出转发规则
  lport add       [--config PATH] [--proto tcp|udp|both] [--name NAME] [--remark TEXT] [--disabled]
                  监听端口 目标地址:端口             添加转发规则（服务运行中时立即生效）
  lport edit      [--config PATH] [--port PORT] [--target HOST:PORT] [--proto tcp|udp|both]
                  [--name NAME] [--remark TEXT] [--enable|--disable]
                  规则名|ID|端口                     修改转发规则（只改指定的项）
  lport remove    [--config PATH] 规则名|ID|端口 ...  删除转发规则
  lport probe     [--config PATH] [规则名|ID|端口 ...] 检测规则连通性（本机经转发 / 直连目标）
  lport detect                                      检测系统环境与依赖工具
  lport version

默认配置文件: %s
`

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version, config.DefaultPath)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "install":
		err = cmdInstall(args)
	case "uninstall":
		err = cmdUninstall(args)
	case "start", "stop", "restart":
		err = cmdService(cmd)
	case "passwd":
		err = cmdPasswd(args)
	case "list", "ls":
		err = cmdList(args)
	case "add":
		err = cmdAdd(args)
	case "edit":
		err = cmdEdit(args)
	case "remove", "rm":
		err = cmdRemove(args)
	case "probe":
		err = cmdProbe(args)
	case "detect":
		cmdDetect()
	case "version", "-v", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Printf(usage, version, config.DefaultPath)
	default:
		fmt.Fprintf(os.Stderr, usage, version, config.DefaultPath)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("需要 root 权限运行")
	}
	return nil
}

// loadConfig 加载配置，并在 listen 参数非空时写入配置。
func loadConfig(path, listen string) (*config.Store, error) {
	store, res, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if listen != "" && listen != store.Get().Listen {
		if err := store.Update(func(c *config.Config) error { c.Listen = listen; return nil }); err != nil {
			return nil, err
		}
	}
	if res.GeneratedPassword != "" {
		fmt.Printf("\n========================================\n 已生成管理员账号\n 用户名: %s\n 密码:   %s\n 请登录后尽快修改密码\n========================================\n\n",
			store.Get().Admin.Username, res.GeneratedPassword)
	}
	return store, nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "配置文件路径")
	listen := fs.String("listen", "", "监听地址，如 0.0.0.0:8080（会写入配置）")
	_ = fs.Parse(args)
	if os.Geteuid() != 0 {
		log.Printf("警告: 当前不是 root，iptables/nftables 后端、低端口和软件安装将不可用")
	}
	store, err := loadConfig(*cfgPath, *listen)
	if err != nil {
		return err
	}
	mgr := manager.New(store)
	mgr.Start()
	defer mgr.Stop()

	apiSrv := api.New(store, mgr, auth.New(store), web.Dist())
	srv := &http.Server{
		Addr:              store.Get().Listen,
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctl, err := listenCtl(api.SocketPath(store.Path()))
	if err != nil {
		log.Printf("警告: 控制套接字启动失败，lport add/remove 将无法连接运行中的服务: %v", err)
	} else {
		ctlSrv := &http.Server{Handler: apiSrv.LocalHandler(), ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = ctlSrv.Serve(ctl) }()
		defer ctlSrv.Close()
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("lport %s 已启动: http://%s  (配置: %s, 后端: %s)", version, srv.Addr, store.Path(), mgr.BackendName())
		errCh <- srv.ListenAndServe()
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Printf("收到信号 %v，正在停止并清理转发规则", s)
	case err := <-errCh:
		return fmt.Errorf("Web 服务启动失败: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	return nil
}

// listenCtl 监听控制套接字，先移除上次异常退出遗留的文件；套接字关闭时文件会被自动删除。
func listenCtl(path string) (net.Listener, error) {
	if len(path) > 100 {
		return nil, fmt.Errorf("路径过长（Unix 套接字路径上限约 100 字节）: %s", path)
	}
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "配置文件路径")
	listen := fs.String("listen", "", "监听地址，如 0.0.0.0:8080")
	backendFlag := fs.String("backend", "", "转发工具 nftables | iptables | socat | realm（默认交互选择）")
	yes := fs.Bool("y", false, "非交互模式，全部使用默认值")
	_ = fs.Parse(args)
	if err := requireRoot(); err != nil {
		return err
	}
	p := newPrompter(!*yes)

	// 问答结束前不写文件，中途退出不会留下用户不知道的随机密码
	store, res, err := config.LoadNoSave(*cfgPath)
	if err != nil {
		return err
	}

	// 1. 管理员密码：配置中没有密码时询问
	generated, pwHash := res.GeneratedPassword, ""
	if generated != "" && p.interactive {
		pw, err := p.password()
		if err != nil {
			return err
		}
		if pw != "" {
			h, err := config.HashPassword(pw)
			if err != nil {
				return err
			}
			pwHash = h
			generated = ""
		}
	}

	// 2. 转发工具：命令行指定 > 交互选择（仅配置中未指定时）> 自动选择
	backend := store.Get().Backend
	switch {
	case *backendFlag != "":
		backend = *backendFlag
		if !model.ValidBackend(backend) {
			return fmt.Errorf("--backend 必须是 nftables / iptables / socat / realm")
		}
	case res.BackendAuto && p.interactive:
		backend = p.chooseBackend(store.Get().Rules)
	case res.BackendAuto && !sysinfo.ToolInstalled(backend) && rulesCompatible(store.Get().Rules, model.BackendNftables) == nil:
		// 非交互且没有任何可用工具时，使用默认的 nftables 并自动安装
		backend = model.BackendNftables
	}
	if err := rulesCompatible(store.Get().Rules, backend); err != nil {
		return err
	}
	if err := store.Update(func(c *config.Config) error {
		c.Backend = backend
		if pwHash != "" {
			c.Admin.PasswordHash = pwHash
		}
		if *listen != "" {
			c.Listen = *listen
		}
		return nil
	}); err != nil {
		return err
	}
	ensureTool(p, backend)

	// 3. 系统服务：首次安装时询问；已安装则直接升级并重启
	installSvc := true
	switch {
	case service.InitSystem() == "":
		installSvc = false
		fmt.Println("未检测到 systemd 或 OpenRC，跳过服务注册")
	case !service.Installed():
		installSvc = p.confirm(fmt.Sprintf("是否安装为系统服务（%s）并开机自启?", service.InitSystem()), true)
	}
	if installSvc {
		if err := service.Install(*cfgPath); err != nil {
			return err
		}
	} else if err := service.CopySelf(); err != nil {
		return fmt.Errorf("复制程序到 %s 失败: %w", service.BinPath, err)
	}

	c := store.Get()
	fmt.Printf("\n安装完成\n  程序:     %s\n  配置:     %s\n  管理地址: http://%s\n  转发工具: %s\n  用户名:   %s\n",
		service.BinPath, *cfgPath, c.Listen, c.Backend, c.Admin.Username)
	if generated != "" {
		fmt.Printf("  密码:     %s（随机生成，请登录后修改，或执行 lport passwd 重置）\n", generated)
	}
	if !installSvc {
		fmt.Printf("  未注册服务，手动启动: %s serve --config %s\n", service.BinPath, *cfgPath)
	}
	return nil
}

// ensureTool 检查后端依赖的工具，缺失时询问（非交互模式直接）安装。
func ensureTool(p *prompter, backend string) {
	if sysinfo.ToolInstalled(backend) {
		return
	}
	info := sysinfo.Detect()
	cmdline := sysinfo.ToolsInstallCommand(info.PackageManager, []string{backend})
	if cmdline == "" {
		fmt.Printf("警告: %s 未安装且无法识别包管理器，请手动安装后执行 systemctl restart lport\n", backend)
		return
	}
	if !p.confirm(fmt.Sprintf("%s 未安装，是否现在安装（%s）?", backend, cmdline), true) {
		fmt.Printf("警告: %s 未安装，转发规则不会生效。可稍后在 Web 界面安装，或执行: %s\n", backend, cmdline)
		return
	}
	fmt.Println("正在安装", backend, "...")
	if _, out, err := sysinfo.Install([]string{backend}); err != nil {
		fmt.Print(out)
		fmt.Printf("警告: %v，可稍后在 Web 界面重试\n", err)
	}
}

func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "配置文件路径")
	purge := fs.Bool("purge", false, "同时删除配置目录")
	_ = fs.Parse(args)
	if err := requireRoot(); err != nil {
		return err
	}
	if err := service.Uninstall(*cfgPath, *purge); err != nil {
		return err
	}
	fmt.Println("已卸载")
	return nil
}

// cmdService 通过 systemd / OpenRC 启动、停止或重启已安装的服务。
func cmdService(action string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if service.InitSystem() == "" {
		return errors.New("未检测到 systemd 或 OpenRC")
	}
	if !service.Installed() {
		return errors.New("服务未安装，请先执行 lport install")
	}
	var err error
	switch action {
	case "start":
		err = service.Start()
	case "stop":
		err = service.Stop()
	case "restart":
		err = service.Restart()
	}
	if err != nil {
		return err
	}
	if service.Running() {
		fmt.Println("服务运行中")
	} else {
		fmt.Println("服务已停止")
	}
	return nil
}

func cmdPasswd(args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "配置文件路径")
	_ = fs.Parse(args)
	pw := fs.Arg(0)
	if pw == "" {
		pw = config.RandomPassword()
	}
	if len(pw) < 6 {
		return errors.New("密码至少 6 位")
	}
	store, err := loadConfig(*cfgPath, "")
	if err != nil {
		return err
	}
	h, err := config.HashPassword(pw)
	if err != nil {
		return err
	}
	if err := store.Update(func(c *config.Config) error { c.Admin.PasswordHash = h; return nil }); err != nil {
		return err
	}
	fmt.Printf("用户名: %s\n新密码: %s\n", store.Get().Admin.Username, pw)
	if service.Installed() {
		fmt.Println("正在重启服务使密码生效...")
		return service.Restart()
	}
	return nil
}

func cmdDetect() {
	info := sysinfo.Detect()
	fmt.Printf("系统:       %s (%s, 家族: %s)\n", info.OSName, info.OSID, info.Family)
	fmt.Printf("内核:       %s\n", info.Kernel)
	fmt.Printf("包管理器:   %s\n", info.PackageManager)
	fmt.Printf("init 系统:  %s\n", info.InitSystem)
	fmt.Printf("root:       %v\n", info.IsRoot)
	fmt.Printf("ip_forward: %v\n", info.IPForward)
	fmt.Println("工具:")
	for _, t := range info.Tools {
		if t.Installed {
			fmt.Printf("  [✓] %-9s %s  %s\n", t.Name, t.Path, t.Version)
		} else {
			fmt.Printf("  [✗] %-9s 未安装\n", t.Name)
		}
	}
	if info.InstallCommand != "" {
		fmt.Printf("安装缺失工具: %s\n", info.InstallCommand)
	}
	ls := portcheck.Listeners(false)
	fmt.Printf("系统已占用端口: %d 个（lport serve 后可在 Web 界面查看详情）\n", len(ls))
}
