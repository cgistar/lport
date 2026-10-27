package backend

import (
	"net"
	"strconv"

	"lport/internal/model"
)

// NewRealm 每条规则每个协议一个 realm 进程。realm 单进程虽可同时转发 tcp/udp，但某个协议绑定失败时
// 只会结束对应任务、进程继续运行，拆开后任一协议失败都能被监管发现。
func NewRealm() *Process { return newProcess(model.BackendRealm, RealmArgs) }

// RealmArgs 生成某条规则某个协议的 realm 参数。
func RealmArgs(r model.Rule, proto string) []string {
	host, port, _ := r.TargetHostPort()
	args := []string{"-l", "0.0.0.0:" + strconv.Itoa(r.ListenPort), "-r", net.JoinHostPort(host, strconv.Itoa(port))}
	if proto == model.ProtoUDP {
		// UDP 会话超时与 socat 后端保持一致
		args = append(args, "-u", "-t", "--udp-timeout", "120")
	}
	return args
}
