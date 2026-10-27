package backend

import (
	"strconv"

	"lport/internal/model"
)

// NewSocat 每条规则每个协议一个 socat 进程。
func NewSocat() *Process { return newProcess(model.BackendSocat, SocatArgs) }

// SocatArgs 生成某条规则某个协议的 socat 参数。
func SocatArgs(r model.Rule, proto string) []string {
	host, port, _ := r.TargetHostPort()
	target := host + ":" + strconv.Itoa(port)
	lp := strconv.Itoa(r.ListenPort)
	if proto == model.ProtoUDP {
		return []string{"-T", "120", "UDP4-LISTEN:" + lp + ",fork,reuseaddr", "UDP4:" + target}
	}
	return []string{"TCP4-LISTEN:" + lp + ",fork,reuseaddr", "TCP4:" + target}
}
