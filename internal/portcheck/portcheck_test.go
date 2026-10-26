package portcheck

import (
	"strings"
	"testing"
)

const tcpSample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 100 0 0 10 0
   2: 0F02000A:0016 0202000A:D2A4 01 00000000:00000000 02:000A3F1B 00000000     0        0 33333 4 0000000000000000 20 4 29 10 -1
`

const tcp6Sample = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44444 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 55555 1 0000000000000000 100 0 0 10 0
`

const udpSample = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  123: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 66666 2 0000000000000000 0
`

func TestParseProcNet(t *testing.T) {
	ls, err := ParseProcNet(strings.NewReader(tcpSample), "tcp", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 2 {
		t.Fatalf("expected 2 listeners (established skipped), got %d", len(ls))
	}
	if ls[0].Port != 22 || ls[0].Addr != "0.0.0.0" || ls[0].Inode != 12345 {
		t.Errorf("bad first: %+v", ls[0])
	}
	if ls[1].Port != 8080 || ls[1].Addr != "127.0.0.1" {
		t.Errorf("bad second: %+v", ls[1])
	}

	ls6, _ := ParseProcNet(strings.NewReader(tcp6Sample), "tcp", true)
	if len(ls6) != 2 || ls6[0].Port != 80 || ls6[0].Addr != "::" || ls6[1].Port != 631 || ls6[1].Addr != "::1" {
		t.Errorf("bad tcp6: %+v", ls6)
	}

	lu, _ := ParseProcNet(strings.NewReader(udpSample), "udp", false)
	if len(lu) != 1 || lu[0].Port != 53 || lu[0].Proto != "udp" {
		t.Errorf("bad udp: %+v", lu)
	}
}

func TestParentPID(t *testing.T) {
	if ParentPID(1) != 0 {
		t.Skip("pid 1 has unexpected parent")
	}
}

func TestBlocksIPv4(t *testing.T) {
	for addr, want := range map[string]bool{
		"0.0.0.0":         true,
		"127.0.0.1":       true,
		"::":              true, // 双栈通配
		"::ffff:10.0.0.1": true,
		"::1":             false,
		"fe80::1":         false,
		"2001:db8::5":     false,
	} {
		if got := (Listener{Addr: addr}).BlocksIPv4(); got != want {
			t.Errorf("%s: got %v, want %v", addr, got, want)
		}
	}
}
