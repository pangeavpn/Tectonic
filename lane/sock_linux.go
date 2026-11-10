//go:build linux

package lane

import (
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func setNotSentLowat(rc syscall.RawConn, n int) {
	_ = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, n)
	})
}

func readTCPInfo(rc syscall.RawConn) (tcpInfo, bool) {
	var ti *unix.TCPInfo
	var err error
	if cerr := rc.Control(func(fd uintptr) {
		ti, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); cerr != nil || err != nil || ti == nil {
		return tcpInfo{}, false
	}
	return tcpInfo{
		rtt:     time.Duration(ti.Rtt) * time.Microsecond,
		minRTT:  time.Duration(ti.Min_rtt) * time.Microsecond,
		rate:    float64(ti.Delivery_rate),
		retrans: uint64(ti.Total_retrans),
		stalled: ti.Retransmits > 0,
	}, true
}
