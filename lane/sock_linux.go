//go:build linux

package lane

import (
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func setNotSentLowat(rc syscall.RawConn, n int) bool {
	var err error
	if cerr := rc.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, n)
	}); cerr != nil {
		return false
	}
	return err == nil
}

func readTCPInfo(rc syscall.RawConn) (tcpInfo, bool) {
	var ti *unix.TCPInfo
	var err error
	if cerr := rc.Control(func(fd uintptr) {
		ti, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); cerr != nil || err != nil || ti == nil {
		return tcpInfo{}, false
	}
	mss := float64(ti.Snd_mss)
	// In flight is what has been sent and neither acknowledged, delivered
	// out of order nor given up for lost, plus what was sent again.
	inflight := int64(ti.Unacked) - int64(ti.Sacked) - int64(ti.Lost) + int64(ti.Retrans)
	info := tcpInfo{
		rtt:      time.Duration(ti.Rtt) * time.Microsecond,
		minRTT:   time.Duration(ti.Min_rtt) * time.Microsecond,
		rate:     float64(ti.Delivery_rate),
		retrans:  uint64(ti.Total_retrans),
		stalled:  ti.Retransmits > 0,
		cwnd:     float64(ti.Snd_cwnd) * mss,
		inflight: float64(max(inflight, 0)) * mss,
		notsent:  float64(ti.Notsent_bytes),
		mss:      mss,
		rto:      time.Duration(ti.Rto) * time.Microsecond,

		bytesSent:   ti.Bytes_sent,
		bytesResent: ti.Bytes_retrans,
		segsSent:    ti.Data_segs_out,
		delivered:   ti.Delivered,
	}
	if ti.Pacing_rate != ^uint64(0) {
		info.pacing = float64(ti.Pacing_rate)
	}
	return info, true
}

// pacedByDesign reports whether the connection's congestion control always
// paces: BBR, in any version.
func pacedByDesign(rc syscall.RawConn) bool {
	var name string
	rc.Control(func(fd uintptr) {
		name, _ = unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
	})
	return strings.HasPrefix(name, "bbr")
}
