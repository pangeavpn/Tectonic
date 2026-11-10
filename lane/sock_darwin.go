//go:build darwin

package lane

import (
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

// readTCPInfo uses TCP_CONNECTION_INFO, the Darwin (macOS and iOS) form of
// TCP_INFO. It has no delivery rate, so the rate is the congestion window
// over the smoothed RTT.
func readTCPInfo(rc syscall.RawConn) (tcpInfo, bool) {
	var ti *unix.TCPConnectionInfo
	var err error
	if cerr := rc.Control(func(fd uintptr) {
		ti, err = unix.GetsockoptTCPConnectionInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_CONNECTION_INFO)
	}); cerr != nil || err != nil || ti == nil {
		return tcpInfo{}, false
	}
	info := tcpInfo{
		rtt:     time.Duration(ti.Srtt) * time.Millisecond,
		retrans: ti.Txretransmitpackets,
	}
	if ti.Srtt > 0 && ti.Snd_cwnd > 0 {
		info.rate = float64(ti.Snd_cwnd) / (float64(ti.Srtt) / 1000)
	}
	// Darwin gives the window in bytes and the bytes in the send buffer,
	// sent or not; those the window covers are taken to be in flight.
	info.cwnd = float64(ti.Snd_cwnd)
	info.inflight = min(float64(ti.Snd_sbbytes), info.cwnd)
	info.notsent = float64(ti.Snd_sbbytes) - info.inflight
	info.mss = float64(ti.Maxseg)
	info.rto = time.Duration(ti.Rto) * time.Millisecond
	return info, true
}

// pacedByDesign: Darwin's TCP does not pace.
func pacedByDesign(syscall.RawConn) bool { return false }
