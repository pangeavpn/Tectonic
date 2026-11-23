//go:build windows

package lane

import (
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sioTCPInfo is SIO_TCP_INFO (Windows 10 1703 and later), which x/sys/windows does not name.
const sioTCPInfo = windows.IOC_INOUT | windows.IOC_VENDOR | 39

// tcpInfoV0 is TCP_INFO_v0.
type tcpInfoV0 struct {
	State             int32
	Mss               uint32
	ConnectionTimeMs  uint64
	TimestampsEnabled uint8
	RttUs             uint32
	MinRttUs          uint32
	BytesInFlight     uint32
	Cwnd              uint32
	SndWnd            uint32
	RcvWnd            uint32
	RcvBuf            uint32
	BytesOut          uint64
	BytesIn           uint64
	BytesReordered    uint32
	BytesRetrans      uint32
	FastRetrans       uint32
	DupAcksIn         uint32
	TimeoutEpisodes   uint32
	SynRetrans        uint8
}

// Windows has no TCP_NOTSENT_LOWAT, so the lane still paces itself on PONGs.
func setNotSentLowat(syscall.RawConn, int) bool { return false }

func readTCPInfo(rc syscall.RawConn) (tcpInfo, bool) {
	var ti tcpInfoV0
	var err error
	if cerr := rc.Control(func(fd uintptr) {
		var version, n uint32
		err = windows.WSAIoctl(windows.Handle(fd), sioTCPInfo,
			(*byte)(unsafe.Pointer(&version)), uint32(unsafe.Sizeof(version)),
			(*byte)(unsafe.Pointer(&ti)), uint32(unsafe.Sizeof(ti)), &n, nil, 0)
	}); cerr != nil || err != nil || ti.Mss == 0 {
		return tcpInfo{}, false
	}
	// No byte counts, so the session's send limit stays off: fed from these, it held a Windows
	// uplink's queue no lower.
	return tcpInfo{
		rtt:      time.Duration(ti.RttUs) * time.Microsecond,
		minRTT:   time.Duration(ti.MinRttUs) * time.Microsecond,
		retrans:  uint64(ti.BytesRetrans),
		cwnd:     float64(ti.Cwnd),
		inflight: float64(ti.BytesInFlight),
		mss:      float64(ti.Mss),
	}, true
}

func pacedByDesign(syscall.RawConn) bool { return false }
