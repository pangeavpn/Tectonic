//go:build !linux && !darwin

package lane

import "syscall"

// Other platforms (Windows among them) have no TCP_NOTSENT_LOWAT or TCP_INFO
// that we use, so the lane falls back to PING/PONG for its estimates and for
// keeping its queue out of the kernel.

func setNotSentLowat(syscall.RawConn, int) bool { return false }

func readTCPInfo(syscall.RawConn) (tcpInfo, bool) { return tcpInfo{}, false }
