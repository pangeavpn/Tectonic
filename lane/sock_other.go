//go:build !linux && !darwin

package lane

import "syscall"

// Other platforms have no TCP_NOTSENT_LOWAT or TCP_INFO that we use, so the
// lane falls back to PING/PONG for its estimates.

func setNotSentLowat(syscall.RawConn, int) {}

func readTCPInfo(syscall.RawConn) (tcpInfo, bool) { return tcpInfo{}, false }
