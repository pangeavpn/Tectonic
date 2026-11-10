//go:build linux

package server

import (
	"net"

	"golang.org/x/sys/unix"
)

// forceSocketBuffers raises c's buffers past net.core.rmem_max and
// wmem_max, which only a process with CAP_NET_ADMIN may do, and returns
// the receive buffer the socket ends up with. The kernel reports twice
// what was asked for, to cover its own bookkeeping; the return value is
// halved to match.
func forceSocketBuffers(c *net.UDPConn, n int) int {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0
	}
	got := 0
	rc.Control(func(fd uintptr) {
		unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n)
		unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n)
		if v, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF); err == nil {
			got = v / 2
		}
	})
	return got
}
