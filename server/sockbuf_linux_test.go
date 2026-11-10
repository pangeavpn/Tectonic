//go:build linux

package server

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSocketBuffersAreRaised(t *testing.T) {
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rcvbuf := func() int {
		rc, err := c.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var v int
		rc.Control(func(fd uintptr) { v, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF) })
		return v / 2 // the kernel reports twice what was set
	}
	before := rcvbuf()
	got := setSocketBuffers(c)
	if got != rcvbuf() {
		t.Fatalf("setSocketBuffers reported %d, the socket has %d", got, rcvbuf())
	}
	// How far it goes is up to net.core.rmem_max, or CAP_NET_ADMIN; it
	// never comes out smaller, or larger than asked for.
	if got < before || got > wgSocketBuffer {
		t.Fatalf("receive buffer went from %d to %d, asking for %d", before, got, wgSocketBuffer)
	}
	t.Logf("receive buffer: %d before, %d after", before, got)
}
