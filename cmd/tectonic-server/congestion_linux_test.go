//go:build linux

package main

import (
	"log/slog"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func congestionOf(t *testing.T, c net.Conn) string {
	t.Helper()
	rc, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cc string
	rc.Control(func(fd uintptr) { cc, _ = unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION) })
	return cc
}

// reno is in every kernel and open to every process, so it stands in for bbr here.
func TestConnectionsTakeTheListenersCongestionControl(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	for _, cc := range []string{"reno", "no-such-congestion-control"} {
		ln, err := listenTCP("127.0.0.1:0", cc, log)
		if err != nil {
			t.Fatalf("%s: %v", cc, err)
		}
		go func() {
			if c, err := net.Dial("tcp", ln.Addr().String()); err == nil {
				defer c.Close()
				c.Read(make([]byte, 1))
			}
		}()
		c, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		got := congestionOf(t, c)
		c.Close()
		ln.Close()
		if cc == "reno" && got != "reno" {
			t.Fatalf("a connection accepted on a reno listener runs %q", got)
		}
		if cc != "reno" && got == "" {
			t.Fatal("no congestion control at all where the one asked for is missing")
		}
	}
}
