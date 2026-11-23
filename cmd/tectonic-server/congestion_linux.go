//go:build linux

package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// setCongestion sets a socket's congestion control. On a listening socket, its connections inherit it.
func setCongestion(c syscall.RawConn, cc string) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, cc)
	}); err != nil {
		return err
	}
	return serr
}
