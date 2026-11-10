//go:build !linux

package server

import "net"

func forceSocketBuffers(*net.UDPConn, int) int { return 0 }
