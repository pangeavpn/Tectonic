package server

import "net"

// wgSocketBuffer is the buffer a session asks for on its UDP socket to
// WireGuard, in each direction: what wireguard-go asks for on its own.
//
// WireGuard hands over the tunnel's traffic in bursts: a TCP sender inside
// the tunnel that gets a run of ACKs at once answers with hundreds of
// packets, encrypted on several cores and sent in one go. The default
// buffer (about 200 KB on Linux, less than a hundred full-size packets as
// the kernel counts them) overflows before a reader can be scheduled, and
// what it drops the TCP inside the tunnel takes for congestion. Nothing
// waits here for long: the reader moves each packet to a lane's queue at
// once, and that queue is where the tunnel's backlog is limited.
const wgSocketBuffer = 7 << 20

// wgSocketBufferLow is the receive buffer below which the server warns
// that the system's limit is in the way.
const wgSocketBufferLow = 1 << 20

// setSocketBuffers asks for wgSocketBuffer on c and returns the receive
// buffer the socket really has, or 0 where that can't be read.
func setSocketBuffers(c *net.UDPConn) int {
	c.SetReadBuffer(wgSocketBuffer)
	c.SetWriteBuffer(wgSocketBuffer)
	return forceSocketBuffers(c, wgSocketBuffer)
}
