package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/pangeavpn/tectonic/bench/knet"
	"github.com/pangeavpn/tectonic/bench/link"
)

// The bench runs over one of two paths between the client and the node:
//
//   - the simulated link (bench/link): two gVisor stacks in this process,
//     the default and the only choice off Linux;
//   - the kernel path (-kernel, bench/knet): network namespaces joined by
//     veths, with netem, tbf and fq on a router between them. The TCP
//     under the transports is Linux's, so lanes run with TCP_NOTSENT_LOWAT
//     and TCP_INFO as they do on Linux, Android, macOS and iOS; and the
//     TCP inside the tunnel is Linux's, through real TUN devices.

// path is the outer network between the client and the node.
type path interface {
	client() pathHost
	server() pathHost
	serverAddr() netip.Addr
	// stats is what the path delivered in each direction (up is
	// client→server).
	stats() (up, down link.DirStats)
	// tcpFlows lists TCP connections to port on the server.
	tcpFlows(port uint16) []link.Flow
	resetFlow(f link.Flow) error
	close()
}

// pathHost opens sockets on one end of the path.
type pathHost interface {
	DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	ListenTCP(port uint16) (net.Listener, error)
	ListenUDP(port uint16) (net.PacketConn, error)
}

// kernel is the kernel topology when the bench runs with -kernel, and
// kernelInner whether the tunnel's TCP is the kernel's too (TUN devices)
// rather than gVisor's.
var (
	kernel      *knet.Topology
	kernelInner bool
)

// newPath builds a path with the given impairments.
func newPath(lc link.Config) (path, error) {
	if kernel != nil {
		// The previous environment's TUN devices must be gone before the
		// next one makes its own.
		kernel.WaitGone(2 * time.Second)
		if err := kernel.Configure(lc); err != nil {
			return nil, err
		}
		return kernelPath{kernel}, nil
	}
	L, err := link.New(lc)
	if err != nil {
		return nil, err
	}
	return simPath{L}, nil
}

type simPath struct{ L *link.Link }

func (p simPath) client() pathHost                { return p.L.Client }
func (p simPath) server() pathHost                { return p.L.Server }
func (p simPath) serverAddr() netip.Addr          { return link.ServerAddr }
func (p simPath) stats() (up, down link.DirStats) { return p.L.Stats() }
func (p simPath) resetFlow(f link.Flow) error     { return p.L.ResetFlow(f) }
func (p simPath) close()                          { p.L.Close() }

func (p simPath) tcpFlows(port uint16) []link.Flow {
	var out []link.Flow
	for _, f := range p.L.Flows() {
		if f.Proto == link.ProtoTCP && (f.Dst.Port() == port || f.Src.Port() == port) {
			out = append(out, f)
		}
	}
	return out
}

type kernelPath struct{ t *knet.Topology }

func (p kernelPath) client() pathHost                { return p.t.Client() }
func (p kernelPath) server() pathHost                { return p.t.Server() }
func (p kernelPath) serverAddr() netip.Addr          { return knet.ServerAddr }
func (p kernelPath) stats() (up, down link.DirStats) { return p.t.Stats() }
func (p kernelPath) resetFlow(f link.Flow) error     { return p.t.ResetFlow(f) }
func (p kernelPath) close()                          {} // the topology outlives each environment

func (p kernelPath) tcpFlows(port uint16) []link.Flow {
	fs, _ := p.t.TCPFlows(port)
	return fs
}

// tunnelNet opens sockets inside the tunnel, on one peer.
type tunnelNet interface {
	dialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	listenTCP(ap netip.AddrPort) (net.Listener, error)
	listenUDP(ap netip.AddrPort) (net.PacketConn, error)
	dialUDP(dst netip.AddrPort) (net.Conn, error)
}

// gvisorTunnel is a wgnet peer's userspace stack.
type gvisorTunnel struct{ n *netstack.Net }

func (g gvisorTunnel) dialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return g.n.DialContextTCPAddrPort(ctx, dst)
}
func (g gvisorTunnel) listenTCP(ap netip.AddrPort) (net.Listener, error) {
	return g.n.ListenTCPAddrPort(ap)
}
func (g gvisorTunnel) listenUDP(ap netip.AddrPort) (net.PacketConn, error) {
	return g.n.ListenUDPAddrPort(ap)
}
func (g gvisorTunnel) dialUDP(dst netip.AddrPort) (net.Conn, error) {
	return g.n.DialUDPAddrPort(netip.AddrPort{}, dst)
}

// kernelTunnel is a kernel TUN device's side of the tunnel.
type kernelTunnel struct{ h *knet.Host }

func (k kernelTunnel) dialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return k.h.DialTCP(ctx, dst)
}
func (k kernelTunnel) listenTCP(ap netip.AddrPort) (net.Listener, error) {
	return k.h.ListenTCPAddrPort(ap)
}
func (k kernelTunnel) listenUDP(ap netip.AddrPort) (net.PacketConn, error) {
	return k.h.ListenUDPAddrPort(ap)
}
func (k kernelTunnel) dialUDP(dst netip.AddrPort) (net.Conn, error) { return k.h.DialUDP(dst) }

// describePath is the header line saying which path and stacks a run used.
func describePath() string {
	if kernel == nil {
		return fmt.Sprintf("path: simulated link (gVisor TCP outside and inside the tunnel, inner RACK %v)", innerRACK)
	}
	cc := "kernel default (cubic)"
	if kernel.ServerCC != "" {
		cc = kernel.ServerCC
	}
	in := "Linux cubic over TUN devices"
	if !kernelInner {
		in = fmt.Sprintf("gVisor (RACK %v)", innerRACK)
	}
	return fmt.Sprintf("path: kernel (netns + veth, netem/tbf/fq on a router); outer TCP: Linux, node sends with %s; inner TCP: %s", cc, in)
}

// logSockets logs, on the kernel path, what the kernel says about the
// transport's outer TCP connections: congestion control, cwnd, RTT, unsent
// bytes. It shows which lane path the run exercised.
func logSockets(o opts, e *env) {
	if kernel == nil {
		return
	}
	port := uint16(0)
	switch e.tr {
	case tTectonic:
		port = tectonicPort
	case tReality, tAnyTLS:
		port = baselinePort
	default:
		return
	}
	o.logf("%s: client sockets:\n%s", e.tr, kernel.SS(false, port))
	o.logf("%s: node sockets:\n%s", e.tr, kernel.SS(true, port))
}
