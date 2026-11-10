package link

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/pangeavpn/tectonic/bench/internal/stacktune"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nicID tcpip.NICID = 1

// Host is one end of the link: a gVisor stack with a single IPv4 address.
type Host struct {
	// Stack is the host's network stack, exposed for stats and tuning.
	// New sets CUBIC, SACK, no RACK and 4 MiB socket buffers (see
	// internal/stacktune); change protocol options here before opening
	// the sockets they should apply to.
	Stack *stack.Stack

	addr netip.Addr
	ep   *endpoint
}

func newHost(addr netip.Addr, ep *endpoint) (*Host, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	fail := func(what string, err tcpip.Error) (*Host, error) {
		s.Destroy()
		return nil, fmt.Errorf("link: %s for %v: %v", what, addr, err)
	}
	if err := s.CreateNIC(nicID, ep); err != nil {
		return fail("CreateNIC", err)
	}
	pa := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(addr.As4()).WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
		return fail("AddProtocolAddress", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	// The link never reorders, so RACK buys nothing and, in this gVisor,
	// recovers worse from drop bursts; see stacktune.
	if err := stacktune.Tune(s, false); err != nil {
		s.Destroy()
		return nil, err
	}
	return &Host{Stack: s, addr: addr, ep: ep}, nil
}

// Addr returns the host's IPv4 address.
func (h *Host) Addr() netip.Addr { return h.addr }

func (h *Host) full(addr netip.Addr, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(addr.As4()), Port: port}
}

// DialTCP opens a TCP connection from h to dst across the link.
func (h *Host) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	addr := dst.Addr().Unmap()
	if !addr.Is4() {
		return nil, fmt.Errorf("link: %v is not an IPv4 address", dst)
	}
	c, err := gonet.DialContextTCP(ctx, h.Stack, h.full(addr, dst.Port()), ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ListenTCP listens for TCP connections on h's address. Port 0 picks an
// ephemeral port; read it back from the listener's Addr.
func (h *Host) ListenTCP(port uint16) (net.Listener, error) {
	ln, err := gonet.ListenTCP(h.Stack, h.full(h.addr, port), ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return ln, nil
}

// ListenUDP opens an unconnected UDP socket on h's address that can send to
// and receive from any peer. Port 0 picks an ephemeral port. Addresses read
// from and accepted by the socket are *net.UDPAddr.
func (h *Host) ListenUDP(port uint16) (net.PacketConn, error) {
	laddr := h.full(h.addr, port)
	c, err := gonet.DialUDP(h.Stack, &laddr, nil, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// endpoint is the link-layer device of one host. Packets the stack writes go
// into the outbound direction's pipeline; the opposite direction calls
// deliver to hand packets to this stack.
type endpoint struct {
	mtu uint32
	out *direction

	mu         sync.RWMutex
	dispatcher stack.NetworkDispatcher
}

// WritePackets implements stack.LinkEndpoint. The link copies each packet,
// so the stack keeps ownership of pkts.
func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for _, pkt := range pkts.AsSlice() {
		b := make([]byte, 0, pkt.Size())
		for _, s := range pkt.AsSlices() {
			b = append(b, s...)
		}
		e.out.send(b)
	}
	return pkts.Len(), nil
}

// deliver hands a raw IPv4 packet to this host's stack.
func (e *endpoint) deliver(b []byte) {
	if len(b) == 0 || b[0]>>4 != 4 {
		return
	}
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d == nil {
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	d.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()
}

func (e *endpoint) Attach(d stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = d
	e.mu.Unlock()
}

func (e *endpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

func (e *endpoint) MTU() uint32                                  { return e.mtu }
func (e *endpoint) SetMTU(uint32)                                {}
func (e *endpoint) MaxHeaderLength() uint16                      { return 0 }
func (e *endpoint) LinkAddress() tcpip.LinkAddress               { return "" }
func (e *endpoint) SetLinkAddress(tcpip.LinkAddress)             {}
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities { return 0 }
func (e *endpoint) Wait()                                        {}
func (e *endpoint) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (e *endpoint) AddHeader(*stack.PacketBuffer)                {}
func (e *endpoint) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (e *endpoint) Close()                                       {}
func (e *endpoint) SetOnCloseAction(func())                      {}
