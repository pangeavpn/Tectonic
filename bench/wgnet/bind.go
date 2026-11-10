package wgnet

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// PacketConnBind adapts a single net.PacketConn to WireGuard's conn.Bind.
//
// The PacketConn may be anything: a real UDP socket, a bench/link socket, or
// a transport's datagram connection whose addresses are not UDP addresses
// at all. Received addresses become endpoints and are handed back verbatim
// when WireGuard replies, so a PacketConn that ignores the address in
// WriteTo works too.
//
// Close does not close the PacketConn. wireguard-go closes and reopens its
// bind whenever the device comes up or its listen port changes, so the bind
// only stops reading (by setting a read deadline in the past) and the owner
// closes the PacketConn after closing the device.
type PacketConnBind struct {
	pc net.PacketConn

	mu   sync.Mutex
	open bool
}

var _ conn.Bind = (*PacketConnBind)(nil)

// NewPacketConnBind returns a bind that reads and writes through pc.
func NewPacketConnBind(pc net.PacketConn) *PacketConnBind {
	return &PacketConnBind{pc: pc}
}

// PacketConn returns the underlying connection.
func (b *PacketConnBind) PacketConn() net.PacketConn { return b.pc }

// Open implements conn.Bind. It ignores port and reports the PacketConn's
// local UDP port, or 0 if it has none.
func (b *PacketConnBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if err := b.pc.SetReadDeadline(time.Time{}); err != nil {
		return nil, 0, err
	}
	b.open = true
	var port uint16
	if ap, ok := addrPort(b.pc.LocalAddr()); ok {
		port = ap.Port()
	}
	return []conn.ReceiveFunc{b.receive}, port, nil
}

func (b *PacketConnBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	for {
		n, addr, err := b.pc.ReadFrom(packets[0])
		if err != nil {
			if !b.isOpen() {
				return 0, net.ErrClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue // a deadline someone else set; keep reading
			}
			return 0, err
		}
		sizes[0] = n
		eps[0] = newEndpoint(addr)
		return 1, nil
	}
}

func (b *PacketConnBind) isOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.open
}

// Close implements conn.Bind. It unblocks the receive function, which then
// returns net.ErrClosed, but leaves the PacketConn open.
func (b *PacketConnBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return nil
	}
	b.open = false
	return b.pc.SetReadDeadline(time.Unix(1, 0))
}

// SetMark implements conn.Bind; it does nothing.
func (b *PacketConnBind) SetMark(uint32) error { return nil }

// Send implements conn.Bind.
func (b *PacketConnBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*Endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	for _, buf := range bufs {
		if _, err := b.pc.WriteTo(buf, e.addr); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint implements conn.Bind. It accepts "ip:port".
func (b *PacketConnBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &Endpoint{ap: ap, addr: net.UDPAddrFromAddrPort(ap)}, nil
}

// BatchSize implements conn.Bind.
func (b *PacketConnBind) BatchSize() int { return 1 }

// Endpoint is a PacketConnBind peer address. It keeps the net.Addr the
// PacketConn reported so replies go back to exactly that address.
type Endpoint struct {
	ap   netip.AddrPort // zero if addr is not an IP address
	addr net.Addr
}

func newEndpoint(addr net.Addr) *Endpoint {
	ap, _ := addrPort(addr)
	return &Endpoint{ap: ap, addr: addr}
}

// addrPort extracts an IP address and port from addr, unmapping 4-in-6.
func addrPort(addr net.Addr) (netip.AddrPort, bool) {
	var ap netip.AddrPort
	switch a := addr.(type) {
	case *net.UDPAddr:
		ap = a.AddrPort()
	case *net.TCPAddr:
		ap = a.AddrPort()
	case nil:
		return ap, false
	default:
		var err error
		if ap, err = netip.ParseAddrPort(addr.String()); err != nil {
			return ap, false
		}
	}
	if !ap.IsValid() {
		return ap, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

func (e *Endpoint) ClearSrc()           {}
func (e *Endpoint) SrcToString() string { return "" }
func (e *Endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *Endpoint) DstIP() netip.Addr   { return e.ap.Addr() }

func (e *Endpoint) DstToString() string {
	if e.ap.IsValid() {
		return e.ap.String()
	}
	if e.addr != nil {
		return e.addr.String()
	}
	return ""
}

// DstToBytes is used for WireGuard's cookie MACs; any stable encoding of
// the peer address works.
func (e *Endpoint) DstToBytes() []byte {
	if e.ap.IsValid() {
		b, _ := e.ap.MarshalBinary()
		return b
	}
	return []byte(e.DstToString())
}
