package tectonic

import (
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// Bind carries a wireguard-go device straight over a Conn, so a daemon that runs wireguard-go
// needs no loopback socket to relay through, and moves packets in batches.
type Bind struct {
	c *Conn

	mu   sync.Mutex
	stop chan struct{} // closed when the bind closes; nil while it is closed
}

var _ conn.Bind = (*Bind)(nil)

// NewBind returns a closed bind over c. wireguard-go opens and closes its bind as it likes;
// closing the bind leaves c open, and its owner closes it after the device.
func NewBind(c *Conn) *Bind { return &Bind{c: c} }

// bindBatch is how many packets one call moves at most, as wireguard-go's own binds do.
const bindBatch = 128

// Open implements conn.Bind.
func (b *Bind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stop != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	stop := make(chan struct{})
	b.stop = stop
	return []conn.ReceiveFunc{func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		return b.receive(stop, bufs, sizes, eps)
	}}, 0, nil
}

// receive waits for one datagram from the node and takes as many more as are already waiting.
func (b *Bind) receive(stop chan struct{}, bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	var pkt []byte
	select {
	case pkt = <-b.c.recv:
	case <-stop:
		return 0, net.ErrClosed
	case <-b.c.closed:
		return 0, net.ErrClosed
	case <-b.c.pool.Done():
		if err := b.c.pool.Err(); err != nil {
			return 0, err
		}
		return 0, net.ErrClosed
	}
	n := 0
	for {
		sizes[n] = copy(bufs[n], pkt)
		eps[n] = nodeEndpoint{}
		b.c.bufs.Put(pkt[:0])
		if n++; n == len(bufs) {
			return n, nil
		}
		select {
		case pkt = <-b.c.recv:
		default:
			return n, nil
		}
	}
}

// Close implements conn.Bind. It stops the receive function and leaves the Conn open.
func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stop != nil {
		close(b.stop)
		b.stop = nil
	}
	return nil
}

// SetMark implements conn.Bind; there is no socket to mark.
func (b *Bind) SetMark(uint32) error { return nil }

// Send implements conn.Bind: every datagram goes to the node, whatever the endpoint.
func (b *Bind) Send(bufs [][]byte, _ conn.Endpoint) error {
	for _, buf := range bufs {
		if _, err := b.c.WriteTo(buf, nil); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint implements conn.Bind. The device's one peer is the node, whatever its endpoint says.
func (b *Bind) ParseEndpoint(string) (conn.Endpoint, error) { return nodeEndpoint{}, nil }

// BatchSize implements conn.Bind.
func (b *Bind) BatchSize() int { return bindBatch }

// nodeEndpoint is the node, the only peer a device on a Bind has.
type nodeEndpoint struct{}

func (nodeEndpoint) ClearSrc()           {}
func (nodeEndpoint) SrcToString() string { return "" }
func (nodeEndpoint) DstToString() string { return "tectonic" }
func (nodeEndpoint) DstToBytes() []byte  { return []byte("tectonic") }
func (nodeEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (nodeEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
