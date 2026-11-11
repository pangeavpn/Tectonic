// Package tectonic carries WireGuard over a small pool of short-lived TLS 1.3
// connections called lanes. Packets travel across the lanes unordered, so a
// stall on one lane never holds up the others, and to anyone watching the
// network each lane is Chrome loading an ordinary website.
//
// This file is the client's public API. Dial takes the `tectonic` profile
// block the hub returns and gives back a net.PacketConn: everything written
// to it goes to the node's WireGuard, and everything WireGuard sends back
// can be read from it. A daemon brings up a loopback UDP listener, points
// WireGuard's endpoint at it, and relays between the two.
//
// See docs/design.md for how it works and why.
package tectonic

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/pangeavpn/tectonic/lane"
	"github.com/pangeavpn/tectonic/sched"
	"github.com/pangeavpn/tectonic/shape"
	"github.com/pangeavpn/tectonic/wire"
)

// Profile is the `tectonic` block the hub returns when the user connects
// (design §4, step 1).
type Profile struct {
	// Node is the node's address, "203.0.113.7:443". The port defaults
	// to 443.
	Node string `json:"node"`
	// CoverDomain is the node's own domain, used in Own mode.
	CoverDomain string `json:"cover_domain"`
	// KeyID and DeviceKey are the credential the hub issued for this node:
	// a 20-byte key_id and the 32-byte device_key derived from it.
	KeyID     []byte `json:"key_id"`
	DeviceKey []byte `json:"device_key"`
	// Pins are base64 SHA-256 hashes of the node's default certificate's
	// public key, checked in Borrowed and None mode.
	Pins []string `json:"pins,omitempty"`
	// BorrowedSNI is the hub's list of names to borrow on SNI-allowlist
	// networks.
	BorrowedSNI []string `json:"borrowed_sni,omitempty"`
	// CDN is the optional route through a CDN, for when the node's IP is
	// blocked.
	CDN *CDNRoute `json:"cdn,omitempty"`
	// Shaping holds shaping profiles the hub has rolled out; WELCOME names
	// the one to use. The built-in default is always available.
	Shaping []*shape.Profile `json:"shaping,omitempty"`
}

// CDNRoute is how to reach the node through a CDN (design §10).
type CDNRoute struct {
	// Host is the CDN host name: the SNI and the HTTP Host.
	Host string `json:"host"`
	// Path is the WebSocket path the CDN forwards to the node.
	Path string `json:"path"`
	// Edge is the address to dial, if not Host on port 443.
	Edge string `json:"edge,omitempty"`
}

// ParseProfile decodes a profile block from JSON.
func ParseProfile(data []byte) (Profile, error) {
	var p Profile
	err := json.Unmarshal(data, &p)
	return p, err
}

// SNIMode chooses what a lane's ClientHello names (design §9).
type SNIMode int

const (
	// SNIAuto uses the mode remembered for the current network. On a
	// network not seen before it tries Own for the first lane, then
	// Borrowed, then None, moving on only when the mode before has failed
	// or got no answer, and remembers the one that logs in.
	SNIAuto SNIMode = iota
	// SNIOwn names the node's cover domain.
	SNIOwn
	// SNIBorrowed names a domain the network allows.
	SNIBorrowed
	// SNINone sends no server name.
	SNINone
)

func (m SNIMode) String() string {
	if m == SNIAuto {
		return "auto"
	}
	return lane.SNIMode(m).String()
}

// Choice is an SNI mode and, for Borrowed, the name borrowed.
type Choice struct {
	Mode SNIMode `json:"mode"`
	Name string  `json:"name,omitempty"`
}

// ModeStore remembers which SNI mode works on each network, so the next
// connection goes straight to it. Implementations must be safe for
// concurrent use; a daemon would persist them.
type ModeStore interface {
	Mode(network string) (Choice, bool)
	SetMode(network string, c Choice)
	ForgetMode(network string)
}

// NewMemoryModeStore returns a ModeStore that lives only in memory.
func NewMemoryModeStore() ModeStore { return &memoryModes{m: map[string]Choice{}} }

type memoryModes struct {
	mu sync.Mutex
	m  map[string]Choice
}

func (s *memoryModes) Mode(n string) (Choice, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.m[n]
	return c, ok
}
func (s *memoryModes) SetMode(n string, c Choice) { s.mu.Lock(); s.m[n] = c; s.mu.Unlock() }
func (s *memoryModes) ForgetMode(n string)        { s.mu.Lock(); delete(s.m, n); s.mu.Unlock() }

// Config configures a client.
type Config struct {
	Profile Profile
	// SNIMode forces one mode; the zero value is SNIAuto.
	SNIMode SNIMode
	// SNI is a name the user typed for Borrowed mode. It takes precedence
	// over the hub's list.
	SNI string
	// Network identifies the network the device is on (an SSID hash, a
	// carrier ID), so the SNI mode can be remembered per network. Update
	// it with Conn.SetNetwork.
	Network string
	// Modes stores the per-network SNI modes. Nil means in memory only.
	Modes ModeStore
	// Cellular tells the server the device is on cellular, where it allows
	// fewer lanes.
	Cellular bool
	// Control runs on each lane's socket before it connects, for example
	// to protect it from the VPN's own routing on mobile.
	Control func(network, address string, c syscall.RawConn) error
	// DialContext replaces the TCP dialer entirely (tests, benchmarks,
	// custom routing). Control is not used when it is set.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// RootCAs verifies certificates checked by name (Own mode, the CDN).
	// Nil means the system roots.
	RootCAs *x509.CertPool
	// Churn overrides lane lifetimes and byte budgets; zero means the
	// design's.
	Churn  sched.Churn
	Logger *slog.Logger
}

// Errors returned by the client.
var (
	// ErrCredentialRejected means the key_id expired or the server revoked
	// it. Fetch a new profile from the hub.
	ErrCredentialRejected = sched.ErrCredentialRejected
	// ErrClosed is returned after Close.
	ErrClosed = net.ErrClosed
)

// recvBuffer is how many datagrams from the node can wait for ReadFrom.
// They come in bursts: when a late packet arrives, the pool hands on at
// once everything it held back for it, which can be the most it holds
// (8192) with more arriving behind. A buffer that overflows drops packets
// that had already made it across, and the TCP connections inside the
// tunnel take each for congestion.
const recvBuffer = 16384

// Conn is a datagram connection to the node's WireGuard, carried over
// Tectonic lanes. It implements net.PacketConn; the address passed to
// WriteTo is ignored, and ReadFrom always reports RemoteAddr.
type Conn struct {
	pool   *sched.Pool
	d      *dialer
	log    *slog.Logger
	local  net.Addr
	remote net.Addr

	recv      chan []byte
	bufs      sync.Pool
	closed    chan struct{}
	closeOnce sync.Once

	rdMu       sync.Mutex
	rdDeadline time.Time
	rdWake     chan struct{}
}

// Dial checks the profile and starts connecting. It returns at once with a
// Conn that queues packets until the first lane is up; the first WireGuard
// packet written rides in with that lane's login, so it reaches the node
// within two round trips. Use WaitForSession to block until the session is
// established.
func Dial(ctx context.Context, cfg Config) (*Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := newDialer(cfg)
	if err != nil {
		return nil, err
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	c := &Conn{
		d:      d,
		log:    log,
		local:  addr("tectonic"),
		remote: addr(d.node),
		recv:   make(chan []byte, recvBuffer),
		closed: make(chan struct{}),
		rdWake: make(chan struct{}),
		bufs:   sync.Pool{New: func() any { return make([]byte, 0, 2048) }},
	}
	c.pool = sched.NewPool(sched.PoolConfig{
		Dial:     d.dial,
		Receive:  c.receive,
		Profiles: d.profiles,
		Churn:    cfg.Churn,
		Logger:   log,
	})
	return c, nil
}

func (c *Conn) receive(pkt []byte) {
	b := append(c.bufs.Get().([]byte)[:0], pkt...)
	select {
	case c.recv <- b:
	default:
		c.bufs.Put(b[:0]) // the reader has fallen behind: drop, as UDP would
	}
}

// ReadFrom reads one datagram from the node's WireGuard.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.rdMu.Lock()
		dl, wake := c.rdDeadline, c.rdWake
		c.rdMu.Unlock()
		var timeout <-chan time.Time
		var timer *time.Timer
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}
		stop := func() {
			if timer != nil {
				timer.Stop()
			}
		}
		select {
		case b := <-c.recv:
			stop()
			n := copy(p, b)
			c.bufs.Put(b[:0])
			return n, c.remote, nil
		case <-c.closed:
			stop()
			return 0, nil, ErrClosed
		case <-c.pool.Done():
			stop()
			if err := c.pool.Err(); err != nil {
				return 0, nil, err
			}
			return 0, nil, ErrClosed
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-wake:
			stop() // the deadline changed; start over
		}
	}
}

// WriteTo sends one datagram to the node's WireGuard. addr is ignored.
func (c *Conn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, ErrClosed
	case <-c.pool.Done():
		if err := c.pool.Err(); err != nil {
			return 0, err
		}
		return 0, ErrClosed
	default:
	}
	if len(p) > wire.MaxBodyLen {
		return 0, fmt.Errorf("tectonic: datagram of %d bytes is too large", len(p))
	}
	c.pool.Send(p)
	return len(p), nil
}

// Close ends the session and closes every lane.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.pool.Close()
	})
	return nil
}

// LocalAddr returns a placeholder address; the connection has no single
// local socket.
func (c *Conn) LocalAddr() net.Addr { return c.local }

// RemoteAddr returns the node's address.
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline sets the read deadline. Writes never block.
func (c *Conn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

// SetReadDeadline sets the deadline for ReadFrom.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.rdMu.Lock()
	c.rdDeadline = t
	close(c.rdWake)
	c.rdWake = make(chan struct{})
	c.rdMu.Unlock()
	return nil
}

// SetWriteDeadline does nothing: writes are queued, never blocked.
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }

// WaitForSession blocks until the first lane has logged in, the connection
// fails, or timeout passes. It matches the PangeaVPN daemon's SessionWaiter.
func (c *Conn) WaitForSession(ctx context.Context, timeout time.Duration) error {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return c.pool.WaitSession(ctx)
}

// SetNetwork tells the client the device moved to another network, so new
// lanes use the SNI mode remembered for it.
func (c *Conn) SetNetwork(network string, cellular bool) { c.d.setNetwork(network, cellular) }

// Stats is a snapshot of the client.
type Stats struct {
	Lanes     int
	Session   [16]byte
	Carrier   string // "direct" or "cdn"
	Mode      Choice // the SNI mode new direct lanes use
	Throttled bool   // per-connection throttling was detected
	Sent      uint64 // datagrams sent
	Dropped   uint64 // datagrams no lane would take
	Dupes     uint64 // duplicated small packets
	// Packets from the node that arrived ahead of earlier ones and waited
	// for them; earlier packets given up on when the wait ran out; and
	// packets that arrived after being given up on.
	Held, Skipped, Late uint64
	// Lost is how many packets the node said it had dropped, which nothing
	// waited for. Reported is the same count in the other direction: what
	// this end told the node not to wait for.
	Lost, Reported uint64
}

// Stats returns a snapshot of the client.
func (c *Conn) Stats() Stats {
	ps := c.pool.Stats()
	carrier, mode := c.d.state()
	return Stats{
		Lanes: ps.Lanes, Session: ps.Session, Carrier: carrier, Mode: mode, Throttled: ps.Throttled,
		Sent: ps.Scheduler.Sent, Dropped: ps.Scheduler.Dropped, Dupes: ps.Scheduler.Duplicated,
		Held: ps.Resequencer.Held, Skipped: ps.Resequencer.Skipped, Late: ps.Resequencer.Late,
		Lost: ps.Resequencer.Lost, Reported: ps.Scheduler.Reported,
	}
}

type addr string

func (a addr) Network() string { return "tectonic" }
func (a addr) String() string  { return string(a) }

var _ net.PacketConn = (*Conn)(nil)

// errNoModes is returned when the profile allows no SNI mode at all.
var errNoModes = errors.New("tectonic: the profile allows no SNI mode (no cover domain and no pins)")
