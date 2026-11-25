package tectonic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/lane"
	"github.com/pangeavpn/tectonic/sched"
	"github.com/pangeavpn/tectonic/server"
	"github.com/pangeavpn/tectonic/wire"
)

// These tests drive the dialer's choice of SNI mode on a network it hasn't
// seen (tryModes) against a real node, through a fake network that treats
// each connection by the name in its ClientHello, as an SNI filter does.

const (
	modeCover    = "n3.cover.test"
	modeBorrowed = "allowed.example"
)

type modeCerts struct {
	roots *x509.CertPool
	own   tls.Certificate
	def   tls.Certificate
	pin   string
}

var modeTestCerts = sync.OnceValue(func() modeCerts {
	var c modeCerts
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	c.roots = x509.NewCertPool()
	c.roots.AddCert(caCert)
	mk := func(serial int64, names []string, selfSigned bool) tls.Certificate {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "x"},
			DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		}
		parent, key := caCert, caKey
		if selfSigned {
			parent, key = tmpl, k
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, key)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	}
	c.own = mk(2, []string{modeCover}, false)
	c.def = mk(3, nil, true)
	leaf, _ := x509.ParseCertificate(c.def.Certificate[0])
	c.pin = lane.PinOf(leaf).String()
	return c
})

// wgStub stands in for the node's WireGuard: it records every datagram
// with the socket it came from, and sends it back. Each session has its own
// socket, so the sources tell the sessions apart.
type wgStub struct {
	conn *net.UDPConn
	mu   sync.Mutex
	got  []wgDatagram
}

type wgDatagram struct {
	from string
	data []byte
}

func newWGStub(t *testing.T) *wgStub {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	w := &wgStub{conn: conn}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			w.mu.Lock()
			w.got = append(w.got, wgDatagram{from.String(), bytes.Clone(buf[:n])})
			w.mu.Unlock()
			conn.WriteToUDP(buf[:n], from)
		}
	}()
	return w
}

// copies returns the sockets that delivered pkt, one entry per copy.
func (w *wgStub) copies(pkt []byte) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var from []string
	for _, d := range w.got {
		if bytes.Equal(d.data, pkt) {
			from = append(from, d.from)
		}
	}
	return from
}

type modeNode struct {
	addr   string
	secret []byte
	wg     *wgStub
}

func startModeNode(t *testing.T, secret byte) *modeNode {
	t.Helper()
	c := modeTestCerts()
	n := &modeNode{secret: bytes.Repeat([]byte{secret}, 32), wg: newWGStub(t)}
	s, err := server.New(server.Config{
		NodeSecret:         n.secret,
		CoverDomain:        modeCover,
		OwnCertificate:     func() (*tls.Certificate, error) { return &c.own, nil },
		DefaultCertificate: func() (*tls.Certificate, error) { return &c.def, nil },
		Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "<html>a small, plausible website</html>")
		}),
		WireGuard: n.wg.conn.LocalAddr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })
	n.addr = ln.Addr().String()
	return n
}

// What the fake network does to a connection, by the name in its
// ClientHello.
type sniRule int

const (
	sniPass       sniRule = iota
	sniReset              // the connection is reset when the ClientHello is seen
	sniDrop               // the ClientHello and everything after it vanish
	sniDropLogin          // the TLS handshake passes; what the client sends after it vanishes
	sniDropAnswer         // the login passes; what the server sends from then on vanishes
)

// fakeNet is the network between the client and its node.
type fakeNet struct {
	rules        map[string]sniRule       // by name; "" is a ClientHello without one
	routes       map[string]string        // names that reach some other server
	delays       map[string]time.Duration // how long a name's ClientHello is held up
	connectDelay time.Duration            // how long a TCP handshake takes
	connectErr   error                    // if set, TCP never connects
	dead         map[string]bool          // addresses whose SYNs vanish: a dial there never connects
	// residual, if set, is how long the network resets every ClientHello
	// to the node after resetting one by its name, as the GFW does; a
	// name reset again starts the time over.
	residual      time.Duration
	residualUntil time.Time

	mu     sync.Mutex
	dials  []dialRecord
	hellos []string // the name in every ClientHello sent, in order
	conns  []*fakeConn
}

type dialRecord struct {
	began, done time.Time
	addr        string // the address the client asked for
}

func (n *fakeNet) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	began := time.Now()
	if n.dead[addr] {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if n.connectDelay > 0 {
		select {
		case <-time.After(n.connectDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dials = append(n.dials, dialRecord{began, time.Now(), addr})
	if n.connectErr != nil {
		return nil, n.connectErr
	}
	c := &fakeConn{net: n, addr: addr, done: make(chan struct{})}
	c.cond = sync.NewCond(&c.mu)
	n.conns = append(n.conns, c)
	return c, nil
}

func (n *fakeNet) sent() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.hellos)
}

// lastDialed is the address of the most recent connection.
func (n *fakeNet) lastDialed() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.dials) == 0 {
		return ""
	}
	return n.dials[len(n.dials)-1].addr
}

func (n *fakeNet) dialed() []dialRecord {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.dials)
}

// fakeConn is a TCP connection through the fake network. It reaches its
// server only once the network has seen its ClientHello and let it by.
type fakeConn struct {
	net  *fakeNet
	addr string
	done chan struct{} // closed with the connection

	mu      sync.Mutex
	cond    *sync.Cond
	rule    sniRule
	out     []byte   // what the client wrote, up to the last whole record
	records int      // records the client has sent
	appData int      // of them, application data: its Finished, then its login
	up      net.Conn // the server, once the ClientHello has passed
	vanish  bool     // what the client sends no longer arrives
	mute    bool     // what the server sends no longer arrives
	closed  bool
	expired bool // a read deadline in the past
}

func (c *fakeConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.out = append(c.out, b...)
	for len(c.out) >= 5 {
		n := 5 + int(binary.BigEndian.Uint16(c.out[3:]))
		if len(c.out) < n {
			break
		}
		rec := c.out[:n]
		c.out = c.out[n:]
		if err := c.record(rec); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// record handles one TLS record from the client.
func (c *fakeConn) record(rec []byte) error {
	c.records++
	if c.records == 1 {
		name := helloName(rec)
		c.net.mu.Lock()
		c.net.hellos = append(c.net.hellos, name)
		c.rule = c.net.rules[name]
		if c.net.residual > 0 {
			if c.rule == sniReset {
				c.net.residualUntil = time.Now().Add(c.net.residual)
			} else if time.Now().Before(c.net.residualUntil) {
				c.rule = sniReset
			}
		}
		to := c.addr
		if r, ok := c.net.routes[name]; ok {
			to = r
		}
		delay := c.net.delays[name]
		c.net.mu.Unlock()
		if delay > 0 {
			c.mu.Unlock()
			select {
			case <-time.After(delay):
			case <-c.done:
			}
			c.mu.Lock()
			if c.closed {
				return net.ErrClosed
			}
		}
		switch c.rule {
		case sniReset:
			c.closed = true
			close(c.done)
			c.cond.Broadcast()
			return syscall.ECONNRESET
		case sniDrop:
			c.vanish = true
			return nil
		}
		up, err := net.Dial("tcp", to)
		if err != nil {
			return err
		}
		c.up = up
		c.cond.Broadcast()
	}
	if rec[0] == 23 {
		c.appData++
		if c.appData == 2 { // the login
			switch c.rule {
			case sniDropLogin:
				c.vanish = true
			case sniDropAnswer:
				c.mute = true
			}
		}
	}
	if c.vanish {
		return nil
	}
	_, err := c.up.Write(rec)
	return err
}

func (c *fakeConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	for c.up == nil && !c.closed && !c.expired {
		c.cond.Wait()
	}
	up, closed, expired := c.up, c.closed, c.expired
	c.mu.Unlock()
	switch {
	case closed:
		return 0, syscall.ECONNRESET
	case expired:
		return 0, os.ErrDeadlineExceeded
	}
	for {
		n, err := up.Read(b)
		c.mu.Lock()
		mute := c.mute
		c.mu.Unlock()
		if err != nil || !mute {
			return n, err
		}
	}
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		close(c.done)
	}
	c.closed = true
	c.cond.Broadcast()
	if c.up != nil {
		return c.up.Close()
	}
	return nil
}

func (c *fakeConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *fakeConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *fakeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expired = !t.IsZero() && !t.After(time.Now())
	c.cond.Broadcast()
	if c.up != nil {
		return c.up.SetReadDeadline(t)
	}
	return nil
}

func (c *fakeConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.up != nil {
		return c.up.SetWriteDeadline(t)
	}
	return nil
}

func (c *fakeConn) LocalAddr() net.Addr  { return addr("client") }
func (c *fakeConn) RemoteAddr() net.Addr { return addr(c.addr) }

// helloName returns the server name in a ClientHello record, or "" if it
// has none.
func helloName(rec []byte) (name string) {
	defer func() {
		if recover() != nil {
			name = "not a ClientHello"
		}
	}()
	b := rec[5:]
	if b[0] != 1 {
		return "not a ClientHello"
	}
	b = b[4+2+32:]                            // handshake header, version, random
	b = b[1+int(b[0]):]                       // session id
	b = b[2+int(binary.BigEndian.Uint16(b)):] // cipher suites
	b = b[1+int(b[0]):]                       // compression methods
	b = b[2:]                                 // length of the extensions
	for len(b) > 0 {
		typ, n := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		ext := b[4 : 4+n]
		b = b[4+n:]
		if typ == 0 { // server_name: list length, name type, name length, name
			return string(ext[5:])
		}
	}
	return ""
}

// modeRig is a dialer on a fake network in front of a node.
type modeRig struct {
	t     *testing.T
	node  *modeNode
	net   *fakeNet
	modes ModeStore
	cfg   Config
	d     *dialer
	first []byte
	rode  bool        // the first packet went out in a login
	back  chan []byte // what the chosen lane hands the pool
}

const modeNetwork = "cafe-wifi"

func newModeRig(t *testing.T, mod func(*Config)) *modeRig {
	t.Helper()
	r := &modeRig{
		t:     t,
		node:  startModeNode(t, 7),
		net:   &fakeNet{rules: map[string]sniRule{}, routes: map[string]string{}, delays: map[string]time.Duration{}},
		modes: NewMemoryModeStore(),
		back:  make(chan []byte, 16),
	}
	id, err := wire.NewKeyID(time.Now().Add(24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dk := wire.DeviceKey(r.node.secret, id)
	cfg := Config{
		Profile: Profile{
			Node: r.node.addr, CoverDomain: modeCover, KeyID: id[:], DeviceKey: dk[:],
			Pins: []string{modeTestCerts().pin}, BorrowedSNI: []string{modeBorrowed},
		},
		RootCAs:     modeTestCerts().roots,
		Network:     modeNetwork,
		Modes:       r.modes,
		DialContext: r.net.dial,
	}
	if mod != nil {
		mod(&cfg)
	}
	r.cfg = cfg
	if r.d, err = newDialer(cfg); err != nil {
		t.Fatal(err)
	}
	// A WireGuard handshake initiation, as the first packet usually is.
	r.first = make([]byte, 148)
	rand.Read(r.first)
	copy(r.first, []byte{1, 0, 0, 0})
	return r
}

// dial asks the dialer for the pool's first lane, the way the pool does.
func (r *modeRig) dial() (sched.PoolLane, error) {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var taken []byte
	l, err := r.d.dial(ctx, sched.DialRequest{
		Reason: "first",
		// As the pool's: whoever asks gets the same packet.
		TakeFirstPacket: func() []byte {
			if taken == nil {
				taken = r.first
			}
			return taken
		},
		Handler: lane.Handler{Data: func(_ *lane.Lane, pkt []byte) {
			select {
			case r.back <- bytes.Clone(pkt):
			default:
			}
		}},
	})
	if err != nil {
		return nil, err
	}
	r.t.Cleanup(func() { l.Close() })
	r.rode = taken != nil
	if taken == nil {
		// Nobody took the packet for a login, so it is still in the pool's
		// queue, and the pool sends it as soon as it has the lane.
		l.Send(r.first)
	}
	return l, nil
}

// mustDial dials and checks that the lane it got is logged in.
func (r *modeRig) mustDial() sched.PoolLane {
	r.t.Helper()
	l, err := r.dial()
	if err != nil {
		r.t.Fatal(err)
	}
	select {
	case <-l.Welcomed():
	case <-l.Done():
		r.t.Fatalf("the lane ended: %v", l.Err())
	case <-time.After(5 * time.Second):
		r.t.Fatal("the lane never logged in")
	}
	return l
}

func (r *modeRig) wantSent(names ...string) {
	r.t.Helper()
	if got := r.net.sent(); !slices.Equal(got, names) {
		r.t.Fatalf("ClientHellos sent: %q, want %q", got, names)
	}
}

func (r *modeRig) wantRemembered(mode SNIMode) {
	r.t.Helper()
	got, ok := r.modes.Mode(modeNetwork)
	if !ok || got.Mode != mode {
		r.t.Fatalf("remembered %+v (%v), want %v", got, ok, mode)
	}
	if mode == SNIBorrowed && got.Name != modeBorrowed {
		r.t.Fatalf("remembered the borrowed name %q", got.Name)
	}
}

// wantFirstPacket checks that the first packet went out in a login, or
// didn't; that the node's WireGuard got it from exactly sessions sessions,
// once each; and that its answer came back on the lane that was chosen.
func (r *modeRig) wantFirstPacket(inLogin bool, sessions int) {
	r.t.Helper()
	if r.rode != inLogin {
		r.t.Fatalf("the first packet rode in a login: %v, want %v", r.rode, inLogin)
	}
	select {
	case got := <-r.back:
		if !bytes.Equal(got, r.first) {
			r.t.Fatalf("the chosen lane delivered %x", got)
		}
	case <-time.After(5 * time.Second):
		r.t.Fatalf("no answer to the first packet on the chosen lane; WireGuard got it from %v", r.node.wg.copies(r.first))
	}
	time.Sleep(50 * time.Millisecond) // time for a second copy, were there one
	from := r.node.wg.copies(r.first)
	slices.Sort(from)
	if len(from) != sessions || len(slices.Compact(slices.Clone(from))) != sessions {
		r.t.Fatalf("WireGuard got the first packet from %v, want %d session(s), once each", from, sessions)
	}
}

func TestStallBound(t *testing.T) {
	d := &dialer{stallMin: modeStallMin, stallMax: modeStallMax}
	for connect, want := range map[time.Duration]time.Duration{
		0:                      2 * time.Second, // nothing measured: the least
		30 * time.Millisecond:  2 * time.Second,
		150 * time.Millisecond: 2 * time.Second,
		500 * time.Millisecond: 3 * time.Second, // six round trips
		800 * time.Millisecond: 4800 * time.Millisecond,
		2 * time.Second:        5 * time.Second, // the most
	} {
		if got := d.stallBound(connect); got != want {
			t.Errorf("stallBound(%v) = %v, want %v", connect, got, want)
		}
	}
}

// Where Own works it is chosen every time, and no other ClientHello is sent.
func TestModeOwnIsChosenWhereItWorks(t *testing.T) {
	for i := range 20 {
		r := newModeRig(t, nil)
		l := r.mustDial()
		r.wantSent(modeCover)
		r.wantRemembered(SNIOwn)
		r.wantFirstPacket(true, 1)
		if len(r.net.dialed()) != 1 {
			t.Fatalf("run %d: %d connections, want 1", i, len(r.net.dialed()))
		}
		l.Close()
	}
}

// A reset moves on at once, to Borrowed and no further. Own never got as
// far as its login, so the first packet rides in Borrowed's.
func TestModeFallsBackAtOnceWhenOwnIsReset(t *testing.T) {
	r := newModeRig(t, nil)
	r.net.rules[modeCover] = sniReset
	start := time.Now()
	r.mustDial()
	if took := time.Since(start); took >= r.d.stallMin {
		t.Fatalf("took %v: it waited instead of moving on", took)
	}
	r.wantSent(modeCover, modeBorrowed)
	r.wantRemembered(SNIBorrowed)
	r.wantFirstPacket(true, 1)
}

// So does a handshake that fails: here Own's certificate isn't trusted.
func TestModeFallsBackAtOnceWhenOwnHandshakeFails(t *testing.T) {
	r := newModeRig(t, func(cfg *Config) { cfg.RootCAs = x509.NewCertPool() })
	start := time.Now()
	r.mustDial()
	if took := time.Since(start); took >= r.d.stallMin {
		t.Fatalf("took %v: it waited instead of moving on", took)
	}
	r.wantSent(modeCover, modeBorrowed)
	r.wantRemembered(SNIBorrowed)
	r.wantFirstPacket(true, 1)
}

// So does a login that fails: here the cover name reaches a server that has
// the certificate but not the node's secret, and answers with its website.
// The first packet went out with that login. It must go again with the
// next one, and reach WireGuard once.
func TestModeFallsBackAtOnceWhenOwnLoginFails(t *testing.T) {
	r := newModeRig(t, nil)
	other := startModeNode(t, 9)
	r.net.routes[modeCover] = other.addr
	start := time.Now()
	r.mustDial()
	if took := time.Since(start); took >= r.d.stallMin {
		t.Fatalf("took %v: it waited instead of moving on", took)
	}
	r.wantSent(modeCover, modeBorrowed)
	r.wantRemembered(SNIBorrowed)
	r.wantFirstPacket(true, 1)
	if from := other.wg.copies(r.first); len(from) != 0 {
		t.Fatalf("the server that refused the login passed the first packet on: %v", from)
	}
}

// A blackholed ClientHello gets the wait, and then Borrowed is tried
// alongside it. With two attempts under way no login carries the first
// packet: it goes on the lane that is chosen.
func TestModeFallsBackAfterTheWaitWhenOwnIsBlackholed(t *testing.T) {
	r := newModeRig(t, nil)
	r.d.stallMin = 200 * time.Millisecond
	r.net.rules[modeCover] = sniDrop
	r.mustDial()
	r.wantSent(modeCover, modeBorrowed)
	r.wantRemembered(SNIBorrowed)
	r.wantFirstPacket(false, 1)
	dials := r.net.dialed()
	if gap := dials[1].began.Sub(dials[0].done); gap < r.d.stallMin || gap > 3*time.Second {
		t.Fatalf("Borrowed was tried %v after Own's ClientHello went out, want %v", gap, r.d.stallMin)
	}
	// The attempt that was given up on is closed, not left to hang.
	deadline := time.Now().Add(2 * time.Second)
	for !r.net.conns[0].isClosed() {
		if time.Now().After(deadline) {
			t.Fatal("the blackholed connection was left open")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The wait is six of the round trips the attempt's own TCP handshake took,
// when that is more than the least.
func TestModeWaitGrowsWithTheRoundTrip(t *testing.T) {
	r := newModeRig(t, nil)
	r.d.stallMin = 50 * time.Millisecond
	r.net.connectDelay = 60 * time.Millisecond
	r.net.rules[modeCover] = sniDrop
	r.mustDial()
	r.wantSent(modeCover, modeBorrowed)
	dials := r.net.dialed()
	if gap := dials[1].began.Sub(dials[0].done); gap < modeStallRTTs*r.net.connectDelay || gap > 3*time.Second {
		t.Fatalf("Borrowed was tried %v after Own's ClientHello went out, want %v or a little more",
			gap, modeStallRTTs*r.net.connectDelay)
	}
}

// None is tried only when Borrowed has failed too.
func TestModeNoneIsLast(t *testing.T) {
	r := newModeRig(t, nil)
	r.d.stallMin = 100 * time.Millisecond
	r.net.rules[modeCover] = sniDrop
	r.net.rules[modeBorrowed] = sniReset
	r.mustDial()
	r.wantSent(modeCover, modeBorrowed, "")
	r.wantRemembered(SNINone)
	r.wantFirstPacket(false, 1)
}

// With every mode blocked the dial fails, having tried each once, in order.
func TestModeAllBlocked(t *testing.T) {
	r := newModeRig(t, nil)
	for _, name := range []string{modeCover, modeBorrowed, ""} {
		r.net.rules[name] = sniReset
	}
	if _, err := r.dial(); err == nil {
		t.Fatal("dial succeeded with every mode blocked")
	}
	r.wantSent(modeCover, modeBorrowed, "")
	if c, ok := r.modes.Mode(modeNetwork); ok {
		t.Fatalf("remembered %+v", c)
	}
}

// A connection that fails before any ClientHello is sent says nothing about
// the name: no other mode is tried.
func TestModeConnectFailureTriesNoOtherMode(t *testing.T) {
	r := newModeRig(t, nil)
	r.net.connectErr = errors.New("connection refused")
	if _, err := r.dial(); err == nil {
		t.Fatal("dial succeeded")
	}
	if n := len(r.net.dialed()); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
	r.wantSent()
	if c, ok := r.modes.Mode(modeNetwork); ok {
		t.Fatalf("remembered %+v", c)
	}
}

// Own completes TLS and sends its login with the first packet, and the
// login vanishes. Borrowed is tried after the wait, counted from the login,
// and logs in. Its own login went out without the packet, which Own's
// attempt still had, so the packet follows on the lane once it is chosen.
func TestModeFirstPacketLeavesAStalledLogin(t *testing.T) {
	r := newModeRig(t, nil)
	r.d.stallMin = 200 * time.Millisecond
	r.net.rules[modeCover] = sniDropLogin
	r.net.delays[modeCover] = 150 * time.Millisecond // the handshake takes a while
	r.mustDial()
	r.wantSent(modeCover, modeBorrowed)
	r.wantRemembered(SNIBorrowed)
	r.wantFirstPacket(true, 1)
	dials := r.net.dialed()
	if gap, want := dials[1].began.Sub(dials[0].done), r.net.delays[modeCover]+r.d.stallMin; gap < want {
		t.Fatalf("Borrowed was tried %v after Own's ClientHello went out: the login didn't get a wait of its own (%v)", gap, want)
	}
}

// The case the client cannot tell from the last: Own's login arrives and
// is accepted, and nothing comes back. The node has passed the first
// packet on by then, which shows that it rides in the login and doesn't
// wait for WELCOME. It is sent again on the lane that is chosen rather
// than risk its loss, so here WireGuard gets it from two sessions: the one
// nobody is left in, and the one in use.
func TestModeFirstPacketWhenTheAnswerIsLost(t *testing.T) {
	r := newModeRig(t, nil)
	r.d.stallMin = 200 * time.Millisecond
	r.net.rules[modeCover] = sniDropAnswer
	r.mustDial()
	r.wantSent(modeCover, modeBorrowed)
	r.wantRemembered(SNIBorrowed)
	r.wantFirstPacket(true, 2)
}

// The same through the client's pool, with the waits as shipped: a packet
// written while the first lane is connecting reaches WireGuard although the
// client never hears WELCOME, and long before any other mode is tried.
func TestModeFirstPacketRidesInTheLogin(t *testing.T) {
	r := newModeRig(t, nil)
	r.net.connectDelay = 50 * time.Millisecond // time for the packet to be waiting
	r.net.rules[modeCover] = sniDropAnswer
	c, err := Dial(context.Background(), r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	if _, err := c.WriteTo(r.first, nil); err != nil {
		t.Fatal(err)
	}
	for len(r.node.wg.copies(r.first)) == 0 {
		if time.Since(start) > modeStallMin/2 {
			t.Fatal("the first packet didn't reach WireGuard with the first login")
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.wantSent(modeCover)
	if st := c.Stats(); st.Session != [16]byte{} {
		t.Fatalf("the client has a session, %x: the packet may have followed WELCOME", st.Session)
	}
}

// Own works, but slower than the wait allows, so Borrowed is tried
// alongside it. Own logs in first all the same and is the one kept. Neither
// login carried the first packet, so it is in one session only.
func TestModeSlowOwnIsKeptIfItLogsInFirst(t *testing.T) {
	r := newModeRig(t, nil)
	r.d.stallMin = 300 * time.Millisecond
	r.net.delays[modeCover] = 400 * time.Millisecond
	r.net.delays[modeBorrowed] = 5 * time.Second
	r.mustDial()
	r.wantSent(modeCover, modeBorrowed)
	r.wantRemembered(SNIOwn)
	r.wantFirstPacket(false, 1)
}

// A remembered mode is used directly. When it stops working it is
// forgotten, and the mode is worked out again, from Own if Own has not been
// blocked here lately: a cover domain this network reset is not sent again
// until ownBlockedFor has passed, and then it is tried first.
func TestModeRememberedThenForgotten(t *testing.T) {
	r := newModeRig(t, nil)
	r.net.rules[modeCover] = sniReset
	r.mustDial()
	r.wantSent(modeCover, modeBorrowed)
	r.wantRemembered(SNIBorrowed)

	r.mustDial()
	r.wantSent(modeCover, modeBorrowed, modeBorrowed)

	// The network changes its mind about both names.
	r.net.rules[modeCover] = sniPass
	r.net.rules[modeBorrowed] = sniReset
	for range modeFailLimit {
		if _, err := r.dial(); err == nil {
			t.Fatal("dial succeeded with the remembered mode blocked")
		}
	}
	if c, ok := r.modes.Mode(modeNetwork); ok {
		t.Fatalf("still remembers %+v after %d failures", c, modeFailLimit)
	}
	r.mustDial()
	r.wantSent(modeCover, modeBorrowed, modeBorrowed, modeBorrowed, modeBorrowed, modeBorrowed, "")
	r.wantRemembered(SNINone)

	// Hours later, None stops working too, and Own is tried again first.
	r.net.rules[""] = sniReset
	r.d.mu.Lock()
	r.d.ownBlocked[modeNetwork] = time.Now()
	r.d.mu.Unlock()
	for range modeFailLimit {
		r.dial()
	}
	r.mustDial()
	r.wantSent(modeCover, modeBorrowed, modeBorrowed, modeBorrowed, modeBorrowed, modeBorrowed, "", "", "", modeCover)
	r.wantRemembered(SNIOwn)
}

// A forced mode is used as it is, whatever happens to it.
func TestModeForced(t *testing.T) {
	r := newModeRig(t, func(cfg *Config) { cfg.SNIMode = SNINone })
	r.mustDial()
	r.wantSent("")
	if c, ok := r.modes.Mode(modeNetwork); ok {
		t.Fatalf("a forced mode was remembered: %+v", c)
	}

	r = newModeRig(t, func(cfg *Config) { cfg.SNIMode = SNIOwn })
	r.net.rules[modeCover] = sniReset
	if _, err := r.dial(); err == nil {
		t.Fatal("dial succeeded with the forced mode blocked")
	}
	r.wantSent(modeCover)
}

// A profile without a cover domain starts at Borrowed.
func TestModeOrderWithoutACoverDomain(t *testing.T) {
	r := newModeRig(t, func(cfg *Config) { cfg.Profile.CoverDomain = "" })
	r.mustDial()
	r.wantSent(modeBorrowed)
	r.wantRemembered(SNIBorrowed)
	r.wantFirstPacket(true, 1)
}

// Until an attempt is chosen nothing its lane receives reaches the pool,
// and what the others receive never does: they are in no session of the
// pool's.
func TestModeOnlyTheChosenLaneReachesThePool(t *testing.T) {
	var got []string
	note := func(what string) { got = append(got, what) }
	s := &modeSearch{req: sched.DialRequest{Handler: lane.Handler{
		Data:   func(*lane.Lane, []byte) { note("data") },
		Lost:   func(*lane.Lane, wire.Lost) { note("lost") },
		Retire: func(*lane.Lane) { note("retire") },
		Close:  func(*lane.Lane, wire.CloseReason) { note("close") },
		End:    func(*lane.Lane) { note("end") },
	}}}
	chosen, other := &attempt{}, &attempt{}
	all := func(a *attempt) {
		h := s.handler(a)
		h.Data(nil, []byte{1})
		h.Lost(nil, wire.Lost{})
		h.Retire(nil)
		h.Close(nil, wire.CloseNormal)
		h.End(nil)
	}
	all(chosen)
	all(other)
	if len(got) != 0 {
		t.Fatalf("before any attempt was chosen the pool got %v", got)
	}
	s.won.Store(chosen)
	all(other)
	if len(got) != 0 {
		t.Fatalf("the pool got %v from an attempt that wasn't chosen", got)
	}
	all(chosen)
	if want := []string{"data", "lost", "retire", "close", "end"}; !slices.Equal(got, want) {
		t.Fatalf("the pool got %v from the chosen lane, want %v", got, want)
	}
}

// Where the GFW resets the cover domain and then every connection to the
// node for a while, the client sends the cover domain once, waits the block
// out without touching the node, and then logs in with the borrowed name,
// which it remembers. It never sends the cover domain again: that would
// start the block over, for good.
func TestModeWaitsOutResidualCensorship(t *testing.T) {
	r := newModeRig(t, nil)
	r.net.rules[modeCover] = sniReset
	r.net.residual = 300 * time.Millisecond
	if _, err := r.dial(); err == nil {
		t.Fatal("logged in through a block on the address")
	}
	r.wantSent(modeCover, modeBorrowed, "")
	// While the block lasts, no lane is tried at all.
	if _, err := r.dial(); !errors.Is(err, errResidualWait) {
		t.Fatalf("dial while waiting: %v, want errResidualWait", err)
	}
	r.wantSent(modeCover, modeBorrowed, "")
	// Once it has passed, Borrowed is tried first and works.
	r.d.mu.Lock()
	r.d.quiet[modeNetwork] = time.Now()
	r.d.mu.Unlock()
	time.Sleep(r.net.residual)
	r.mustDial()
	r.wantSent(modeCover, modeBorrowed, "", modeBorrowed)
	r.wantRemembered(SNIBorrowed)
}

// A new Conn on that network, as a daemon makes after giving up on the last, shares its store: it
// neither sends the blocked name again, which would start the block over, nor dials while it lasts.
func TestModeANewConnKeepsWhatTheLastLearned(t *testing.T) {
	r := newModeRig(t, nil)
	r.net.rules[modeCover] = sniReset
	r.net.residual = 300 * time.Millisecond
	if _, err := r.dial(); err == nil {
		t.Fatal("logged in through a block on the address")
	}
	r.wantSent(modeCover, modeBorrowed, "")
	d, err := newDialer(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.d = d
	if _, err := r.dial(); !errors.Is(err, errResidualWait) {
		t.Fatalf("a new Conn dialed during the block: %v, want errResidualWait", err)
	}
	r.wantSent(modeCover, modeBorrowed, "")
	r.d.mu.Lock()
	r.d.quiet[modeNetwork] = time.Now()
	r.d.mu.Unlock()
	time.Sleep(r.net.residual)
	r.mustDial()
	r.wantSent(modeCover, modeBorrowed, "", modeBorrowed)
}

// A cover domain that was reset is not sent again on that network, even
// once the mode is worked out again from the start.
func TestModeDoesNotRetryABlockedCoverDomain(t *testing.T) {
	r := newModeRig(t, nil)
	r.net.rules[modeCover] = sniReset
	r.mustDial()
	r.wantSent(modeCover, modeBorrowed)
	r.modes.ForgetMode(modeNetwork)
	r.mustDial()
	r.wantSent(modeCover, modeBorrowed, modeBorrowed)
	// Another network is another matter.
	r.d.setNetwork("home", false)
	r.cfg.Network = "home"
	r.d.mu.Lock()
	r.d.network = "home"
	r.d.mu.Unlock()
	r.mustDial()
	r.wantSent(modeCover, modeBorrowed, modeBorrowed, modeCover, modeBorrowed)
}

// A network that is simply down blocks nothing: Own stays on the list.
func TestModeDownNetworkBlocksNothing(t *testing.T) {
	r := newModeRig(t, nil)
	r.net.connectErr = errors.New("network is unreachable")
	if _, err := r.dial(); err == nil {
		t.Fatal("dialled through a network that is down")
	}
	r.net.mu.Lock()
	r.net.connectErr = nil
	r.net.mu.Unlock()
	if _, err := r.dial(); errors.Is(err, errResidualWait) {
		t.Fatal("waiting out a block after the network was down")
	}
	r.wantSent(modeCover)
}

// Lanes spread across the node's addresses, one each, because a browser
// holds one connection open per address. The node needs no change: these
// are addresses it already answers on.
func TestLanesSpreadAcrossTheNodesAddresses(t *testing.T) {
	r := newModeRig(t, nil)
	// The same node, reached by a second address. The fake network dials
	// whatever it is given, so an alias stands in for a second IP.
	second := "alias." + r.node.addr
	r.net.routes[""] = r.node.addr // no SNI reaches the node either way
	r.cfg.Profile.Nodes = []string{second}
	d, err := newDialer(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.d = d
	if got := d.nodes; len(got) != 2 || got[0] != r.node.addr || got[1] != second {
		t.Fatalf("addresses %q", got)
	}

	// Four lanes, each taking the least used address: two per address.
	var released []func(ok bool)
	seen := map[string]int{}
	for range 4 {
		addr, release := d.takeAddr()
		seen[addr]++
		released = append(released, release)
	}
	if seen[r.node.addr] != 2 || seen[second] != 2 {
		t.Fatalf("four lanes landed %v, want two on each address", seen)
	}
	// As lanes end their addresses come free again, and the next lane
	// takes the one carrying the fewest.
	released[0](true)
	released[1](true) // both of the first address's, and both worked
	addr, _ := d.takeAddr()
	if addr != r.node.addr {
		t.Fatalf("after two lanes on %s ended, the next went to %s", r.node.addr, addr)
	}

	// An address whose lanes never log in is left alone, so it is not
	// picked again at once: it carries no lanes, and without this the
	// address with the fewest would always be the broken one.
	d.laneAddrs, d.addrBad, d.addrFails = map[string]int{}, map[string]time.Time{}, map[string]int{}
	for range 4 {
		a, done := d.takeAddr()
		done(a == second) // the first address is the broken one
	}
	for range 4 {
		if a, done := d.takeAddr(); a != second {
			done(false)
			t.Fatalf("a lane went to %s, the address whose lanes never logged in", a)
		} else {
			done(true)
		}
	}
	// Once every address is being left alone, the session still has
	// somewhere to go rather than refusing to dial.
	d.laneAddrs, d.addrBad, d.addrFails = map[string]int{}, map[string]time.Time{}, map[string]int{}
	for range 6 {
		_, done := d.takeAddr()
		done(false)
	}
	if a, done := d.takeAddr(); a == "" {
		t.Fatal("no address at all once they had all failed")
	} else {
		done(false)
	}

	// And a real pair of lanes reaches the node on different addresses.
	d.laneAddrs, d.addrBad, d.addrFails = map[string]int{}, map[string]time.Time{}, map[string]int{}
	r.modes.SetMode(modeNetwork, Choice{Mode: SNINone, Cover: modeCover, At: time.Now()})
	var addrs []string
	for range 2 {
		l := r.mustDial()
		t.Cleanup(func() { l.Close() })
		addrs = append(addrs, r.net.lastDialed())
	}
	if addrs[0] == addrs[1] {
		t.Fatalf("both lanes dialled %s", addrs[0])
	}
}

// On a network it hasn't seen, the first attempt races the node's addresses, as a browser does a
// name's, so a first address that swallows its SYNs costs a quarter of a second, not the dial.
func TestModeSearchRacesTheNodesAddresses(t *testing.T) {
	const dead = "192.0.2.1:443"
	r := newModeRig(t, nil)
	live := r.node.addr
	r.net.dead = map[string]bool{dead: true}
	r.cfg.Profile.Node, r.cfg.Profile.Nodes = dead, []string{live}
	d, err := newDialer(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.d = d
	start := time.Now()
	r.mustDial()
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the first lane took %v behind an address that never answers", took)
	}
	r.wantSent(modeCover)
	r.wantRemembered(SNIOwn)
	if got := r.net.lastDialed(); got != live {
		t.Fatalf("the lane went to %s, want %s", got, live)
	}
}

// While the client is waiting out a block on the node's address it opens
// CDN lanes without having given up on direct ones, and Stats must say so:
// it used to report "direct" for a session running over the CDN.
func TestModeStatsReportTheCarrierInUse(t *testing.T) {
	const edge = "edge.cdn.test"
	r := newModeRig(t, func(cfg *Config) {
		cfg.Profile.CDN = &CDNRoute{Host: edge, Path: "/socket", Edge: "127.0.0.1:9"}
	})
	if got, _ := r.d.state(); got != lane.Direct.String() {
		t.Fatalf("carrier %q before anything was blocked", got)
	}
	// A block on the address: every mode is reset as its ClientHello goes.
	for _, name := range []string{modeCover, modeBorrowed, ""} {
		r.net.rules[name] = sniReset
	}
	if _, err := r.dial(); err == nil {
		t.Fatal("logged in through a block on the address")
	}
	r.d.mu.Lock()
	quiet := r.d.quiet[modeNetwork]
	r.d.mu.Unlock()
	if quiet.IsZero() {
		t.Fatal("no wait on the address was started")
	}
	if got, _ := r.d.state(); got != lane.CDN.String() {
		t.Fatalf("carrier %q while waiting out a block with a CDN route, want cdn", got)
	}
	// Once the wait is over, direct lanes are the ones to report again.
	r.d.mu.Lock()
	r.d.quiet[modeNetwork] = time.Now()
	r.d.mu.Unlock()
	if got, _ := r.d.state(); got != lane.Direct.String() {
		t.Fatalf("carrier %q once the wait was over", got)
	}
}

// startImpostor runs a TLS server that is not the node: its certificate is
// self-signed for the cover domain, so it passes neither the check by name
// nor a pin, as an interceptor the device doesn't trust, or the wrong
// server, would.
func startImpostor(t *testing.T) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: modeCover}, DNSNames: []string{modeCover},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// A certificate that fails the check is an interceptor or the wrong
// server, not a censor. The search moves on as it does after a reset, but
// the cover domain is not marked blocked and no wait on the address starts.
// And since the CDN carrier checks its edge by name alone, which an
// interceptor the device trusts passes, new lanes stay off the CDN on that
// network however many direct lanes fail.
func TestModeRefusedCertificateIsNotABlock(t *testing.T) {
	const edge = "edge.cdn.test"
	r := newModeRig(t, func(cfg *Config) {
		cfg.Profile.CDN = &CDNRoute{Host: edge, Path: "/socket", Edge: "127.0.0.1:9"}
	})
	imp := startImpostor(t)
	for _, name := range []string{modeCover, modeBorrowed, ""} {
		r.net.routes[name] = imp
	}
	var want []string
	for range directFailLimit {
		if _, err := r.dial(); !errors.Is(err, lane.ErrCertificate) {
			t.Fatalf("%v, want lane.ErrCertificate", err)
		}
		// Each search tries every mode, Own first, and none goes by the CDN.
		want = append(want, modeCover, modeBorrowed, "")
		r.wantSent(want...)
	}
	r.d.mu.Lock()
	ownBlocked, quiet := r.d.ownBlocked[modeNetwork], r.d.quiet[modeNetwork]
	locked, onCDN := r.d.intercepted[modeNetwork], r.d.onCDN
	r.d.mu.Unlock()
	if !ownBlocked.IsZero() || !quiet.IsZero() {
		t.Fatalf("own blocked until %v, quiet until %v; want neither", ownBlocked, quiet)
	}
	// A certificate nothing trusts says nothing about the CDN either: the
	// edge is somewhere else, and whatever served this one cannot pass the
	// check by name a CDN lane makes. So the CDN is still on offer, and
	// once this many direct lanes have failed the client goes by it.
	if !locked.IsZero() {
		t.Fatalf("a certificate nothing trusts wrote the CDN off until %v", locked)
	}
	if !onCDN {
		t.Fatal("direct lanes kept failing on a certificate and the client never tried the CDN")
	}
	if _, err := r.dial(); err == nil {
		t.Fatal("the CDN lane reached a dead edge and succeeded")
	}
	want = append(want, edge)
	r.wantSent(want...)

	// A certificate the device itself trusts is another matter: only that
	// can sit in front of the CDN's edge too, so the CDN is written off.
	r.d.refused(modeNetwork, Choice{Mode: SNIOwn}, fmt.Errorf("a lane: %w", lane.ErrIntercepted))
	r.d.mu.Lock()
	locked = r.d.intercepted[modeNetwork]
	r.d.mu.Unlock()
	if locked.IsZero() {
		t.Fatal("a certificate the device trusts left the CDN on offer")
	}

	// Once the connections reach the node, Own works at once.
	r.net.mu.Lock()
	clear(r.net.routes)
	r.net.mu.Unlock()
	r.mustDial()
	r.wantSent(append(want, modeCover)...)
	r.wantRemembered(SNIOwn)

	// And a lane that logged in proves nothing is holding the TLS after
	// all, so the CDN comes back without waiting out the rest of the day.
	r.d.mu.Lock()
	locked = r.d.intercepted[modeNetwork]
	r.d.mu.Unlock()
	if !locked.IsZero() {
		t.Fatalf("the CDN is still written off until %v, after a lane logged in", locked)
	}
}

// A weaker mode that has run out is worked out again, and the mode the
// search settles on is settled from then. Keeping the time it ran out at
// would leave the choice stale for good: every later lane would search the
// modes again, which sends the cover domain to a network that resets it and
// takes every lane to the node's first address.
func TestModeThatRanOutSettlesAgain(t *testing.T) {
	// Own fails on its certificate, which says nothing about the network:
	// the cover domain is not written off, so the client does look at the
	// modes again once the weaker one it settled on has run out.
	r := newModeRig(t, func(cfg *Config) { cfg.RootCAs = x509.NewCertPool() })
	second := "alias." + r.node.addr
	// The fake network sends a ClientHello where its name routes, so an
	// alias stands in for the node's second IP.
	r.net.routes[modeBorrowed] = r.node.addr
	r.cfg.Profile.Nodes = []string{second}
	d, err := newDialer(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.d = d

	l := r.mustDial()
	t.Cleanup(func() { l.Close() })
	r.wantSent(modeCover, modeBorrowed)
	r.wantRemembered(SNIBorrowed)

	// Hours pass, so the client looks at the modes again.
	c, _ := r.modes.Mode(modeNetwork)
	c.At = time.Now().Add(-WeakerModeFor - time.Minute)
	r.modes.SetMode(modeNetwork, c)

	l2 := r.mustDial()
	t.Cleanup(func() { l2.Close() })
	r.wantSent(modeCover, modeBorrowed, modeCover, modeBorrowed)
	got, _ := r.modes.Mode(modeNetwork)
	if age := time.Since(got.At); age > time.Minute {
		t.Fatalf("the mode it settled on was settled %v ago: every lane from here searches again", age)
	}

	// So the lanes after it take the mode as it stands: one ClientHello
	// each, and none of them the cover domain's. Without that the search
	// runs again for every lane, which both tells the network the cover
	// domain is wanted here and keeps every lane on one address, since a
	// search dials the node's first address alone.
	for range 2 {
		l := r.mustDial()
		t.Cleanup(func() { l.Close() })
	}
	r.wantSent(modeCover, modeBorrowed, modeCover, modeBorrowed, modeBorrowed, modeBorrowed)
}
