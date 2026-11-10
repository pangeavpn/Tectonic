// Package baseline models the transports Tectonic is benchmarked against.
//
// The real REALITY and AnyTLS servers cannot be linked into the benchmark, so
// this package reproduces the part of their behaviour that decides speed:
// every WireGuard datagram travels, in order, over ONE TLS 1.3 connection on
// ONE TCP connection, with each protocol's own framing and, for AnyTLS, its
// default padding scheme. A lost TCP segment therefore stalls every datagram
// behind it, which is exactly what Tectonic's lanes are meant to avoid.
//
// Neither model reproduces anything that only matters to censors (REALITY's
// handshake borrowing and authentication, AnyTLS's fallback); the client
// does send a Chrome ClientHello via uTLS so record and handshake sizes match.
package baseline

import (
	"bufio"
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
	"os"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Kind selects the transport model.
type Kind int

const (
	// Reality models VLESS over REALITY: after the TLS handshake the client
	// sends a VLESS request header (UDP command) and every datagram is a
	// 2-byte big-endian length followed by the payload, in both directions.
	// Writes are not coalesced, so each datagram becomes its own TLS record
	// with Go's default record sizing.
	Reality Kind = iota
	// AnyTLS models AnyTLS (protocol v2) carrying UDP with sing-box's
	// UDP-over-TCP v2 in connect mode: an authentication packet, a session
	// layer of 7-byte frames, and the default padding scheme on the client's
	// first eight writes.
	AnyTLS
)

func (k Kind) String() string {
	switch k {
	case Reality:
		return "reality"
	case AnyTLS:
		return "anytls"
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

// handshakeTimeout bounds the server's TLS handshake.
const handshakeTimeout = 10 * time.Second

// maxDatagram is the largest datagram the 2-byte length framing can carry.
const maxDatagram = 1<<16 - 1

// Serve accepts TLS connections on l until ctx is done, then closes l and
// every connection and returns nil. Each connection gets its own UDP socket
// dialled to wgAddr (normally a WireGuard server on loopback): datagrams from
// the client are written to it and everything read from it goes back to the
// client. It returns early only if Accept fails.
func Serve(ctx context.Context, kind Kind, l net.Listener, cert tls.Certificate, wgAddr *net.UDPAddr) error {
	if kind != Reality && kind != AnyTLS {
		return fmt.Errorf("baseline: unknown kind %v", kind)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS13,
	}
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	for {
		raw, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveConn(ctx, kind, tls.Server(raw, cfg), wgAddr)
		}()
	}
}

func serveConn(ctx context.Context, kind Kind, tc *tls.Conn, wgAddr *net.UDPAddr) {
	defer tc.Close()
	stop := context.AfterFunc(ctx, func() { tc.Close() })
	defer stop()
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		return
	}
	udp, err := net.DialUDP("udp", nil, wgAddr)
	if err != nil {
		return
	}
	defer udp.Close()
	udp.SetReadBuffer(4 << 20)
	udp.SetWriteBuffer(4 << 20)

	br := bufio.NewReaderSize(tc, 64<<10)
	var s serverSession
	switch kind {
	case Reality:
		s, err = acceptReality(tc, br)
	case AnyTLS:
		s, err = acceptAnyTLS(tc, br)
	}
	if err != nil {
		return
	}

	// UDP → TLS.
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer tc.Close()
		buf := make([]byte, maxDatagram)
		for {
			n, err := udp.Read(buf)
			if err != nil {
				return
			}
			if err := s.writeDatagram(buf[:n]); err != nil {
				return
			}
		}
	}()
	// TLS → UDP, until either side fails; then stop the other half.
	buf := make([]byte, maxDatagram)
	for {
		p, err := readDatagram(s.reader(), buf)
		if err == nil {
			_, err = udp.Write(p)
		}
		if err != nil {
			break
		}
	}
	tc.Close() // unblocks a write stuck on a peer that stopped reading
	udp.Close()
	<-done
}

// serverSession is the per-protocol half of a server connection after the
// protocol's preamble has been read.
type serverSession interface {
	reader() io.Reader // the datagram byte stream from the client
	writeDatagram(p []byte) error
}

// clientSession is the per-protocol half of a client connection.
type clientSession interface {
	reader() io.Reader
	writeDatagram(p []byte) error // called with packetConn.wmu held
}

// readDatagram reads one length-prefixed datagram into buf.
func readDatagram(r io.Reader, buf []byte) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	p := buf[:binary.BigEndian.Uint16(hdr[:])]
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return p, nil
}

// appendDatagram appends the length-prefixed framing of p to b.
func appendDatagram(b, p []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
	return append(b, p...)
}

// Dial opens one TLS connection with dial, presenting Chrome's ClientHello
// (uTLS HelloChrome_133) for serverName without verifying the certificate,
// runs the protocol's preamble and returns the datagram connection.
//
// WriteTo sends one datagram over the connection whatever the address;
// ReadFrom returns datagrams with the TCP connection's remote address.
// Closing the PacketConn closes the TLS connection. There is no reconnect:
// once the connection fails every call returns the error.
func Dial(ctx context.Context, kind Kind, dial func(ctx context.Context) (net.Conn, error), serverName string) (net.PacketConn, error) {
	if kind != Reality && kind != AnyTLS {
		return nil, fmt.Errorf("baseline: unknown kind %v", kind)
	}
	raw, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	uc := utls.UClient(raw, &utls.Config{ServerName: serverName, InsecureSkipVerify: true}, utls.HelloChrome_133)
	if err := uc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("baseline: TLS handshake: %w", err)
	}
	c := &packetConn{
		conn:    uc,
		remote:  raw.RemoteAddr(),
		in:      make(chan []byte, 512),
		done:    make(chan struct{}),
		closing: make(chan struct{}),
		rdl:     makeDeadline(),
	}
	br := bufio.NewReaderSize(uc, 64<<10)
	switch kind {
	case Reality:
		c.s = newRealityClient(uc, br)
	case AnyTLS:
		c.s, err = newAnyTLSClient(uc, br, &c.wmu)
	}
	if err != nil {
		uc.Close()
		return nil, err
	}
	go c.readLoop()
	return c, nil
}

// packetConn is the client's datagram connection. A goroutine parses
// datagrams off the TLS stream into a channel, so read deadlines never
// interrupt the parser mid-frame.
type packetConn struct {
	conn   net.Conn
	remote net.Addr
	s      clientSession

	wmu sync.Mutex // serializes writes to conn

	in        chan []byte
	done      chan struct{} // closed when readLoop exits
	readErr   error         // why readLoop exited; set before done closes
	closing   chan struct{}
	closeOnce sync.Once
	rdl       deadline
}

func (c *packetConn) readLoop() {
	defer close(c.done)
	r := c.s.reader()
	buf := make([]byte, maxDatagram)
	for {
		p, err := readDatagram(r, buf)
		if err != nil {
			select {
			case <-c.closing:
				err = net.ErrClosed
			default:
				if errors.Is(err, io.EOF) {
					err = io.ErrUnexpectedEOF
				}
			}
			c.readErr = err
			return
		}
		select {
		case c.in <- append([]byte(nil), p...):
		case <-c.closing:
			c.readErr = net.ErrClosed
			return
		}
	}
}

// ReadFrom implements net.PacketConn.
func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case b := <-c.in:
		return copy(p, b), c.remote, nil
	default:
	}
	select {
	case b := <-c.in:
		return copy(p, b), c.remote, nil
	case <-c.done:
		select {
		case b := <-c.in:
			return copy(p, b), c.remote, nil
		default:
		}
		return 0, nil, c.opError("read", c.readErr)
	case <-c.rdl.wait():
		return 0, nil, c.opError("read", os.ErrDeadlineExceeded)
	}
}

// WriteTo implements net.PacketConn. addr is ignored.
func (c *packetConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if len(p) > maxDatagram {
		return 0, c.opError("write", fmt.Errorf("datagram of %d bytes exceeds %d", len(p), maxDatagram))
	}
	select {
	case <-c.closing:
		return 0, c.opError("write", net.ErrClosed)
	default:
	}
	c.wmu.Lock()
	err := c.s.writeDatagram(p)
	c.wmu.Unlock()
	if err != nil {
		return 0, c.opError("write", err)
	}
	return len(p), nil
}

func (c *packetConn) opError(op string, err error) error {
	return &net.OpError{Op: op, Net: "baseline", Source: c.conn.LocalAddr(), Addr: c.remote, Err: err}
}

// Close implements net.PacketConn.
func (c *packetConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closing)
		err = c.conn.Close()
	})
	return err
}

func (c *packetConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *packetConn) SetDeadline(t time.Time) error {
	c.rdl.set(t)
	return c.conn.SetWriteDeadline(t)
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.rdl.set(t)
	return nil
}

func (c *packetConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// deadline is a resettable timer whose channel closes when it fires, in the
// style of net.Pipe's deadlines.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func makeDeadline() deadline { return deadline{cancel: make(chan struct{})} }

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // the timer fired; wait for it to close cancel
	}
	d.timer = nil
	closed := isClosed(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(cancel) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *deadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// SelfSignedCert returns a fresh ECDSA P-256 certificate for host (a DNS
// name or IP address), valid for a year.
func SelfSignedCert(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
