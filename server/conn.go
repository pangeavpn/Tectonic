package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pangeavpn/tectonic/wire"
)

const (
	// helloLen is the size of a HELLO frame.
	helloLen = wire.HeaderLen + wire.HelloLen
	// helloMin is how much of a HELLO frame the client's first TLS record
	// must hold for the connection to become a lane: every field and the
	// first 16 bytes of the tag, which only the holder of the device key
	// can produce. A HELLO that is all in one record is checked whole. One
	// whose record ends inside the tag is checked as far as it goes, and
	// the rest is waited for only if that much is right.
	helloMin = helloLen - wire.TagLen + 16
)

// startsHello reports whether b starts with a HELLO frame's header.
func startsHello(b []byte) bool {
	return len(b) >= wire.HeaderLen && b[0] == wire.TypeHello && binary.BigEndian.Uint16(b[1:]) == wire.HelloLen
}

// conn is a connection as the cover web server has it. It is the TLS
// connection and nothing else, with one exception: on a connection that
// negotiated HTTP/2, the web server's first read is where the node looks
// for a HELLO.
//
// The node never waits where a web server would not. The first read is the
// read the web server asked for, and it returns one TLS record. A record
// that isn't the start of a valid HELLO goes to the web server as it is, at
// once, so the web server answers or hangs up when it would have anyway.
//
// The check costs a few microseconds. It is made on every first record of
// an HTTP/2 connection, whatever is in it, so the time the first read takes
// does not depend on what the client sent.
type conn struct {
	*tls.Conn
	s   *Server
	raw net.Conn

	// Set once, when the handshake ends.
	ready    bool
	h2       bool   // negotiated HTTP/2: the first read is looked at
	tls13    bool   // and TLS 1.3: it can be a lane
	exporter []byte // what a HELLO on this connection is bound to

	// Reading is the web server's, one read at a time.
	read bool   // the first read has been made
	held []byte // read from the client and not yet given to the web server

	// mu orders the web server's writes and the hand-over to a lane.
	mu     sync.Mutex
	opened bool   // something has been written: on HTTP/2, the SETTINGS frame
	skip   []byte // written already on the web server's behalf (see cover.serve)
	// lane is set when a lane has the connection. The web server is still
	// letting go of it then, and nothing it does reaches the connection.
	lane atomic.Bool
}

// HandshakeContext runs the TLS handshake and then works out everything the
// first read will need that doesn't depend on what the client sends, so
// that none of it is done between the web server's first read and its first
// write.
func (c *conn) HandshakeContext(ctx context.Context) error {
	err := c.Conn.HandshakeContext(ctx)
	if err == nil {
		c.prepare()
	}
	return err
}

func (c *conn) prepare() {
	if c.ready {
		return
	}
	cs := c.Conn.ConnectionState()
	if !cs.HandshakeComplete {
		return
	}
	c.ready = true
	c.h2 = cs.NegotiatedProtocol == "h2"
	c.tls13 = cs.Version == tls.VersionTLS13
	if c.h2 {
		// TLS 1.2 without the extended master secret has no exporter; a
		// connection like that is never a lane, so any value will do.
		c.exporter, _ = cs.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
	}
}

func (c *conn) Read(p []byte) (int, error) {
	if !c.read {
		c.read = true
		c.prepare()
		if c.h2 {
			return c.firstRead(p)
		}
	}
	if len(c.held) > 0 {
		n := copy(p, c.held)
		c.held = c.held[n:]
		return n, nil
	}
	if c.lane.Load() {
		return 0, net.ErrClosed
	}
	return c.Conn.Read(p)
}

// firstRead makes the web server's first read and looks at what it brings.
func (c *conn) firstRead(p []byte) (int, error) {
	buf := make([]byte, max(len(p), helloLen))
	n, err := c.Conn.Read(buf)
	if n == 0 {
		return 0, err
	}
	if h, ok := c.login(buf, &n); ok {
		c.handOver(h, buf[helloLen:n])
		return 0, net.ErrClosed
	}
	// An error that came with data comes again on the next read.
	m := copy(p, buf[:n])
	c.held = buf[m:n]
	return m, nil
}

// login reports whether buf[:n], the client's first record, starts with a
// valid HELLO. If the record ends inside a tag that is right so far, login
// reads on for the rest and moves n along.
func (c *conn) login(buf []byte, n *int) (wire.Hello, bool) {
	got := buf[:min(*n, helloLen)]
	h, ok := c.s.checkHello(got[min(len(got), wire.HeaderLen):], c.exporter)
	if !ok || !c.tls13 || len(got) < helloMin || !startsHello(got) {
		return h, false
	}
	if len(got) == helloLen {
		return h, true
	}
	m, err := io.ReadAtLeast(c.Conn, buf[*n:], helloLen-*n)
	*n += m
	if err != nil {
		return h, false
	}
	return c.s.checkHello(buf[wire.HeaderLen:helloLen], c.exporter)
}

// handOver takes the connection from the web server and starts it as a
// lane. rest is what the client sent after HELLO in the bytes already read.
//
// A lane opens the way the web server opens any HTTP/2 connection, with its
// SETTINGS frame, and the client reads past it. The web server writes that
// frame from a goroutine of its own, so it may or may not have gone out yet.
// If it hasn't, the node writes the same bytes; the web server's own write
// then finds the connection gone.
func (c *conn) handOver(h wire.Hello, rest []byte) {
	c.mu.Lock()
	c.lane.Store(true)
	opened := c.opened
	c.mu.Unlock()

	tc := c.Conn
	tc.SetDeadline(time.Time{})
	if !opened {
		if _, err := tc.Write(c.s.cover.opening); err != nil {
			tc.Close()
			return
		}
	}
	var r io.Reader
	if len(rest) > 0 {
		r = io.MultiReader(bytes.NewReader(rest), tc)
	}
	if !c.s.startLane(tc, c.raw, r, h) {
		tc.Close()
	}
}

func (c *conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lane.Load() {
		return 0, net.ErrClosed
	}
	c.opened = true
	if len(c.skip) > 0 {
		k := min(len(p), len(c.skip))
		if !bytes.Equal(p[:k], c.skip[:k]) {
			c.skip = nil // not what was sent for it; nothing to drop
		} else {
			c.skip = c.skip[k:]
			if k == len(p) {
				return k, nil
			}
			n, err := c.Conn.Write(p[k:])
			return k + n, err
		}
	}
	return c.Conn.Write(p)
}

func (c *conn) Close() error {
	if c.lane.Load() {
		return nil
	}
	return c.Conn.Close()
}

func (c *conn) CloseWrite() error {
	if c.lane.Load() {
		return nil
	}
	return c.Conn.CloseWrite()
}

func (c *conn) SetDeadline(t time.Time) error {
	if c.lane.Load() {
		return nil
	}
	return c.Conn.SetDeadline(t)
}

func (c *conn) SetReadDeadline(t time.Time) error {
	if c.lane.Load() {
		return nil
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	if c.lane.Load() {
		return nil
	}
	return c.Conn.SetWriteDeadline(t)
}

// plainConn is a conn without the methods that show it is TLS. Before Go
// 1.27, net/http serves HTTP/2 on a connection it is handed only if the
// connection doesn't look like TLS.
type plainConn struct{ net.Conn }
