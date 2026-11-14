package server

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/wire"
)

// flightConn holds what the client writes until flush, so that the
// client's Finished and the record after it reach the node together, the
// way a lane's HELLO does: in the flight after Finished, where TLS has it
// buffered by the time the handshake ends.
type flightConn struct {
	net.Conn
	mu      sync.Mutex
	writes  int
	flushed bool
	buf     []byte
}

func (c *flightConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	// The ClientHello goes out; everything after it waits for the flush,
	// so the rest of the client's handshake and its first record go in one
	// write. After the flush the connection is an ordinary one.
	if c.writes > 1 && !c.flushed {
		c.buf = append(c.buf, p...)
		c.mu.Unlock()
		return len(p), nil
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *flightConn) flush() error {
	c.mu.Lock()
	b := c.buf
	c.buf, c.flushed = nil, true
	c.mu.Unlock()
	_, err := c.Conn.Write(b)
	return err
}

// A first record that ends inside a tag that is right so far is a login's
// beginning, and the rest of it may be a round trip away. The node waits
// for that in the web server's read, where a web server waits for the rest
// of a request and its SETTINGS frame has gone out from a goroutine of its
// own. Waiting for it in the handshake instead, before any of that, keeps
// the frame in: the node would say nothing at all for as long as it waited,
// which no web server does.
func TestPartialHelloDoesNotHoldUpTheOpening(t *testing.T) {
	ts := newServerAs(t, httpServesTLSConns, nil)

	raw, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	raw.SetDeadline(time.Now().Add(20 * time.Second))
	fc := &flightConn{Conn: raw}
	c := tls.Client(fc, &tls.Config{RootCAs: certs(t).roots, ServerName: coverDomain, NextProtos: []string{"h2"}})
	t.Cleanup(func() { c.Close() })
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}

	frame := ts.hello(t, c)
	if _, err := c.Write(frame[:helloMin]); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := fc.flush(); err != nil {
		t.Fatal(err)
	}

	opening := make([]byte, len(ts.cover.opening))
	if _, err := io.ReadFull(c, opening); err != nil {
		t.Fatalf("the node said nothing after a partial HELLO: %v", err)
	}
	took := time.Since(start)
	if !bytes.Equal(opening, ts.cover.opening) {
		t.Fatalf("the node opened with % x, want the web server's % x", opening, ts.cover.opening)
	}
	// The whole point is that it does not wait for the rest of the tag
	// first; restOfTag is how long that wait would be.
	if took > restOfTag/4 {
		t.Fatalf("the node's opening took %v, which is the wait for the rest of the tag (%v), not a web server's answer", took, restOfTag)
	}

	// And the rest of the tag still logs the lane in, once it comes.
	if _, err := c.Write(frame[helloMin:]); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatalf("after the rest of the HELLO: %v", err)
	}
	if hdr[0] != wire.TypeWelcome {
		t.Fatalf("after the rest of the HELLO came % x, want WELCOME", hdr)
	}
	if n := ts.Stats().Sessions; n != 1 {
		t.Fatalf("%d sessions, want 1", n)
	}
}
