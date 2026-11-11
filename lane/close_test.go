package lane

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// recordsIn records the TLS records a connection reads, and whether it read
// to the end of the stream (a FIN).
type recordsIn struct {
	net.Conn
	mu   sync.Mutex
	buf  []byte
	lens []int
	eof  bool
}

func (c *recordsIn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, p[:n]...)
	for len(c.buf) >= 5 {
		l := int(binary.BigEndian.Uint16(c.buf[3:5]))
		if len(c.buf) < 5+l {
			break
		}
		c.lens = append(c.lens, l)
		c.buf = c.buf[5+l:]
	}
	if errors.Is(err, io.EOF) {
		c.eof = true
	}
	return n, err
}

func (c *recordsIn) seen() ([]int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.lens...), c.eof
}

// A client lane ends the way Chrome ends a connection: a FIN, and never a
// TLS close_notify, whose record (19 bytes with TLS 1.3's type and tag) no
// padded Tectonic record can be. The server still answers with its own
// close_notify, and both lanes end cleanly.
func TestClientRetiresWithoutCloseNotify(t *testing.T) {
	const alertRecord = 2 + 1 + 16
	var rec *recordsIn
	recd := make(chan struct{})
	n := newTestNode(t, func(n *testNode) {
		n.wrap = func(c net.Conn) net.Conn {
			rec = &recordsIn{Conn: c}
			close(recd)
			return rec
		}
	})
	cl := dial(t, n.dialConfig(t, SNIOwn))
	sl := n.acceptLane(t)
	waitWelcome(t, cl)
	<-recd
	for i := range 20 {
		cl.Send(bytes.Repeat([]byte{byte(i)}, 200))
	}
	cl.Retire()
	if err := waitDone(t, cl); err != nil {
		t.Fatalf("client lane err = %v, want clean retire", err)
	}
	if err := waitDone(t, sl); err != nil {
		t.Fatalf("server lane err = %v, want clean retire", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	lens, eof := rec.seen()
	for !eof && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		lens, eof = rec.seen()
	}
	if !eof {
		t.Fatal("the server never read the client's FIN")
	}
	for i, l := range lens {
		if l == alertRecord {
			t.Fatalf("client record %d of %d is %d bytes, an alert: %v", i+1, len(lens), l, lens)
		}
	}
}

// Ending a client lane at once sends no close_notify either.
func TestClientCloseSendsNoAlert(t *testing.T) {
	const alertRecord = 2 + 1 + 16
	var rec *recordsIn
	recd := make(chan struct{})
	n := newTestNode(t, func(n *testNode) {
		n.wrap = func(c net.Conn) net.Conn {
			rec = &recordsIn{Conn: c}
			close(recd)
			return rec
		}
	})
	cl := dial(t, n.dialConfig(t, SNIOwn))
	sl := n.acceptLane(t)
	waitWelcome(t, cl)
	<-recd
	cl.Close()
	waitDone(t, sl)
	lens, _ := rec.seen()
	for i, l := range lens {
		if l == alertRecord {
			t.Fatalf("client record %d of %d is %d bytes, an alert: %v", i+1, len(lens), l, lens)
		}
	}
}
