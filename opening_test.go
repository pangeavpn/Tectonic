package tectonic_test

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic"
)

// recordTap sits on the path between a client and a node and notes what
// anything there can see of TLS: each record's direction, content type and
// length, in the order they pass. Records that arrive together are noted
// and passed on together, so nothing the far end sends in reply is noted
// ahead of them.
type recordTap struct {
	addr string

	mu    sync.Mutex
	conns [][]tapRecord
}

type tapRecord struct {
	fromClient bool
	typ        byte
	n          int // the length in the record header
}

const (
	tlsHeaderLen   = 5
	tlsApplication = 23
)

func newRecordTap(t *testing.T, upstream string) *recordTap {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tap := &recordTap{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", upstream)
			if err != nil {
				c.Close()
				continue
			}
			tap.mu.Lock()
			id := len(tap.conns)
			tap.conns = append(tap.conns, nil)
			tap.mu.Unlock()
			go tap.relay(id, u, c, true)
			go tap.relay(id, c, u, false)
		}
	}()
	return tap
}

func (tap *recordTap) relay(id int, dst, src net.Conn, fromClient bool) {
	defer dst.Close()
	defer src.Close()
	br := bufio.NewReaderSize(src, 256<<10)
	// whole reports the size of the record at the front of the buffer, if
	// all of it is there.
	whole := func() (int, bool) {
		if br.Buffered() < tlsHeaderLen {
			return 0, false
		}
		hdr, _ := br.Peek(tlsHeaderLen)
		n := tlsHeaderLen + int(hdr[3])<<8 + int(hdr[4])
		return n, br.Buffered() >= n
	}
	var out []byte
	for {
		hdr, err := br.Peek(tlsHeaderLen)
		if err != nil {
			return
		}
		rec, err := br.Peek(tlsHeaderLen + int(hdr[3])<<8 + int(hdr[4]))
		if err != nil {
			return
		}
		tap.mu.Lock()
		tap.conns[id] = append(tap.conns[id], tapRecord{fromClient, rec[0], len(rec) - tlsHeaderLen})
		tap.mu.Unlock()
		out = append(out, rec...)
		br.Discard(len(rec))
		if _, more := whole(); more {
			continue
		}
		if _, err := dst.Write(out); err != nil {
			return
		}
		out = out[:0]
	}
}

// opening is the application records of one connection, in each direction,
// that followed the client's Finished, as record lengths on the wire; and
// which of the client's came after the server's first.
type opening struct {
	client, server []int
	afterServer    []bool // for each of client: the server had spoken
}

func (tap *recordTap) openings() []opening {
	tap.mu.Lock()
	defer tap.mu.Unlock()
	var out []opening
	for _, recs := range tap.conns {
		var o opening
		finished := false
		for _, r := range recs {
			switch {
			case r.typ != tlsApplication:
			case !finished:
				// In TLS 1.3 the client's first encrypted record is its
				// Finished, and everything the server sent before it is
				// handshake.
				finished = r.fromClient
			case r.fromClient:
				o.client = append(o.client, r.n)
				o.afterServer = append(o.afterServer, len(o.server) > 0)
			default:
				o.server = append(o.server, r.n)
			}
		}
		out = append(out, o)
	}
	return out
}

// On the wire, every lane starts with the records a Chromium browser and an
// HTTP/2 server start with. This is the real client against the real node,
// with real TLS in between: the node finds HELLO although it begins in one
// TLS record and ends in the next, and the first WireGuard packet still
// leaves with it.
//
// Record lengths are as an observer reads them, 17 bytes more than what is
// inside: the client's 87 (Chrome's preface, SETTINGS and WINDOW_UPDATE),
// then 460 to 470 (the HEADERS of its first GET), then 26 (its SETTINGS
// ACK) once the server has spoken; the server's 39 (SETTINGS ACK and
// WINDOW_UPDATE), then 108 to 109 (response HEADERS), then the page.
func TestLanesOpenLikeChromeOnTheWire(t *testing.T) {
	wg, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()
	n := startNode(t, wg.LocalAddr().String(), nil)
	tap := newRecordTap(t, n.addr)
	p := n.profile(t)
	p.Node = tap.addr
	c, err := tectonic.Dial(context.Background(), tectonic.Config{
		Profile: p, RootCAs: certs().roots, Network: "test-net", SNIMode: tectonic.SNIOwn,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	initiation := make([]byte, 148)
	initiation[0] = 1
	if _, err := c.WriteTo(initiation, nil); err != nil {
		t.Fatal(err)
	}
	wg.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 2048)
	if n, _, err := wg.ReadFrom(buf); err != nil || !bytes.Equal(buf[:n], initiation) {
		t.Fatalf("the first WireGuard packet did not reach the node: %d bytes, %v", n, err)
	}

	// The second lane resumes TLS; it must open the same way.
	const lanes = 2
	var got []opening
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		got = tap.openings()
		done := 0
		for _, o := range got {
			if o.ack() >= 0 && len(o.reply()) >= 3 {
				done++
			}
		}
		if done >= lanes {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("saw %d lanes open in full, want %d: %+v", done, lanes, got)
		}
	}
	for i, o := range got[:lanes] {
		t.Logf("lane %d: client %v, server %v", i+1, o.client, o.server)
		if len(o.client) < 3 || o.client[0] != 87 || o.client[1] < 460 || o.client[1] > 470 {
			t.Errorf("lane %d: the client's records begin %v, want 87, then 460 to 470", i+1, o.client)
		}
		if o.ack() < 0 {
			t.Errorf("lane %d: none of the client's records %v is a 26 that follows the server's first bytes (which do: %v)",
				i+1, o.client, o.afterServer)
		}
		if s := o.reply(); len(s) < 3 || s[0] != 39 || s[1] < 108 || s[1] > 109 || s[2] < 1090+17 || s[2] > 4090+17+3 {
			t.Errorf("lane %d: the server's records begin %v, want 39, then 108 to 109, then 1107 to 4110", i+1, o.server)
		}
	}
}

// ack is which of the client's records is the one that ends its opening: a
// 26 sent after the server's first bytes, or -1. A packet the tunnel sends
// in the meantime may come before it.
func (o opening) ack() int {
	for i := 2; i < len(o.client); i++ {
		if o.client[i] == 26 && o.afterServer[i] {
			return i
		}
	}
	return -1
}

// reply is the server's records from the lane's opening on. A node that
// answers the TLS handshake with an HTTP/2 SETTINGS frame of its own, as a
// web server does, sends that 62-byte record first; it is no part of the
// lane's opening.
func (o opening) reply() []int {
	if len(o.server) > 0 && o.server[0] == 62 {
		return o.server[1:]
	}
	return o.server
}
