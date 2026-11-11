package tectonic_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

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
// ACK) once the server has spoken. The server's are the web server's own
// SETTINGS, then the records the node's cover web server answers a page
// load with (its WINDOW_UPDATE, SETTINGS ACK, the response's HEADERS and
// DATA, grouped as it happens to group them): together they hold what a
// browser loading the page is sent, give or take a byte of the Date header.
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

	// A visitor loads the page through the tap first, opening the
	// connection as Chrome does.
	vc, err := tls.Dial("tcp", tap.addr, &tls.Config{RootCAs: certs().roots, ServerName: p.CoverDomain, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range chromeOpening(p.CoverDomain) {
		vc.Write(rec)
	}
	vc.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		hdr := make([]byte, 9)
		if _, err := io.ReadFull(vc, hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(io.Discard, vc, int64(hdr[0])<<16|int64(hdr[1])<<8|int64(hdr[2])); err != nil {
			t.Fatal(err)
		}
		if hdr[3] == 0x0 && hdr[4]&0x1 != 0 { // DATA that ends the page
			break
		}
	}
	vc.Close()
	page := -1
	for deadline := time.Now().Add(5 * time.Second); page < 0; time.Sleep(5 * time.Millisecond) {
		if got := tap.openings(); len(got) > 0 && len(got[0].reply()) > 0 {
			page = 0
			for _, n := range got[0].reply() {
				page += n - 17
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the visitor's page load never passed the tap")
		}
	}
	visits := len(tap.openings())

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
		got = tap.openings()[visits:]
		done := 0
		for _, o := range got {
			if o.ack() >= 0 && o.carries(page) >= 0 {
				done++
			}
		}
		if done >= lanes {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("saw %d lanes open in full, want %d (the page is %d bytes): %+v", done, lanes, page, got)
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
		if len(o.server) == 0 || o.server[0] != 62 {
			t.Errorf("lane %d: the server's records begin %v, want the web server's SETTINGS (62)", i+1, o.server)
		}
	}
}

// carries reports how many of the server's records after its SETTINGS hold,
// together, what a visitor loading the page is sent (give or take two
// bytes), or -1 if no run of them from the first does.
func (o opening) carries(page int) int {
	total := 0
	for i, n := range o.reply() {
		total += n - 17
		if total >= page-2 && total <= page+2 {
			return i + 1
		}
	}
	return -1
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

// chromeOpening is what Chrome sends first when it loads https://authority/,
// in its two TLS records: the preface with its SETTINGS and WINDOW_UPDATE,
// then the request.
func chromeOpening(authority string) [2][]byte {
	frame := func(b []byte, typ, flags byte, stream uint32, payload []byte) []byte {
		b = append(b, byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload)), typ, flags)
		b = binary.BigEndian.AppendUint32(b, stream)
		return append(b, payload...)
	}
	var settings []byte
	for _, s := range [][2]uint32{{0x1, 65536}, {0x2, 0}, {0x4, 6291456}, {0x6, 262144}} {
		settings = binary.BigEndian.AppendUint16(settings, uint16(s[0]))
		settings = binary.BigEndian.AppendUint32(settings, s[1])
	}
	first := frame([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 0x4, 0, 0, settings)
	first = frame(first, 0x8, 0, 0, binary.BigEndian.AppendUint32(nil, 15663105))
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{
		{":method", "GET"}, {":authority", authority}, {":scheme", "https"}, {":path", "/"},
		{"sec-ch-ua", `"Chromium";v="157", "Not?A_Brand";v="8"`},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", `"Windows"`},
		{"upgrade-insecure-requests", "1"},
		{"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"sec-fetch-dest", "document"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", "en-US,en;q=0.9"},
		{"priority", "u=0, i"},
	} {
		enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	req := frame(nil, 0x1, 0x1|0x4|0x20, 1, append([]byte{0x80, 0, 0, 0, 255}, hb.Bytes()...))
	return [2][]byte{first, req}
}
