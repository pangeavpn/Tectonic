package server

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/lane"
	"github.com/pangeavpn/tectonic/wire"
)

// These tests hold the node to what a net/http server with the same
// settings does for a client that doesn't log in: what it sends first, when
// it gives up on a client that stalls, and how it closes.

// newServerAs is newTestServer with the choice New makes from the Go
// version: whether the web server is given each connection whole (direct)
// or the way it has to be before Go 1.27.
func newServerAs(t *testing.T, direct bool, mod func(*Config)) *testServer {
	t.Helper()
	p := certs(t)
	wg := newFakeWG(t)
	secret := []byte("0123456789abcdef0123456789abcdef")
	cfg := Config{
		NodeSecret:         secret,
		CoverDomain:        coverDomain,
		OwnCertificate:     func() (*tls.Certificate, error) { return &p.own, nil },
		DefaultCertificate: func() (*tls.Certificate, error) { return &p.def, nil },
		Cover:              http.HandlerFunc(coverPage),
		WireGuard:          wg.conn.LocalAddr().String(),
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := newServer(cfg, direct)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })
	return &testServer{Server: s, addr: ln.Addr().String(), wg: wg, secret: secret}
}

func coverPage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "cover page %s tls=%v", r.Proto, r.TLS != nil)
}

// newStockServer is a plain net/http HTTPS server set up as the cover is.
func newStockServer(t *testing.T, headerTimeout time.Duration) string {
	t.Helper()
	p := certs(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(coverPage),
		ReadHeaderTimeout: headerTimeout,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(io.Discard, "", 0),
		TLSConfig: &tls.Config{
			MinVersion:                  tls.VersionTLS12,
			NextProtos:                  []string{"h2", "http/1.1"},
			Certificates:                []tls.Certificate{p.own},
			DynamicRecordSizingDisabled: true,
		},
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// tapConn keeps what the server sent, so a test can see the TLS records.
type tapConn struct {
	net.Conn
	mu sync.Mutex
	in []byte
}

func (c *tapConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.in = append(c.in, p[:n]...)
	c.mu.Unlock()
	return n, err
}

// closedWithAlert reports whether the last record the server sent is a TLS
// alert: 19 bytes of encrypted record in TLS 1.3, 26 in TLS 1.2.
func (c *tapConn) closedWithAlert() bool {
	c.mu.Lock()
	b := c.in
	c.mu.Unlock()
	typ, size := 0, 0
	for len(b) >= 5 {
		typ, size = int(b[0]), int(b[3])<<8|int(b[4])
		if len(b) < 5+size {
			return false
		}
		b = b[5+size:]
	}
	return (typ == 23 && size == 19) || (typ == 21 && size == 26)
}

type probeClient struct {
	*tls.Conn
	tap   *tapConn
	since time.Time // when the handshake ended
}

func probeDial(t *testing.T, addr string, maxVersion uint16, alpn ...string) *probeClient {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tap := &tapConn{Conn: raw}
	c := tls.Client(tap, &tls.Config{RootCAs: certs(t).roots, ServerName: coverDomain, NextProtos: alpn, MaxVersion: maxVersion})
	t.Cleanup(func() { c.Close() })
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	return &probeClient{Conn: c, tap: tap, since: time.Now()}
}

// outcome is what a client saw of a connection the server ended.
type outcome struct {
	read  string
	alert bool
	after time.Duration
	err   error
}

// untilClosed reads until the server closes the connection.
func (c *probeClient) untilClosed(limit time.Duration) outcome {
	c.SetReadDeadline(time.Now().Add(limit))
	b, err := io.ReadAll(c.Conn)
	return outcome{read: string(b), alert: c.tap.closedWithAlert(), after: time.Since(c.since), err: err}
}

// readFrame reads one HTTP/2 frame and returns all of it.
func readFrame(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 9)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	f := append(hdr, make([]byte, int(hdr[0])<<16|int(hdr[1])<<8|int(hdr[2]))...)
	_, err := io.ReadFull(r, f[9:])
	return f, err
}

func TestHTTP2ServerSpeaksFirst(t *testing.T) {
	stock := newStockServer(t, 10*time.Second)
	for _, direct := range modes() {
		ts := newServerAs(t, direct, nil)
		for name, version := range map[string]uint16{"TLS 1.3": tls.VersionTLS13, "TLS 1.2": tls.VersionTLS12} {
			t.Run(fmt.Sprintf("direct=%v/%s", direct, name), func(t *testing.T) {
				var first [2][]byte
				for i, addr := range []string{ts.addr, stock} {
					c := probeDial(t, addr, version, "h2")
					c.SetReadDeadline(time.Now().Add(2 * time.Second))
					f, err := readFrame(c)
					if err != nil {
						t.Fatalf("server %d sent nothing to a silent HTTP/2 client: %v", i, err)
					}
					first[i] = f
				}
				if !isSettings(first[0]) || !bytes.Equal(first[0], first[1]) {
					t.Fatalf("node opened with % x, net/http with % x", first[0], first[1])
				}
				if !bytes.Equal(first[0], ts.cover.opening) {
					t.Fatalf("node opened with % x, but keeps % x for lanes", first[0], ts.cover.opening)
				}
			})
		}
	}
}

// modes is the ways the web server can be given its connections that this
// version of Go can do.
func modes() []bool {
	if httpServesTLSConns {
		return []bool{true, false}
	}
	return []bool{false}
}

func TestStalledClientGetsOneTimeout(t *testing.T) {
	const timeout = 600 * time.Millisecond
	stock := newStockServer(t, timeout)
	shaped := append([]byte{wire.TypeHello, 0, wire.HelloLen}, bytes.Repeat([]byte{'x'}, wire.HelloLen)...)
	for _, direct := range modes() {
		ts := newServerAs(t, direct, func(c *Config) { c.HandshakeTimeout = timeout })
		for name, sends := range map[string][]byte{
			"says nothing":           nil,
			"starts a HELLO":         {wire.TypeHello, 0, wire.HelloLen},
			"a HELLO-sized line":     shaped,
			"a request line, no end": []byte("GET / HTTP/1.1\r\n"),
		} {
			t.Run(fmt.Sprintf("direct=%v/%s", direct, name), func(t *testing.T) {
				var got [2]outcome
				var wg sync.WaitGroup
				for i, addr := range []string{ts.addr, stock} {
					c := probeDial(t, addr, tls.VersionTLS13, "http/1.1")
					if len(sends) > 0 {
						c.Write(sends)
					}
					wg.Add(1)
					go func() { defer wg.Done(); got[i] = c.untilClosed(5 * time.Second) }()
				}
				wg.Wait()
				node, ref := got[0], got[1]
				if node.err != nil || ref.err != nil {
					t.Fatalf("read: node %v, net/http %v", node.err, ref.err)
				}
				if node.read != ref.read {
					t.Fatalf("node answered %q, net/http %q", node.read, ref.read)
				}
				if !ref.alert || !node.alert {
					t.Fatalf("closed with a TLS alert: node %v, net/http %v", node.alert, ref.alert)
				}
				// Twice the timeout is what waiting first for a HELLO and
				// then for a request would take.
				if node.after < timeout-100*time.Millisecond || node.after > timeout+timeout/2 {
					t.Fatalf("node closed after %v, net/http after %v; the timeout is %v", node.after, ref.after, timeout)
				}
			})
		}
	}
}

// hello returns a HELLO frame that logs in on c.
func (ts *testServer) hello(t *testing.T, c *tls.Conn) []byte {
	t.Helper()
	id, dk := ts.credential(t)
	cs := c.ConnectionState()
	exporter, err := cs.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
	if err != nil {
		t.Fatal(err)
	}
	h := wire.Hello{Version: wire.Version, KeyID: id, Timestamp: uint64(time.Now().Unix())}
	h.Sign(wire.LaneKey(dk, exporter))
	return wire.AppendFrame(nil, wire.TypeHello, h.AppendBody(nil))
}

// wantLane checks that the server answers as a lane does: the web server's
// SETTINGS frame, once, and then WELCOME.
func (ts *testServer) wantLane(t *testing.T, c *probeClient) {
	t.Helper()
	got := make([]byte, len(ts.cover.opening)+wire.HeaderLen)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("lane opening: %v after % x", err, got)
	}
	if !bytes.Equal(got[:len(ts.cover.opening)], ts.cover.opening) {
		t.Fatalf("lane opened with % x, want the web server's SETTINGS % x", got, ts.cover.opening)
	}
	if got[len(ts.cover.opening)] != wire.TypeWelcome {
		t.Fatalf("after SETTINGS came % x, want WELCOME", got[len(ts.cover.opening):])
	}
}

func TestLaneOpensWithSettingsThenWelcome(t *testing.T) {
	for _, direct := range modes() {
		t.Run(fmt.Sprintf("direct=%v", direct), func(t *testing.T) {
			ts := newServerAs(t, direct, nil)
			// The web server writes SETTINGS from a goroutine of its own, so
			// whether it or the node gets there first varies; either way
			// the frame is sent once.
			for range 40 {
				c := probeDial(t, ts.addr, 0, "h2")
				c.Write(ts.hello(t, c.Conn))
				ts.wantLane(t, c)
				c.Close()
			}
		})
	}
}

func TestHelloAcrossTwoRecords(t *testing.T) {
	for _, direct := range modes() {
		t.Run(fmt.Sprintf("direct=%v", direct), func(t *testing.T) {
			ts := newServerAs(t, direct, nil)
			c := probeDial(t, ts.addr, 0, "h2")
			frame := ts.hello(t, c.Conn)
			c.Write(frame[:helloMin])
			time.Sleep(50 * time.Millisecond)
			c.Write(frame[helloMin:])
			ts.wantLane(t, c)
		})
	}
}

// A first record that is not the start of a valid HELLO is the web server's
// at once. net/http hangs up on an HTTP/2 client whose first 24 bytes are
// not the preface, and so must the node, without first waiting for the rest
// of a HELLO that is not coming.
func TestBadHelloIsNotWaitedFor(t *testing.T) {
	stock := newStockServer(t, 10*time.Second)
	ts := newServerAs(t, httpServesTLSConns, nil)
	random := func(n int) []byte {
		b := make([]byte, n)
		rand.Read(b)
		return append([]byte{wire.TypeHello, 0, wire.HelloLen}, b...)
	}
	for name, first := range map[string]func(*tls.Conn) []byte{
		"24 bytes": func(*tls.Conn) []byte { return random(24 - wire.HeaderLen) },
		"wrong tag, record ends in it": func(c *tls.Conn) []byte {
			f := ts.hello(t, c)[:helloMin+5]
			f[helloMin-1] ^= 1
			return f
		},
		"right so far but too short": func(c *tls.Conn) []byte { return ts.hello(t, c)[:helloMin-1] },
		"whole and wrong":            func(*tls.Conn) []byte { return random(wire.HelloLen) },
	} {
		t.Run(name, func(t *testing.T) {
			for i, addr := range []string{ts.addr, stock} {
				c := probeDial(t, addr, tls.VersionTLS13, "h2")
				c.Write(first(c.Conn))
				got := c.untilClosed(5 * time.Second)
				if got.err != nil || got.after > 2*time.Second {
					t.Fatalf("server %d: still open after %v (%v)", i, got.after, got.err)
				}
			}
			if ts.Stats().Sessions != 0 {
				t.Fatal("a bad HELLO opened a session")
			}
		})
	}
}

// A direct lane negotiates HTTP/2, as the client always does. On any other
// connection a HELLO is only a bad HTTP request.
func TestHelloNeedsHTTP2(t *testing.T) {
	ts := newServerAs(t, httpServesTLSConns, nil)
	c := probeDial(t, ts.addr, tls.VersionTLS13, "http/1.1")
	c.Write(append(ts.hello(t, c.Conn), "\r\n\r\n"...))
	got := c.untilClosed(5 * time.Second)
	if want := "HTTP/1.1 400 Bad Request"; len(got.read) < len(want) || got.read[:len(want)] != want {
		t.Fatalf("got %q, want a 400", got.read)
	}
	if ts.Stats().Sessions != 0 {
		t.Fatal("a HELLO on HTTP/1.1 opened a session")
	}
}

// A client that speaks plain HTTP to the TLS port gets net/http's answer.
func TestPlainHTTPOnTheTLSPort(t *testing.T) {
	if !httpServesTLSConns {
		t.Skip("before Go 1.27 the node runs the handshake itself")
	}
	ts := newServerAs(t, true, nil)
	stock := newStockServer(t, 10*time.Second)
	var got [2]string
	for i, addr := range []string{ts.addr, stock} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+coverDomain+"\r\n\r\n")
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(c)
		got[i] = string(b)
	}
	if got[0] == "" || got[0] != got[1] {
		t.Fatalf("node answered %q, net/http %q", got[0], got[1])
	}
}

// Before Go 1.27 the node sends the web server's SETTINGS for it. They must
// not then be sent a second time, and everything else has to work as it
// does when the web server is given the connection whole.
func TestCoverBeforeGo127(t *testing.T) {
	ts := newServerAs(t, false, nil)
	p := certs(t)

	c := probeDial(t, ts.addr, tls.VersionTLS13, "h2")
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if f, err := readFrame(c); err != nil || !bytes.Equal(f, ts.cover.opening) {
		t.Fatalf("opened with % x (%v)", f, err)
	}
	c.Write(append([]byte(h2Preface), 0, 0, 0, 0x4, 0, 0, 0, 0, 0)) // preface, empty SETTINGS
	acked := false
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		f, err := readFrame(c)
		if err != nil {
			break
		}
		if isSettings(f) {
			t.Fatalf("SETTINGS sent twice: % x", f)
		}
		acked = acked || (f[3] == 0x4 && f[4] == 0x1)
	}
	if !acked {
		t.Fatal("the web server did not go on to serve HTTP/2")
	}

	for _, proto := range []string{"HTTP/1.1", "HTTP/2.0"} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: p.roots, ServerName: coverDomain}}
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetHTTP1(proto == "HTTP/1.1")
		tr.Protocols.SetHTTP2(proto == "HTTP/2.0")
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://" + ts.addr + "/")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if want := "cover page " + proto + " tls=true"; string(body) != want {
			t.Fatalf("body %q, want %q", body, want)
		}
	}

	cfg := ts.dialCfg(t)
	cfg.FirstPacket = []byte("first")
	cl := dial(t, cfg)
	cl.welcome(t)
	if got := cl.recv(t); string(got) != "echo:first" {
		t.Fatalf("got %q", got)
	}
	bad := ts.dialCfg(t)
	bad.DeviceKey[0] ^= 1
	if err := waitErr(t, dial(t, bad).l); !errors.Is(err, lane.ErrLoginFailed) {
		t.Fatalf("err = %v, want login failure", err)
	}
}
