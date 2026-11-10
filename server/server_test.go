package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/pangeavpn/tectonic/lane"
	"github.com/pangeavpn/tectonic/wire"
)

const coverDomain = "n1.cover.test"

type pki struct {
	roots      *x509.CertPool
	own        tls.Certificate
	def        tls.Certificate
	defaultPin lane.Pin
}

var (
	pkiOnce sync.Once
	testPKI pki
)

func certs(t testing.TB) pki {
	pkiOnce.Do(func() {
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
		ca, _ := x509.ParseCertificate(caDER)
		testPKI.roots = x509.NewCertPool()
		testPKI.roots.AddCert(ca)
		leaf := func(names []string, signer *x509.Certificate, signKey *ecdsa.PrivateKey) tls.Certificate {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"},
				DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			if signer == nil {
				signer, signKey = tmpl, k
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &k.PublicKey, signKey)
			if err != nil {
				panic(err)
			}
			return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
		}
		testPKI.own = leaf([]string{coverDomain, "edge.cdn.test"}, ca, caKey)
		testPKI.def = leaf(nil, nil, nil)
		c, _ := x509.ParseCertificate(testPKI.def.Certificate[0])
		testPKI.defaultPin = lane.PinOf(c)
	})
	return testPKI
}

// fakeWG echoes datagrams back, prefixed with "echo:", and records the
// source address of each, which identifies the session that sent it.
type fakeWG struct {
	conn  *net.UDPConn
	mu    sync.Mutex
	srcs  []string
	quiet bool
}

func newFakeWG(t *testing.T) *fakeWG {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	w := &fakeWG{conn: c}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			w.mu.Lock()
			w.srcs = append(w.srcs, addr.String())
			quiet := w.quiet
			w.mu.Unlock()
			if !quiet {
				c.WriteToUDP(append([]byte("echo:"), buf[:n]...), addr)
			}
		}
	}()
	return w
}

func (w *fakeWG) sources() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.srcs...)
}

type testServer struct {
	*Server
	addr   string
	wg     *fakeWG
	secret []byte
}

func newTestServer(t *testing.T, mod func(*Config)) *testServer {
	t.Helper()
	p := certs(t)
	wg := newFakeWG(t)
	secret := []byte("0123456789abcdef0123456789abcdef")
	cfg := Config{
		NodeSecret:         secret,
		CoverDomain:        coverDomain,
		OwnCertificate:     func() (*tls.Certificate, error) { return &p.own, nil },
		DefaultCertificate: func() (*tls.Certificate, error) { return &p.def, nil },
		Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "cover page %s tls=%v", r.Proto, r.TLS != nil)
		}),
		WireGuard: wg.conn.LocalAddr().String(),
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
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

func (ts *testServer) credential(t testing.TB) (wire.KeyID, [wire.KeyLen]byte) {
	id, err := wire.NewKeyID(time.Now().Add(48 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return id, wire.DeviceKey(ts.secret, id)
}

type client struct {
	l   *lane.Lane
	got chan []byte
}

func (ts *testServer) dialCfg(t testing.TB) lane.DialConfig {
	id, dk := ts.credential(t)
	p := certs(t)
	return lane.DialConfig{
		Addr: ts.addr, SNIMode: lane.SNIOwn, ServerName: coverDomain,
		RootCAs: p.roots, Pins: []lane.Pin{p.defaultPin},
		KeyID: id, DeviceKey: dk,
	}
}

func dial(t *testing.T, cfg lane.DialConfig) *client {
	t.Helper()
	c := &client{got: make(chan []byte, 256)}
	cfg.Lane.Handler.Data = func(_ *lane.Lane, pkt []byte) { c.got <- append([]byte(nil), pkt...) }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l, err := lane.Dial(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	c.l = l
	return c
}

func (c *client) welcome(t *testing.T) wire.Welcome {
	t.Helper()
	select {
	case <-c.l.Welcomed():
		w, _ := c.l.Welcome()
		return w
	case <-c.l.Done():
		t.Fatalf("lane ended before WELCOME: %v", c.l.Err())
	case <-time.After(5 * time.Second):
		t.Fatal("no WELCOME")
	}
	return wire.Welcome{}
}

func (c *client) recv(t *testing.T) []byte {
	t.Helper()
	select {
	case p := <-c.got:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("nothing received")
		return nil
	}
}

func waitErr(t *testing.T, l *lane.Lane) error {
	t.Helper()
	select {
	case <-l.Done():
		return l.Err()
	case <-time.After(10 * time.Second):
		t.Fatal("lane did not end")
		return nil
	}
}

func TestLoginForwardsToWireGuard(t *testing.T) {
	ts := newTestServer(t, nil)
	cfg := ts.dialCfg(t)
	cfg.FirstPacket = []byte("handshake initiation")
	c := dial(t, cfg)
	w := c.welcome(t)
	if w.SessionID.IsZero() || w.MaxLanes != 6 || w.ResumeWindow != 60*time.Second || w.Profile != 0 {
		t.Fatalf("WELCOME = %+v", w)
	}
	if got := c.recv(t); string(got) != "echo:handshake initiation" {
		t.Fatalf("got %q", got)
	}
	for i := range 20 {
		c.l.Send([]byte(fmt.Sprintf("pkt %d", i)))
	}
	seen := map[string]bool{}
	for range 20 {
		seen[string(c.recv(t))] = true
	}
	if !seen["echo:pkt 0"] || !seen["echo:pkt 19"] {
		t.Fatalf("missing echoes: %v", seen)
	}
	if st := ts.Stats(); st.Sessions != 1 || st.Lanes != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestLanesJoinOneSession(t *testing.T) {
	ts := newTestServer(t, nil)
	cfg := ts.dialCfg(t)
	cfg.SessionCache = utls.NewLRUClientSessionCache(4)
	c1 := dial(t, cfg)
	w1 := c1.welcome(t)
	cfg.Join, cfg.SessionID = true, w1.SessionID
	c2 := dial(t, cfg)
	if w2 := c2.welcome(t); w2.SessionID != w1.SessionID {
		t.Fatal("joining lane got a different session")
	}
	if !lane.ResumedTLS(c2.l) {
		t.Fatal("second lane did not resume TLS")
	}
	c1.l.Send([]byte("a"))
	c2.l.Send([]byte("b"))
	time.Sleep(100 * time.Millisecond)
	srcs := ts.wg.sources()
	if len(srcs) != 2 || srcs[0] != srcs[1] {
		t.Fatalf("WireGuard saw %v; one session must be one endpoint", srcs)
	}
	// Downlink is spread over both lanes, delivered whichever way.
	total := 0
	for total < 2 {
		select {
		case <-c1.got:
			total++
		case <-c2.got:
			total++
		case <-time.After(5 * time.Second):
			t.Fatal("echoes lost")
		}
	}
}

func TestJoinNeedsTheSameKeyID(t *testing.T) {
	ts := newTestServer(t, nil)
	c1 := dial(t, ts.dialCfg(t))
	w1 := c1.welcome(t)
	other := ts.dialCfg(t) // a different credential
	other.Join, other.SessionID = true, w1.SessionID
	c2 := dial(t, other)
	if w2 := c2.welcome(t); w2.SessionID == w1.SessionID {
		t.Fatal("another key_id joined the session")
	}
}

func TestSessionOutlivesLanesForTheResumeWindow(t *testing.T) {
	ts := newTestServer(t, func(c *Config) { c.ResumeWindow = 300 * time.Millisecond })
	cfg := ts.dialCfg(t)
	c1 := dial(t, cfg)
	w1 := c1.welcome(t)
	c1.l.Close()
	time.Sleep(50 * time.Millisecond)

	cfg.Join, cfg.SessionID = true, w1.SessionID
	c2 := dial(t, cfg)
	if c2.welcome(t).SessionID != w1.SessionID {
		t.Fatal("rejoin within the resume window got a new session")
	}
	c2.l.Close()
	time.Sleep(600 * time.Millisecond)
	c3 := dial(t, cfg)
	if c3.welcome(t).SessionID == w1.SessionID {
		t.Fatal("session survived past the resume window")
	}
	if ts.Stats().Sessions != 1 {
		t.Fatalf("sessions = %d", ts.Stats().Sessions)
	}
}

func TestDownlinkWaitsForARejoin(t *testing.T) {
	ts := newTestServer(t, nil)
	cfg := ts.dialCfg(t)
	c1 := dial(t, cfg)
	w := c1.welcome(t)
	c1.l.Send([]byte("ping"))
	c1.recv(t)
	// Every lane drops, and WireGuard sends while none is up.
	c1.l.Close()
	waitErr(t, c1.l)
	time.Sleep(50 * time.Millisecond)
	ts.wg.mu.Lock()
	src := ts.wg.srcs[0]
	ts.wg.mu.Unlock()
	addr, _ := net.ResolveUDPAddr("udp", src)
	ts.wg.conn.WriteToUDP([]byte("while you were away"), addr)
	time.Sleep(50 * time.Millisecond)

	cfg.Join, cfg.SessionID = true, w.SessionID
	c2 := dial(t, cfg)
	c2.welcome(t)
	if got := c2.recv(t); string(got) != "while you were away" {
		t.Fatalf("got %q", got)
	}
}

func TestCellularLaneLimit(t *testing.T) {
	ts := newTestServer(t, nil)
	cfg := ts.dialCfg(t)
	cfg.Cellular = true
	if w := dial(t, cfg).welcome(t); w.MaxLanes != 3 {
		t.Fatalf("cellular max_lanes = %d, want 3", w.MaxLanes)
	}
}

func TestFailedLoginsGetTheCoverSite(t *testing.T) {
	ts := newTestServer(t, func(c *Config) { c.Now = time.Now })
	revokedID, revokedKey := ts.credential(t)
	ts.cfg.Revoked.Set([]wire.KeyID{revokedID})

	expiredID, _ := wire.NewKeyID(time.Now().Add(-72 * time.Hour))
	for name, mod := range map[string]func(*lane.DialConfig){
		"wrong key":  func(c *lane.DialConfig) { c.DeviceKey[0] ^= 1 },
		"revoked":    func(c *lane.DialConfig) { c.KeyID, c.DeviceKey = revokedID, revokedKey },
		"expired":    func(c *lane.DialConfig) { c.KeyID, c.DeviceKey = expiredID, wire.DeviceKey(ts.secret, expiredID) },
		"stale time": func(c *lane.DialConfig) { c.Now = func() time.Time { return time.Now().Add(-5 * time.Minute) } },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := ts.dialCfg(t)
			mod(&cfg)
			c := dial(t, cfg)
			if err := waitErr(t, c.l); !errors.Is(err, lane.ErrLoginFailed) {
				t.Fatalf("err = %v, want login failure", err)
			}
		})
	}
	if ts.Stats().Sessions != 0 {
		t.Fatal("a failed login created a session")
	}
}

func tlsDial(t *testing.T, addr string, cfg *tls.Config) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestProbesSeeAnOrdinaryWebsite(t *testing.T) {
	ts := newTestServer(t, nil)
	p := certs(t)
	for _, proto := range []string{"HTTP/1.1", "HTTP/2.0"} {
		t.Run(proto, func(t *testing.T) {
			tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: p.roots, ServerName: coverDomain}}
			tr.Protocols = new(http.Protocols)
			if proto == "HTTP/2.0" {
				tr.Protocols.SetHTTP2(true)
			} else {
				tr.Protocols.SetHTTP1(true)
			}
			hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			resp, err := hc.Get("https://" + ts.addr + "/")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if want := "cover page " + proto + " tls=true"; string(body) != want {
				t.Fatalf("body %q, want %q", body, want)
			}
		})
	}

	// Garbage on an HTTP/1.1 connection: an ordinary 400 and a close.
	c := tlsDial(t, ts.addr, &tls.Config{RootCAs: p.roots, ServerName: coverDomain, NextProtos: []string{"http/1.1"}})
	c.Write([]byte("\x01\x00\x4e" + strings.Repeat("x", 78) + "\r\n\r\n"))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}

	// TLS 1.2 never carries a lane; it just gets the website.
	c12 := tlsDial(t, ts.addr, &tls.Config{RootCAs: p.roots, ServerName: coverDomain, MaxVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	fmt.Fprintf(c12, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", coverDomain)
	resp, err = http.ReadResponse(bufio.NewReader(c12), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("TLS 1.2: %v %v", resp, err)
	}
}

func TestCertificateDependsOnTheName(t *testing.T) {
	ts := newTestServer(t, nil)
	p := certs(t)
	for name, want := range map[string]tls.Certificate{coverDomain: p.own, "allowed.example": p.def, "": p.def} {
		c := tlsDial(t, ts.addr, &tls.Config{ServerName: name, InsecureSkipVerify: true})
		got := c.ConnectionState().PeerCertificates[0].Raw
		if !bytes.Equal(got, want.Certificate[0]) {
			t.Fatalf("SNI %q: wrong certificate", name)
		}
	}
	for _, tc := range []struct {
		name, pattern string
		want          bool
	}{
		{"n1.cover.test", "n1.cover.test", true},
		{"N1.Cover.Test.", "n1.cover.test", true},
		{"n1.cover.test", "*.cover.test", true},
		{"a.n1.cover.test", "*.cover.test", false},
		{"cover.test", "*.cover.test", false},
		{"", "*.cover.test", false},
		{"other.test", "n1.cover.test", false},
	} {
		if got := matchDomain(tc.name, tc.pattern); got != tc.want {
			t.Errorf("matchDomain(%q, %q) = %v", tc.name, tc.pattern, got)
		}
	}
}

func TestEnforceRevocationClosesSessions(t *testing.T) {
	ts := newTestServer(t, nil)
	reason := make(chan wire.CloseReason, 1)
	cfg := ts.dialCfg(t)
	cfg.Lane.Handler.Close = func(_ *lane.Lane, r wire.CloseReason) { reason <- r }
	c := dial(t, cfg)
	c.welcome(t)
	ts.cfg.Revoked.Set([]wire.KeyID{cfg.KeyID})
	ts.EnforceRevocation()
	select {
	case r := <-reason:
		if r != wire.CloseCredential {
			t.Fatalf("reason %v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no CLOSE")
	}
	deadline := time.Now().Add(5 * time.Second)
	for ts.Stats().Sessions != 0 {
		if time.Now().After(deadline) {
			t.Fatal("revoked session still open")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestClientCloseEndsSession(t *testing.T) {
	ts := newTestServer(t, nil)
	c := dial(t, ts.dialCfg(t))
	c.welcome(t)
	c.l.SendClose(wire.CloseNormal)
	deadline := time.Now().Add(5 * time.Second)
	for ts.Stats().Sessions != 0 {
		if time.Now().After(deadline) {
			t.Fatal("session outlived the client's CLOSE")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestShutdownSendsClose(t *testing.T) {
	ts := newTestServer(t, nil)
	reason := make(chan wire.CloseReason, 1)
	cfg := ts.dialCfg(t)
	cfg.Lane.Handler.Close = func(_ *lane.Lane, r wire.CloseReason) { reason <- r }
	c := dial(t, cfg)
	c.welcome(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ts.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-reason:
		if r != wire.CloseShutdown {
			t.Fatalf("reason %v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no CLOSE on shutdown")
	}
}

func TestTooManyLanesRetiresTheOldest(t *testing.T) {
	ts := newTestServer(t, func(c *Config) { c.MaxLanes = 2 })
	cfg := ts.dialCfg(t)
	first := dial(t, cfg)
	w := first.welcome(t)
	cfg.Join, cfg.SessionID = true, w.SessionID
	for range 4 {
		dial(t, cfg).welcome(t)
	}
	if err := waitErr(t, first.l); err != nil {
		t.Fatalf("oldest lane ended with %v, want a clean retire", err)
	}
}

// edge stands in for a CDN: it terminates the client's TLS, adds the
// signed header to the WebSocket upgrade, and forwards to the node over a
// TLS connection of its own.
func startEdge(t *testing.T, node string, secret []byte) string {
	t.Helper()
	p := certs(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{p.own}, NextProtos: []string{"http/1.1"}})
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
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				req.Header.Set("Tectonic-Edge", SignEdgeHeader(secret, req.Header.Get("Sec-WebSocket-Key"), time.Now()))
				up, err := tls.Dial("tcp", node, &tls.Config{RootCAs: p.roots, ServerName: coverDomain, NextProtos: []string{"http/1.1"}})
				if err != nil {
					return
				}
				defer up.Close()
				if err := req.Write(up); err != nil {
					return
				}
				go io.Copy(up, br)
				io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestCDNCarrier(t *testing.T) {
	edgeSecret := []byte("edge secret")
	ts := newTestServer(t, func(c *Config) {
		c.CDN = &CDNConfig{Path: "/assets/ws", Verify: EdgeHeader("Tectonic-Edge", edgeSecret, nil)}
	})
	edge := startEdge(t, ts.addr, edgeSecret)
	cfg := ts.dialCfg(t)
	cfg.Carrier = lane.CDN
	cfg.Addr = edge
	cfg.ServerName = "edge.cdn.test"
	cfg.Path = "/assets/ws"
	cfg.FirstPacket = []byte("via the cdn")
	c := dial(t, cfg)
	w := c.welcome(t)
	if got := c.recv(t); string(got) != "echo:via the cdn" {
		t.Fatalf("got %q", got)
	}

	// Direct and CDN lanes can share one session.
	direct := ts.dialCfg(t)
	direct.KeyID, direct.DeviceKey = cfg.KeyID, cfg.DeviceKey
	direct.Join, direct.SessionID = true, w.SessionID
	d := dial(t, direct)
	if d.welcome(t).SessionID != w.SessionID {
		t.Fatal("direct lane could not join the CDN lane's session")
	}

	// An upgrade the CDN didn't sign is just a request to the website.
	resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certs(t).roots, ServerName: coverDomain}}}).
		Get("https://" + ts.addr + "/assets/ws")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(body), "cover page") {
		t.Fatalf("unsigned request got %q", body)
	}
}

func TestEdgeHeader(t *testing.T) {
	secret := []byte("s")
	now := time.Unix(1_800_000_000, 0)
	verify := EdgeHeader("X-Edge", secret, func() time.Time { return now })
	req := func(val, key string) *http.Request {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("X-Edge", val)
		r.Header.Set("Sec-WebSocket-Key", key)
		return r
	}
	if !verify(req(SignEdgeHeader(secret, "k1", now), "k1")) {
		t.Fatal("valid signature rejected")
	}
	for name, r := range map[string]*http.Request{
		"other key":    req(SignEdgeHeader(secret, "k1", now), "k2"),
		"other secret": req(SignEdgeHeader([]byte("t"), "k1", now), "k1"),
		"stale":        req(SignEdgeHeader(secret, "k1", now.Add(-3*time.Minute)), "k1"),
		"missing":      req("", "k1"),
		"garbage":      req("abc", "k1"),
	} {
		if verify(r) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseRevocationList(t *testing.T) {
	id, _ := wire.NewKeyID(time.Now())
	ids, err := ParseRevocationList(strings.NewReader("# revoked\n\n" + id.String() + "\n"))
	if err != nil || len(ids) != 1 || ids[0] != id {
		t.Fatalf("%v %v", ids, err)
	}
	if _, err := ParseRevocationList(strings.NewReader("nothex\n")); err == nil {
		t.Fatal("bad line accepted")
	}
	r := NewRevocation(id)
	if !r.Revoked(id) || r.Len() != 1 {
		t.Fatal("Revoked")
	}
}

func TestConfigValidation(t *testing.T) {
	p := certs(t)
	good := Config{
		NodeSecret:         make([]byte, 32),
		DefaultCertificate: func() (*tls.Certificate, error) { return &p.def, nil },
		Cover:              http.NotFoundHandler(),
		WireGuard:          "127.0.0.1:51820",
	}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Config){
		"short secret": func(c *Config) { c.NodeSecret = []byte("short") },
		"no default":   func(c *Config) { c.DefaultCertificate = nil },
		"no cover":     func(c *Config) { c.Cover = nil },
		"bad wg":       func(c *Config) { c.WireGuard = "nope" },
		"cdn no path":  func(c *Config) { c.CDN = &CDNConfig{Verify: func(*http.Request) bool { return true }} },
	} {
		c := good
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
