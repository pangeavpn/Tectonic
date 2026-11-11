package lane

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/pangeavpn/tectonic/wire"
)

const coverDomain = "cover.test"

// testPKI is a CA, a certificate for the cover domain signed by it, and a
// self-signed default certificate like the one a node pins.
type testPKI struct {
	roots       *x509.CertPool
	cover       tls.Certificate
	defaultCert tls.Certificate
	defaultPin  Pin
}

var (
	pkiOnce sync.Once
	pki     testPKI
)

func getPKI(t testing.TB) testPKI {
	pkiOnce.Do(func() {
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Test Root"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
		if err != nil {
			panic(err)
		}
		ca, _ := x509.ParseCertificate(caDER)
		pki.roots = x509.NewCertPool()
		pki.roots.AddCert(ca)

		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: coverDomain},
			DNSNames:     []string{coverDomain},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
		if err != nil {
			panic(err)
		}
		pki.cover = tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}

		defKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		defTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: "default"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		defDER, err := x509.CreateCertificate(rand.Reader, defTmpl, defTmpl, &defKey.PublicKey, defKey)
		if err != nil {
			panic(err)
		}
		pki.defaultCert = tls.Certificate{Certificate: [][]byte{defDER}, PrivateKey: defKey}
		leaf, _ := x509.ParseCertificate(defDER)
		pki.defaultPin = PinOf(leaf)
	})
	return pki
}

// testNode is a minimal server: TLS, the HELLO check, and a server lane.
type testNode struct {
	t      *testing.T
	ln     net.Listener
	secret []byte
	lanes  chan *Lane
	snis   chan string
	// handler is installed on each server lane.
	handler Handler
	// cover, if set, answers connections whose HELLO fails, the way the
	// cover site would.
	refuse bool
	// ws serves the CDN carrier: TLS + HTTP/1.1 + WebSocket.
	ws bool
	// wrap, if set, wraps each accepted TCP connection before TLS.
	wrap func(net.Conn) net.Conn
	// One config for every connection: each tls.Config has its own session
	// ticket keys, so sharing it is what makes resumption work.
	cfgOnce sync.Once
	cfg     *tls.Config
}

func newTestNode(t *testing.T, mod func(*testNode)) *testNode {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n := &testNode{t: t, ln: ln, secret: []byte("node secret"), lanes: make(chan *Lane, 16), snis: make(chan string, 16)}
	if mod != nil {
		mod(n)
	}
	t.Cleanup(func() { ln.Close() })
	go n.serve()
	return n
}

func (n *testNode) tlsConfig() *tls.Config {
	n.cfgOnce.Do(func() { n.cfg = n.newTLSConfig() })
	return n.cfg
}

func (n *testNode) newTLSConfig() *tls.Config {
	p := getPKI(n.t)
	protos := []string{"h2", "http/1.1"}
	if n.ws {
		protos = []string{"http/1.1"}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: protos,
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			select {
			case n.snis <- hi.ServerName:
			default:
			}
			if hi.ServerName == coverDomain {
				return &p.cover, nil
			}
			return &p.defaultCert, nil
		},
	}
}

func (n *testNode) serve() {
	if n.ws {
		srv := &http.Server{Handler: http.HandlerFunc(n.serveWS)}
		srv.Serve(tls.NewListener(n.ln, n.tlsConfig()))
		return
	}
	for {
		c, err := n.ln.Accept()
		if err != nil {
			return
		}
		if n.wrap != nil {
			c = n.wrap(c)
		}
		go n.handle(c)
	}
}

func (n *testNode) handle(c net.Conn) {
	tc := tls.Server(c, n.tlsConfig())
	if err := tc.Handshake(); err != nil {
		c.Close()
		return
	}
	cs := tc.ConnectionState()
	exp, err := cs.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
	if err != nil {
		c.Close()
		return
	}
	br := bufio.NewReader(tc)
	n.login(tc, br, exp, c)
}

func (n *testNode) serveWS(w http.ResponseWriter, r *http.Request) {
	conn, key, err := AcceptWebSocket(w, r)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	n.login(conn, bufio.NewReader(conn), WebSocketBinding(key), nil)
}

func (n *testNode) login(conn net.Conn, br *bufio.Reader, exporter []byte, raw net.Conn) {
	rd := wire.NewReader(br)
	typ, body, err := rd.Next()
	ok := err == nil && typ == wire.TypeHello
	var h wire.Hello
	if ok {
		h, err = wire.ParseHello(body)
		ok = err == nil && h.Verify(wire.LaneKey(wire.DeviceKey(n.secret, h.KeyID), exporter)) && h.TimestampOK(time.Now())
	}
	if !ok || n.refuse {
		io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		conn.Close()
		return
	}
	l := New(conn, br, Options{Role: Server, Handler: n.handler, Raw: raw})
	w := wire.Welcome{SessionID: h.SessionID, MaxLanes: 6, ResumeWindow: time.Minute}
	if h.SessionID.IsZero() {
		w.SessionID[0] = 0x42
	}
	if err := l.Start(wire.AppendFrame(nil, wire.TypeWelcome, w.AppendBody(nil))); err != nil {
		return
	}
	n.lanes <- l
}

func (n *testNode) addr() string { return n.ln.Addr().String() }

func (n *testNode) acceptLane(t *testing.T) *Lane {
	t.Helper()
	select {
	case l := <-n.lanes:
		t.Cleanup(func() { l.Close() })
		return l
	case <-time.After(5 * time.Second):
		t.Fatal("server lane never came up")
		return nil
	}
}

func (n *testNode) credentials(t testing.TB) (wire.KeyID, [wire.KeyLen]byte) {
	id, err := wire.NewKeyID(time.Now().Add(24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return id, wire.DeviceKey(n.secret, id)
}

func (n *testNode) dialConfig(t testing.TB, mode SNIMode) DialConfig {
	id, dk := n.credentials(t)
	p := getPKI(t)
	cfg := DialConfig{
		Addr:      n.addr(),
		SNIMode:   mode,
		Pins:      []Pin{p.defaultPin},
		RootCAs:   p.roots,
		KeyID:     id,
		DeviceKey: dk,
	}
	switch mode {
	case SNIOwn:
		cfg.ServerName = coverDomain
	case SNIBorrowed:
		cfg.ServerName = "allowed.example"
	}
	return cfg
}

func dial(t *testing.T, cfg DialConfig) *Lane {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func waitWelcome(t *testing.T, l *Lane) wire.Welcome {
	t.Helper()
	select {
	case <-l.Welcomed():
		w, _ := l.Welcome()
		return w
	case <-l.Done():
		t.Fatalf("lane ended before WELCOME: %v", l.Err())
	case <-time.After(5 * time.Second):
		t.Fatal("no WELCOME")
	}
	return wire.Welcome{}
}

func waitDone(t *testing.T, l *Lane) error {
	t.Helper()
	select {
	case <-l.Done():
		return l.Err()
	case <-time.After(10 * time.Second):
		t.Fatalf("%v did not end", l)
		return nil
	}
}

// packetSink collects DATA delivered by a lane.
type packetSink struct {
	mu   sync.Mutex
	pkts [][]byte
	ch   chan struct{}
}

func newSink() *packetSink { return &packetSink{ch: make(chan struct{}, 1024)} }

func (s *packetSink) handler(_ *Lane, pkt []byte) {
	s.mu.Lock()
	s.pkts = append(s.pkts, append([]byte(nil), pkt...))
	s.mu.Unlock()
	select {
	case s.ch <- struct{}{}:
	default:
	}
}

func (s *packetSink) wait(t *testing.T, n int) [][]byte {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		s.mu.Lock()
		if len(s.pkts) >= n {
			out := append([][]byte(nil), s.pkts...)
			s.mu.Unlock()
			return out
		}
		s.mu.Unlock()
		select {
		case <-s.ch:
		case <-deadline:
			s.mu.Lock()
			got := len(s.pkts)
			s.mu.Unlock()
			t.Fatalf("got %d packets, want %d", got, n)
		}
	}
}

// recordConn is one end of a net.Pipe that records the size of every Write,
// standing in for TLS so tests can see the records the lane would produce.
type recordConn struct {
	net.Conn
	mu     sync.Mutex
	writes []int
	times  []time.Time
}

func (c *recordConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, len(p))
	c.times = append(c.times, time.Now())
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recordConn) sizes() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.writes...)
}

func uconnSNI(t *testing.T, n *testNode) string {
	t.Helper()
	select {
	case s := <-n.snis:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("no ClientHello seen")
		return ""
	}
}

func lruCache() utls.ClientSessionCache { return utls.NewLRUClientSessionCache(8) }

func isHTTPError(err error) bool { return err != nil && strings.Contains(err.Error(), "login failed") }
