package tectonic_test

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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/pangeavpn/tectonic"
	"github.com/pangeavpn/tectonic/lane"
	"github.com/pangeavpn/tectonic/server"
	"github.com/pangeavpn/tectonic/wire"
)

const coverDomain = "n7.cover.test"

type certSet struct {
	roots *x509.CertPool
	own   tls.Certificate
	def   tls.Certificate
	pin   string
}

var (
	certOnce  sync.Once
	testCerts certSet
)

func certs() certSet {
	certOnce.Do(func() {
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ca := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
		caCert, _ := x509.ParseCertificate(caDER)
		testCerts.roots = x509.NewCertPool()
		testCerts.roots.AddCert(caCert)
		mk := func(names []string, selfSigned bool) tls.Certificate {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "x"},
				DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			}
			parent, key := caCert, caKey
			if selfSigned {
				parent, key = tmpl, k
			}
			der, _ := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, key)
			return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
		}
		testCerts.own = mk([]string{coverDomain, "edge.cdn.test"}, false)
		testCerts.def = mk(nil, true)
		leaf, _ := x509.ParseCertificate(testCerts.def.Certificate[0])
		testCerts.pin = lane.PinOf(leaf).String()
	})
	return testCerts
}

type node struct {
	srv     *server.Server
	addr    string
	secret  []byte
	sniSeen chan string
}

// startNode runs a Tectonic server in front of wgAddr.
func startNode(t *testing.T, wgAddr string, mod func(*server.Config)) *node {
	t.Helper()
	c := certs()
	n := &node{secret: bytes.Repeat([]byte{7}, 32), sniSeen: make(chan string, 64)}
	cfg := server.Config{
		NodeSecret:     n.secret,
		CoverDomain:    coverDomain,
		OwnCertificate: func() (*tls.Certificate, error) { return &c.own, nil },
		DefaultCertificate: func() (*tls.Certificate, error) {
			return &c.def, nil
		},
		Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "<html>a small, plausible website</html>")
		}),
		WireGuard: wgAddr,
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })
	n.srv, n.addr = s, ln.Addr().String()
	return n
}

// profile issues a credential the way the hub does and returns the profile
// block for this node.
func (n *node) profile(t *testing.T) tectonic.Profile {
	id, err := wire.NewKeyID(time.Now().Add(7 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dk := wire.DeviceKey(n.secret, id)
	return tectonic.Profile{
		Node:        n.addr,
		CoverDomain: coverDomain,
		KeyID:       id[:],
		DeviceKey:   dk[:],
		Pins:        []string{certs().pin},
		BorrowedSNI: []string{"allowed.example"},
	}
}

// wgKey makes a WireGuard key pair, hex-encoded for IpcSet.
func wgKey(t *testing.T) (priv, pub string) {
	var k [32]byte
	rand.Read(k[:])
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(k[:]), hex.EncodeToString(p)
}

type wgPeer struct {
	dev *device.Device
	tun *tuntest.ChannelTUN
}

func newWG(t *testing.T, ipc string) *wgPeer {
	t.Helper()
	tun := tuntest.NewChannelTUN()
	dev := device.NewDevice(tun.TUN(), conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet(ipc); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	return &wgPeer{dev: dev, tun: tun}
}

func (p *wgPeer) port(t *testing.T) int {
	s, err := p.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			var port int
			fmt.Sscan(v, &port)
			return port
		}
	}
	t.Fatal("no listen_port")
	return 0
}

func (p *wgPeer) handshakes(t *testing.T) bool {
	s, _ := p.dev.IpcGet()
	return strings.Contains(s, "last_handshake_time_sec=") && !strings.Contains(s, "last_handshake_time_sec=0\n")
}

// bridge relays WireGuard's loopback UDP to the Tectonic Conn, as the
// PangeaVPN daemon does with every transport.
func bridge(t *testing.T, c *tectonic.Conn) *net.UDPAddr {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	var peer *net.UDPAddr
	var mu sync.Mutex
	go func() {
		buf := make([]byte, 65535)
		for {
			n, a, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			peer = a
			mu.Unlock()
			c.WriteTo(buf[:n], nil)
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			p := peer
			mu.Unlock()
			if p != nil {
				udp.WriteToUDP(buf[:n], p)
			}
		}
	}()
	return udp.LocalAddr().(*net.UDPAddr)
}

var (
	clientIP = netip.MustParseAddr("10.77.0.1")
	serverIP = netip.MustParseAddr("10.77.0.2")
)

// tunnel brings up WireGuard on both ends with Tectonic in between.
func tunnel(t *testing.T, mod func(*tectonic.Config)) (client, srv *wgPeer, c *tectonic.Conn, n *node) {
	t.Helper()
	cPriv, cPub := wgKey(t)
	sPriv, sPub := wgKey(t)
	srv = newWG(t, fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s/32\n", sPriv, cPub, clientIP))
	n = startNode(t, fmt.Sprintf("127.0.0.1:%d", srv.port(t)), nil)

	cfg := tectonic.Config{Profile: n.profile(t), RootCAs: certs().roots, Network: "test-net"}
	if mod != nil {
		mod(&cfg)
	}
	c, err := tectonic.Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ep := bridge(t, c)
	client = newWG(t, fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s/32\nendpoint=%s\n", cPriv, sPub, serverIP, ep))
	return client, srv, c, n
}

func expectPacket(t *testing.T, ch <-chan []byte, want []byte) {
	t.Helper()
	select {
	case got := <-ch:
		if !bytes.Equal(got, want) {
			t.Fatalf("packet differs:\n got %x\nwant %x", got, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("packet never came through the tunnel")
	}
}

// Milestone M1: an in-process end-to-end test carries a real WireGuard
// handshake, and a probe that fails login gets the cover site.
func TestWireGuardThroughTectonic(t *testing.T) {
	client, srv, c, n := tunnel(t, func(cfg *tectonic.Config) { cfg.SNIMode = tectonic.SNIOwn })

	ping := tuntest.Ping(serverIP, clientIP)
	client.tun.Outbound <- ping // WireGuard handshakes, then sends it
	expectPacket(t, srv.tun.Inbound, ping)
	if !client.handshakes(t) {
		t.Fatal("WireGuard reports no handshake")
	}

	pong := tuntest.Ping(clientIP, serverIP)
	srv.tun.Outbound <- pong
	expectPacket(t, client.tun.Inbound, pong)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.WaitForSession(ctx, 0); err != nil {
		t.Fatal(err)
	}
	// The pool grows to its two base lanes.
	deadline := time.Now().Add(5 * time.Second)
	for c.Stats().Lanes < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("lanes = %d, want 2", c.Stats().Lanes)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i := range 50 {
		p := tuntest.Ping(serverIP, clientIP)
		p[len(p)-1] = byte(i)
		client.tun.Outbound <- p
		select {
		case <-srv.tun.Inbound:
		case <-time.After(5 * time.Second):
			t.Fatalf("ping %d lost", i)
		}
	}
	if st := n.srv.Stats(); st.Sessions != 1 || st.Lanes < 2 {
		t.Fatalf("server stats %+v", st)
	}

	// A probe that doesn't log in gets the cover site.
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certs().roots, ServerName: coverDomain}}}
	resp, err := hc.Get("https://" + n.addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "plausible website") {
		t.Fatalf("probe got %q", body)
	}
}

func TestAutoModeRacesAndRemembers(t *testing.T) {
	modes := tectonic.NewMemoryModeStore()
	// No trusted roots: Own mode's certificate check fails, as it would on
	// a network that blocks the cover domain. Borrowed or None must win.
	_, _, c, _ := tunnel(t, func(cfg *tectonic.Config) {
		cfg.RootCAs = x509.NewCertPool()
		cfg.Modes = modes
		cfg.Network = "cafe-wifi"
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.WaitForSession(ctx, 0); err != nil {
		t.Fatal(err)
	}
	got, ok := modes.Mode("cafe-wifi")
	if !ok || (got.Mode != tectonic.SNIBorrowed && got.Mode != tectonic.SNINone) {
		t.Fatalf("remembered %+v %v", got, ok)
	}
	if got.Mode == tectonic.SNIBorrowed && got.Name != "allowed.example" {
		t.Fatalf("borrowed name %q", got.Name)
	}
	if st := c.Stats(); st.Mode != got || st.Carrier != "direct" {
		t.Fatalf("stats %+v", st)
	}
}

// edge is a stand-in CDN: it terminates TLS, signs the upgrade and
// forwards to the node.
func edge(t *testing.T, nodeAddr string, secret []byte) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certs().own}, NextProtos: []string{"http/1.1"}})
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
				req.Header.Set("Edge-Signature", server.SignEdgeHeader(secret, req.Header.Get("Sec-WebSocket-Key"), time.Now()))
				up, err := tls.Dial("tcp", nodeAddr, &tls.Config{RootCAs: certs().roots, ServerName: coverDomain, NextProtos: []string{"http/1.1"}})
				if err != nil {
					return
				}
				defer up.Close()
				req.Write(up)
				go io.Copy(up, br)
				io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestCDNWhenTheNodeIsBlocked(t *testing.T) {
	cPriv, cPub := wgKey(t)
	sPriv, sPub := wgKey(t)
	srv := newWG(t, fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s/32\n", sPriv, cPub, clientIP))
	edgeSecret := []byte("edge")
	n := startNode(t, fmt.Sprintf("127.0.0.1:%d", srv.port(t)), func(c *server.Config) {
		c.CDN = &server.CDNConfig{Path: "/static/socket", Verify: server.EdgeHeader("Edge-Signature", edgeSecret, nil)}
	})
	edgeAddr := edge(t, n.addr, edgeSecret)

	p := n.profile(t)
	p.CDN = &tectonic.CDNRoute{Host: "edge.cdn.test", Path: "/static/socket", Edge: edgeAddr}
	var mu sync.Mutex
	blockedTries := 0
	c, err := tectonic.Dial(context.Background(), tectonic.Config{
		Profile: p, RootCAs: certs().roots, SNIMode: tectonic.SNIOwn,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == n.addr {
				// The node's IP is null-routed.
				mu.Lock()
				blockedTries++
				mu.Unlock()
				return nil, errors.New("connection timed out")
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ep := bridge(t, c)
	client := newWG(t, fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s/32\nendpoint=%s\n", cPriv, sPub, serverIP, ep))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := c.WaitForSession(ctx, 0); err != nil {
		t.Fatal(err)
	}
	ping := tuntest.Ping(serverIP, clientIP)
	client.tun.Outbound <- ping
	expectPacket(t, srv.tun.Inbound, ping)
	if st := c.Stats(); st.Carrier != "cdn" {
		t.Fatalf("carrier = %s", st.Carrier)
	}
	mu.Lock()
	defer mu.Unlock()
	if blockedTries < 3 {
		t.Fatalf("switched to the CDN after %d direct tries", blockedTries)
	}
}

func TestExpiredCredential(t *testing.T) {
	n := startNode(t, "127.0.0.1:9", nil)
	p := n.profile(t)
	expired, _ := wire.NewKeyID(time.Now().Add(-48 * time.Hour))
	p.KeyID = expired[:]
	if _, err := tectonic.Dial(context.Background(), tectonic.Config{Profile: p}); !errors.Is(err, tectonic.ErrCredentialRejected) {
		t.Fatalf("expired key_id: %v", err)
	}
}

var errTimeout = errors.New("timeout")

func readWithin(c *tectonic.Conn, d time.Duration) (int, net.Addr, error) {
	c.SetReadDeadline(time.Now().Add(d))
	n, a, err := c.ReadFrom(make([]byte, 2048))
	if err != nil && strings.Contains(err.Error(), "deadline") {
		return n, a, errTimeout
	}
	return n, a, err
}

func TestRevocationEndsTheClient(t *testing.T) {
	rev := server.NewRevocation()
	n := startNode(t, "127.0.0.1:9", func(c *server.Config) { c.Revoked = rev })
	p := n.profile(t)
	c, err := tectonic.Dial(context.Background(), tectonic.Config{Profile: p, RootCAs: certs().roots, SNIMode: tectonic.SNIOwn})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.WaitForSession(ctx, 0); err != nil {
		t.Fatal(err)
	}
	var id wire.KeyID
	copy(id[:], p.KeyID)
	rev.Set([]wire.KeyID{id})
	n.srv.EnforceRevocation()
	if _, _, err := readWithin(c, 5*time.Second); !errors.Is(err, tectonic.ErrCredentialRejected) {
		t.Fatalf("ReadFrom = %v, want ErrCredentialRejected", err)
	}
	if _, err := c.WriteTo([]byte("x"), nil); !errors.Is(err, tectonic.ErrCredentialRejected) {
		t.Fatalf("WriteTo = %v", err)
	}
}

func TestProfileValidation(t *testing.T) {
	n := startNode(t, "127.0.0.1:9", nil)
	good := n.profile(t)
	for name, mod := range map[string]func(*tectonic.Profile){
		"no node":      func(p *tectonic.Profile) { p.Node = "" },
		"short key_id": func(p *tectonic.Profile) { p.KeyID = p.KeyID[:5] },
		"bad pin":      func(p *tectonic.Profile) { p.Pins = []string{"!!"} },
		"cdn no host":  func(p *tectonic.Profile) { p.CDN = &tectonic.CDNRoute{Path: "/x"} },
	} {
		p := good
		mod(&p)
		if _, err := tectonic.Dial(context.Background(), tectonic.Config{Profile: p}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A profile round-trips through the hub's JSON.
	b := fmt.Appendf(nil, `{"node":"203.0.113.7","cover_domain":"a.example","key_id":"%s","device_key":"%s","borrowed_sni":["x.example"],"cdn":{"host":"cdn.example","path":"/ws"}}`,
		base64.StdEncoding.EncodeToString(good.KeyID), base64.StdEncoding.EncodeToString(good.DeviceKey))
	p, err := tectonic.ParseProfile(b)
	if err != nil || p.CDN == nil || p.CDN.Path != "/ws" || !bytes.Equal(p.KeyID, good.KeyID) {
		t.Fatalf("ParseProfile: %+v %v", p, err)
	}
	c, err := tectonic.Dial(context.Background(), tectonic.Config{Profile: p, SNIMode: tectonic.SNIOwn})
	if err != nil {
		t.Fatal(err)
	}
	if c.RemoteAddr().String() != "203.0.113.7:443" {
		t.Fatalf("node address %s", c.RemoteAddr())
	}
	c.Close()
}
