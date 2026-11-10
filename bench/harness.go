package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/pangeavpn/tectonic"
	"github.com/pangeavpn/tectonic/bench/baseline"
	"github.com/pangeavpn/tectonic/bench/internal/stacktune"
	"github.com/pangeavpn/tectonic/bench/link"
	"github.com/pangeavpn/tectonic/bench/wgnet"
	"github.com/pangeavpn/tectonic/server"
	"github.com/pangeavpn/tectonic/wire"
)

// transport is one way of carrying WireGuard across the simulated link.
type transport string

const (
	// WireGuard straight over UDP: the reference every other transport is
	// measured against.
	tWireGuard transport = "wireguard"
	tTectonic  transport = "tectonic"
	// Single-connection models of REALITY and AnyTLS (see baseline).
	tReality transport = "reality"
	tAnyTLS  transport = "anytls"
)

var allTransports = []transport{tWireGuard, tTectonic, tReality, tAnyTLS}

const (
	tectonicPort = 443
	baselinePort = 8443
	wgLinkPort   = 51820
	coverDomain  = "node.bench.test"
)

// env is one transport running over one simulated link, with WireGuard
// peers on either side whose netstacks carry the test traffic.
type env struct {
	tr     transport
	L      *link.Link
	client *wgnet.Peer
	server *wgnet.Peer
	conn   *tectonic.Conn // tTectonic only
	node   *server.Server // tTectonic only
	close  []func()
}

func (e *env) Close() {
	for i := len(e.close) - 1; i >= 0; i-- {
		e.close[i]()
	}
}

type pki struct {
	roots *x509.CertPool
	own   tls.Certificate
	def   tls.Certificate
}

var (
	pkiOnce sync.Once
	certs   pki
)

func benchPKI() pki {
	pkiOnce.Do(func() {
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ca := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Bench Root"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		der, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
		caCert, _ := x509.ParseCertificate(der)
		certs.roots = x509.NewCertPool()
		certs.roots.AddCert(caCert)
		leaf := func(names []string, self bool) tls.Certificate {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "bench"},
				DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
			}
			parent, pk := caCert, caKey
			if self {
				parent, pk = tmpl, k
			}
			d, _ := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, pk)
			return tls.Certificate{Certificate: [][]byte{d}, PrivateKey: k}
		}
		certs.own = leaf([]string{coverDomain}, false)
		certs.def = leaf(nil, true)
	})
	return certs
}

func freeUDPPort() (uint16, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

// newEnv builds a link and brings WireGuard up across it over tr.
func newEnv(ctx context.Context, tr transport, lc link.Config) (*env, error) {
	L, err := link.New(lc)
	if err != nil {
		return nil, err
	}
	e := &env{tr: tr, L: L}
	e.close = append(e.close, func() { L.Close() })
	ok := false
	defer func() {
		if !ok {
			e.Close()
		}
	}()

	pair := wgnet.PairConfig{}
	switch tr {
	case tWireGuard:
		cpc, err := L.Client.ListenUDP(wgLinkPort)
		if err != nil {
			return nil, err
		}
		spc, err := L.Server.ListenUDP(wgLinkPort)
		if err != nil {
			return nil, err
		}
		pair.ClientBind = wgnet.NewPacketConnBind(cpc)
		pair.ServerBind = wgnet.NewPacketConnBind(spc)
		pair.ServerEndpoint = netip.AddrPortFrom(link.ServerAddr, wgLinkPort).String()

	case tTectonic:
		port, err := freeUDPPort()
		if err != nil {
			return nil, err
		}
		c, srv, err := startTectonic(ctx, L, tectonicPort, fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return nil, err
		}
		e.conn, e.node = c, srv
		e.close = append(e.close, func() { srv.Close() }, func() { c.Close() })
		pair.ClientBind = wgnet.NewPacketConnBind(c)
		pair.ServerBind = conn.NewStdNetBind()
		pair.ServerListenPort = port
		pair.ServerEndpoint = netip.AddrPortFrom(link.ServerAddr, tectonicPort).String()

	case tReality, tAnyTLS:
		kind := baseline.Reality
		if tr == tAnyTLS {
			kind = baseline.AnyTLS
		}
		port, err := freeUDPPort()
		if err != nil {
			return nil, err
		}
		ln, err := L.Server.ListenTCP(baselinePort)
		if err != nil {
			return nil, err
		}
		sctx, cancel := context.WithCancel(context.Background())
		e.close = append(e.close, cancel)
		go baseline.Serve(sctx, kind, ln, benchPKI().own, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
		pc, err := baseline.Dial(ctx, kind, func(ctx context.Context) (net.Conn, error) {
			return L.Client.DialTCP(ctx, netip.AddrPortFrom(link.ServerAddr, baselinePort))
		}, coverDomain)
		if err != nil {
			return nil, err
		}
		e.close = append(e.close, func() { pc.Close() })
		pair.ClientBind = wgnet.NewPacketConnBind(pc)
		pair.ServerBind = conn.NewStdNetBind()
		pair.ServerListenPort = port
		pair.ServerEndpoint = netip.AddrPortFrom(link.ServerAddr, baselinePort).String()

	default:
		return nil, fmt.Errorf("unknown transport %q", tr)
	}

	client, srv, err := wgnet.NewPair(pair)
	if err != nil {
		return nil, err
	}
	e.client, e.server = client, srv
	e.close = append(e.close, client.Close, srv.Close)
	// The TCP inside the tunnel: RACK on or off (see -inner-rack).
	for _, p := range []*wgnet.Peer{client, srv} {
		if err := stacktune.Tune(p.Stack, innerRACK); err != nil {
			return nil, err
		}
	}

	// Wait for the tunnel: a ping must make it through.
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	p, err := newPinger(e)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	for {
		if _, err := p.ping(pctx, time.Second); err == nil {
			break
		}
		if pctx.Err() != nil {
			return nil, fmt.Errorf("%s: tunnel never came up", tr)
		}
	}
	ok = true
	return e, nil
}

// startTectonic runs a Tectonic node on the link's server host, port
// listen, in front of WireGuard at wgAddr, and dials it from the client
// host.
func startTectonic(ctx context.Context, L *link.Link, listen uint16, wgAddr string) (*tectonic.Conn, *server.Server, error) {
	p := benchPKI()
	secret := bytes.Repeat([]byte{0x5a}, 32)
	srv, err := server.New(server.Config{
		NodeSecret:         secret,
		CoverDomain:        coverDomain,
		OwnCertificate:     func() (*tls.Certificate, error) { return &p.own, nil },
		DefaultCertificate: func() (*tls.Certificate, error) { return &p.def, nil },
		Cover:              http.NotFoundHandler(),
		WireGuard:          wgAddr,
		MaxLanes:           benchMaxLanes(),
		Logger:             benchLogger(),
	})
	if err != nil {
		return nil, nil, err
	}
	ln, err := L.Server.ListenTCP(listen)
	if err != nil {
		return nil, nil, err
	}
	go srv.Serve(ln)

	id, _ := wire.NewKeyID(time.Now().Add(24 * time.Hour))
	dk := wire.DeviceKey(secret, id)
	c, err := tectonic.Dial(ctx, tectonic.Config{
		Profile: tectonic.Profile{
			Node:        netip.AddrPortFrom(link.ServerAddr, listen).String(),
			CoverDomain: coverDomain,
			KeyID:       id[:],
			DeviceKey:   dk[:],
		},
		SNIMode: tectonic.SNIOwn,
		RootCAs: p.roots,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			ap, err := netip.ParseAddrPort(addr)
			if err != nil {
				return nil, err
			}
			return L.Client.DialTCP(ctx, ap)
		},
		Logger: benchLogger(),
	})
	if err != nil {
		srv.Close()
		return nil, nil, err
	}
	return c, srv, nil
}

// benchLogger logs Tectonic's own debug output when BENCH_DEBUG is set.
func benchLogger() *slog.Logger {
	if os.Getenv("BENCH_DEBUG") == "" {
		return slog.New(slog.DiscardHandler)
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// innerRACK selects RACK loss detection for the TCP inside the tunnel.
var innerRACK bool

// benchMaxLanes lets an experiment cap the lane count (BENCH_MAXLANES).
func benchMaxLanes() int {
	n, _ := strconv.Atoi(os.Getenv("BENCH_MAXLANES"))
	return n
}

// --- traffic inside the tunnel ---

const (
	bulkPort = 5001
	echoPort = 7
)

// transfer is a bulk TCP download from the server peer to the client peer,
// running until stopped.
type transfer struct {
	bytes   atomic.Int64
	mu      sync.Mutex
	lastAt  time.Time
	gaps    []gap
	stop    context.CancelFunc
	done    chan struct{}
	started time.Time
	err     error
}

type gap struct {
	at time.Time
	d  time.Duration
}

func startDownload(ctx context.Context, e *env) (*transfer, error) {
	ln, err := e.server.Net.ListenTCPAddrPort(netip.AddrPortFrom(e.server.Addr, bulkPort))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	t := &transfer{stop: cancel, done: make(chan struct{}), started: time.Now()}
	go func() {
		c, err := ln.Accept()
		ln.Close()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64<<10)
		go func() { <-ctx.Done(); c.Close() }()
		for ctx.Err() == nil {
			if _, err := c.Write(buf); err != nil {
				return
			}
		}
	}()
	c, err := e.client.Net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(e.server.Addr, bulkPort))
	if err != nil {
		cancel()
		return nil, err
	}
	go func() {
		defer close(t.done)
		defer c.Close()
		go func() { <-ctx.Done(); c.Close() }()
		buf := make([]byte, 64<<10)
		t.lastAt = time.Now()
		for {
			n, err := c.Read(buf)
			now := time.Now()
			if n > 0 {
				t.bytes.Add(int64(n))
				t.mu.Lock()
				if d := now.Sub(t.lastAt); d > 20*time.Millisecond {
					t.gaps = append(t.gaps, gap{at: t.lastAt, d: d})
				}
				t.lastAt = now
				t.mu.Unlock()
			}
			if err != nil {
				if ctx.Err() == nil {
					t.err = err
				}
				return
			}
		}
	}()
	return t, nil
}

// Stop ends the transfer and waits for it.
func (t *transfer) Stop() {
	t.stop()
	<-t.done
}

// rate measures throughput over d, in bits per second.
func (t *transfer) rate(ctx context.Context, d time.Duration) float64 {
	b0, t0 := t.bytes.Load(), time.Now()
	select {
	case <-time.After(d):
	case <-ctx.Done():
	case <-t.done:
	}
	return float64(t.bytes.Load()-b0) * 8 / time.Since(t0).Seconds()
}

// maxGap is the longest pause between reads in [from, to).
func (t *transfer) maxGap(from, to time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	var m time.Duration
	for _, g := range t.gaps {
		end := g.at.Add(g.d)
		if end.After(from) && g.at.Before(to) && g.d > m {
			m = g.d
		}
	}
	return m
}

// pinger measures round trips inside the tunnel with a UDP echo.
type pinger struct {
	srv  io.Closer
	conn net.Conn
	seq  uint32
	buf  []byte
}

func newPinger(e *env) (*pinger, error) {
	s, err := e.server.Net.ListenUDPAddrPort(netip.AddrPortFrom(e.server.Addr, echoPort))
	if err != nil {
		return nil, err
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := s.ReadFrom(buf)
			if err != nil {
				return
			}
			s.WriteTo(buf[:n], a)
		}
	}()
	c, err := e.client.Net.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(e.server.Addr, echoPort))
	if err != nil {
		s.Close()
		return nil, err
	}
	return &pinger{srv: s, conn: c, buf: make([]byte, 64)}, nil
}

func (p *pinger) Close() { p.conn.Close(); p.srv.Close() }

// ping sends one 64-byte probe, like ping(8), and waits for its echo.
func (p *pinger) ping(ctx context.Context, timeout time.Duration) (time.Duration, error) {
	p.seq++
	msg := make([]byte, 64)
	msg[0], msg[1], msg[2], msg[3] = byte(p.seq>>24), byte(p.seq>>16), byte(p.seq>>8), byte(p.seq)
	start := time.Now()
	if _, err := p.conn.Write(msg); err != nil {
		return 0, err
	}
	deadline := start.Add(timeout)
	for {
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		p.conn.SetReadDeadline(deadline)
		n, err := p.conn.Read(p.buf)
		if err != nil {
			return 0, err
		}
		if n >= 4 && bytes.Equal(p.buf[:4], msg[:4]) {
			return time.Since(start), nil
		}
	}
}

func percentile(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[min(len(s)-1, int(p*float64(len(s))))]
}

// linkBytes is everything the link carried in both directions.
func linkBytes(L *link.Link) uint64 {
	up, down := L.Stats()
	return up.Bytes + down.Bytes
}
