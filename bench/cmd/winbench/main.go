// Command winbench runs a Tectonic client on one host against a node on another, so the client's
// lanes run over that host's own TCP: a Windows client against a node in WSL that shapes its uplink.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/pangeavpn/tectonic"
	"github.com/pangeavpn/tectonic/bench/internal/stacktune"
	"github.com/pangeavpn/tectonic/bench/wgnet"
	"github.com/pangeavpn/tectonic/server"
	"github.com/pangeavpn/tectonic/wire"
)

const (
	coverDomain = "node.bench.test"
	wgPort      = 51999
	sinkPort    = 9000
	echoPort    = 9001
)

var (
	nodeSecret = bytes.Repeat([]byte{0x5a}, 32)
	clientAddr = netip.MustParseAddr("192.168.77.1")
	serverAddr = netip.MustParseAddr("192.168.77.2")
	clientKey  = fixedKey(1)
	serverKey  = fixedKey(2)
)

func fixedKey(b byte) *ecdh.PrivateKey {
	k, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		panic(err)
	}
	return k
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: winbench node|client [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "node":
		err = runNode(os.Args[2:])
	case "client":
		err = runClient(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "winbench:", err)
		os.Exit(1)
	}
}

func logger(debug bool) *slog.Logger {
	if !debug {
		return slog.New(slog.DiscardHandler)
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func newPeer(addr netip.Addr, bind conn.Bind, uapi string, verbose bool) (*netstack.Net, *device.Device, error) {
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, wgnet.DefaultMTU)
	if err != nil {
		return nil, nil, err
	}
	f := reflect.ValueOf(tnet).Elem().FieldByName("stack")
	if !f.IsValid() || f.Type() != reflect.TypeFor[*stack.Stack]() {
		return nil, nil, errors.New("netstack.Net has no stack field")
	}
	if err := stacktune.Tune(*(**stack.Stack)(unsafe.Pointer(f.UnsafeAddr())), true); err != nil {
		return nil, nil, err
	}
	level := device.LogLevelSilent
	if verbose {
		level = device.LogLevelVerbose
	}
	dev := device.NewDevice(tdev, bind, device.NewLogger(level, "wg "))
	if err := dev.IpcSet(uapi); err != nil {
		return nil, nil, err
	}
	return tnet, dev, dev.Up()
}

func runNode(args []string) error {
	fs := flag.NewFlagSet("node", flag.ExitOnError)
	listen := fs.String("listen", ":8443", "address the node listens on")
	dir := fs.String("dir", ".", "directory the CA certificate is written to")
	debug := fs.Bool("debug", false, "log the node's debug output")
	fs.Parse(args)

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "winbench root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "winbench"}, DNSNames: []string{coverDomain},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leaf, caCert, &leafKey.PublicKey, caKey)
	own := tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(filepath.Join(*dir, "ca.pem"), caPEM, 0o644); err != nil {
		return err
	}

	srv, err := server.New(server.Config{
		NodeSecret:         nodeSecret,
		CoverDomain:        coverDomain,
		OwnCertificate:     func() (*tls.Certificate, error) { return &own, nil },
		DefaultCertificate: func() (*tls.Certificate, error) { return &own, nil },
		Cover:              http.NotFoundHandler(),
		WireGuard:          fmt.Sprintf("127.0.0.1:%d", wgPort),
		Logger:             logger(*debug),
	})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	go srv.Serve(ln)

	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=%s/32\n",
		hex.EncodeToString(serverKey.Bytes()), wgPort, hex.EncodeToString(clientKey.PublicKey().Bytes()), clientAddr)
	tnet, _, err := newPeer(serverAddr, conn.NewStdNetBind(), uapi, *debug)
	if err != nil {
		return err
	}
	sl, err := tnet.ListenTCPAddrPort(netip.AddrPortFrom(serverAddr, sinkPort))
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := sl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				n, _ := io.Copy(io.Discard, c)
				binary.Write(c, binary.BigEndian, uint64(n))
			}()
		}
	}()
	ul, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(serverAddr, echoPort))
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := ul.ReadFrom(buf)
			if err != nil {
				return
			}
			ul.WriteTo(buf[:n], a)
		}
	}()
	fmt.Println("node listening on", ln.Addr())
	select {}
}

// probe is one ping: when it went, and its round trip once its echo is back.
type probe struct {
	at   time.Time
	load bool
	rtt  time.Duration
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	node := fs.String("node", "", "the node's address")
	dir := fs.String("dir", ".", "directory holding the node's ca.pem")
	redundant := fs.Bool("redundant", false, "gaming mode")
	lanes := fs.Int("lanes", 0, "base lane count; 0 is the default")
	idle := fs.Duration("idle", 3*time.Second, "how long to ping before the upload")
	dur := fs.Duration("dur", 20*time.Second, "how long to upload")
	interval := fs.Duration("interval", 20*time.Millisecond, "time between pings")
	debug := fs.Bool("debug", false, "log the client's debug output")
	fs.Parse(args)

	caPEM, err := os.ReadFile(filepath.Join(*dir, "ca.pem"))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	id, err := wire.NewKeyID(time.Now().Add(24 * time.Hour))
	if err != nil {
		return err
	}
	dk := wire.DeviceKey(nodeSecret, id)
	ctx := context.Background()
	c, err := tectonic.Dial(ctx, tectonic.Config{
		Profile:   tectonic.Profile{Node: *node, CoverDomain: coverDomain, KeyID: id[:], DeviceKey: dk[:]},
		SNIMode:   tectonic.SNIOwn,
		RootCAs:   roots,
		Lanes:     *lanes,
		Redundant: *redundant,
		Logger:    logger(*debug),
	})
	if err != nil {
		return err
	}
	defer c.Close()
	uapi := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=%s/32\n",
		hex.EncodeToString(clientKey.Bytes()), hex.EncodeToString(serverKey.PublicKey().Bytes()), *node, serverAddr)
	tnet, dev, err := newPeer(clientAddr, wgnet.NewPacketConnBind(c), uapi, *debug)
	if err != nil {
		return err
	}
	defer dev.Close()
	uc, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(serverAddr, echoPort))
	if err != nil {
		return err
	}
	defer uc.Close()
	buf := make([]byte, 64)
	up := false
	for deadline := time.Now().Add(20 * time.Second); !up && time.Now().Before(deadline); {
		uc.Write(buf)
		uc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err := uc.Read(buf)
		up = err == nil
	}
	if !up {
		return errors.New("the tunnel never came up")
	}
	uc.SetReadDeadline(time.Time{})

	var mu sync.Mutex
	var probes []probe
	var loading bool
	go func() {
		rb := make([]byte, 64)
		for {
			n, err := uc.Read(rb)
			if err != nil {
				return
			}
			if n < 4 {
				continue
			}
			seq := binary.BigEndian.Uint32(rb)
			mu.Lock()
			if int(seq) < len(probes) && probes[seq].rtt == 0 {
				probes[seq].rtt = time.Since(probes[seq].at)
			}
			mu.Unlock()
		}
	}()
	stop := make(chan struct{})
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		t := time.NewTicker(*interval)
		defer t.Stop()
		msg := make([]byte, 64)
		for {
			select {
			case <-stop:
				return
			case <-t.C:
			}
			mu.Lock()
			binary.BigEndian.PutUint32(msg, uint32(len(probes)))
			probes = append(probes, probe{at: time.Now(), load: loading})
			mu.Unlock()
			uc.Write(msg)
		}
	}()

	time.Sleep(*idle)
	mu.Lock()
	loading = true
	mu.Unlock()
	tc, err := tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(serverAddr, sinkPort))
	if err != nil {
		return err
	}
	start := time.Now()
	chunk := make([]byte, 64<<10)
	for time.Since(start) < *dur {
		if _, err := tc.Write(chunk); err != nil {
			return err
		}
	}
	tc.CloseWrite()
	var got uint64
	if err := binary.Read(tc, binary.BigEndian, &got); err != nil {
		return err
	}
	took := time.Since(start)
	tc.Close()
	mu.Lock()
	loading = false
	mu.Unlock()
	time.Sleep(time.Second) // the last pings' echoes
	close(stop)
	<-pingDone

	mu.Lock()
	defer mu.Unlock()
	var idleRTT, loadRTT []time.Duration
	lost := 0
	for _, p := range probes {
		switch {
		case p.rtt == 0 && time.Since(p.at) > time.Second:
			lost++
		case p.rtt == 0:
		case p.load:
			loadRTT = append(loadRTT, p.rtt)
		default:
			idleRTT = append(idleRTT, p.rtt)
		}
	}
	st := c.Stats()
	fmt.Printf("upload %.2f Mbit/s (%d bytes in %v)  idle p50 %v  load p50 %v p95 %v p99 %v max %v  lost %d/%d  lanes %d dropped %d dupes %d\n",
		float64(got)*8/took.Seconds()/1e6, got, took.Round(time.Millisecond),
		pct(idleRTT, 0.5), pct(loadRTT, 0.5), pct(loadRTT, 0.95), pct(loadRTT, 0.99), pct(loadRTT, 1),
		lost, len(probes), st.Lanes, st.Dropped, st.Dupes)
	return nil
}

func pct(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := int(p * float64(len(s)-1))
	return s[i].Round(100 * time.Microsecond)
}
