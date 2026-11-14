package tectonic_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic"
	"github.com/pangeavpn/tectonic/lane"
)

// interceptor is a TLS-intercepting middlebox: it answers every connection
// with a certificate from its own CA for the cover domain and for its own
// IP address, as an interceptor mints one for whatever the client asked,
// and reports how many plaintext bytes each client sent it after the
// handshake.
func interceptor(t *testing.T) (addr string, roots *x509.CertPool, read <-chan int) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Interceptor CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ca, _ := x509.ParseCertificate(der)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(3), DNSNames: []string{coverDomain},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}, ca, &leafKey.PublicKey, key)
	cert := tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}

	roots = certs().roots.Clone()
	roots.AddCert(ca) // the device trusts the interceptor, as under a corporate or state CA

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan int, 64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
				if s.Handshake() != nil {
					ch <- 0
					return
				}
				s.SetReadDeadline(time.Now().Add(time.Second))
				buf := make([]byte, 4096)
				n, _ := s.Read(buf)
				ch <- n
			}()
		}
	}()
	return ln.Addr().String(), roots, ch
}

func ownPin(t *testing.T) string {
	leaf, err := x509.ParseCertificate(certs().own.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return lane.PinOf(leaf).String()
}

// Without own_pins, a device that trusts an interceptor's CA hands it the
// login; with them, the lane is refused before anything is sent.
func TestOwnPinsRefuseTrustedInterceptor(t *testing.T) {
	n := startNode(t, "127.0.0.1:9", nil)
	for _, pinned := range []bool{false, true} {
		addr, roots, read := interceptor(t)
		p := n.profile(t)
		p.Node = addr
		if pinned {
			p.OwnPins = []string{ownPin(t)}
		}
		c, err := tectonic.Dial(context.Background(), tectonic.Config{Profile: p, RootCAs: roots, SNIMode: tectonic.SNIOwn})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.WaitForSession(context.Background(), 1500*time.Millisecond); err == nil {
			t.Fatalf("pinned=%v: a session came up through the interceptor", pinned)
		}
		c.Close()
		got := <-read
		if pinned && got != 0 {
			t.Fatalf("pinned: the interceptor read %d plaintext bytes", got)
		}
		if !pinned && got == 0 {
			t.Fatal("unpinned: the interceptor read nothing; the test no longer shows the leak it guards against")
		}
	}
}

// None mode with pins refuses a certificate for the node's IP address from
// a CA the device trusts, which an interceptor can mint for any address.
// Without pins it accepts one, as a Let's Encrypt IP certificate.
func TestNoneModePinsRefuseTrustedIPCertificate(t *testing.T) {
	n := startNode(t, "127.0.0.1:9", nil)
	for _, pinned := range []bool{true, false} {
		addr, roots, read := interceptor(t)
		p := n.profile(t)
		p.Node = addr
		if !pinned {
			p.Pins = nil
		}
		c, err := tectonic.Dial(context.Background(), tectonic.Config{Profile: p, RootCAs: roots, SNIMode: tectonic.SNINone})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.WaitForSession(context.Background(), 1500*time.Millisecond); err == nil {
			t.Fatalf("pinned=%v: a session came up through the interceptor", pinned)
		}
		c.Close()
		got := <-read
		if pinned && got != 0 {
			t.Fatalf("pinned: the interceptor read %d plaintext bytes", got)
		}
		if !pinned && got == 0 {
			t.Fatal("unpinned: the interceptor read nothing; the test no longer shows the leak it guards against")
		}
	}
}

// The real node's certificate passes both checks.
func TestOwnPinsAcceptTheNode(t *testing.T) {
	n := startNode(t, "127.0.0.1:9", nil)
	p := n.profile(t)
	p.OwnPins = []string{ownPin(t)}
	c, err := tectonic.Dial(context.Background(), tectonic.Config{Profile: p, RootCAs: certs().roots, SNIMode: tectonic.SNIOwn})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.WaitForSession(context.Background(), 5*time.Second); err != nil {
		t.Fatal(err)
	}
}
