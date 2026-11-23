package tectonic_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic"
	"github.com/pangeavpn/tectonic/server"
)

// echKey makes an ECH key as a CDN publishes one (X25519, HKDF-SHA256, AES-128-GCM), and the
// ECHConfigList a client is given for it.
func echKey(t *testing.T, publicName string) (tls.EncryptedClientHelloKey, []byte) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	c := []byte{1}                               // config_id
	c = binary.BigEndian.AppendUint16(c, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	c = binary.BigEndian.AppendUint16(c, uint16(len(pub)))
	c = append(c, pub...)
	c = binary.BigEndian.AppendUint16(c, 4)      // one cipher suite:
	c = binary.BigEndian.AppendUint16(c, 0x0001) // HKDF-SHA256
	c = binary.BigEndian.AppendUint16(c, 0x0001) // AES-128-GCM
	c = append(c, 0, byte(len(publicName)))      // maximum_name_length, public_name
	c = append(c, publicName...)
	c = binary.BigEndian.AppendUint16(c, 0) // no extensions
	config := binary.BigEndian.AppendUint16([]byte{0xfe, 0x0d}, uint16(len(c)))
	config = append(config, c...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	return tls.EncryptedClientHelloKey{Config: config, PrivateKey: priv.Bytes(), SendAsRetry: true}, append(list, config...)
}

// firstWrite keeps the first bytes a connection writes: its ClientHello.
type firstWrite struct {
	net.Conn
	mu    *sync.Mutex
	hello *[]byte
}

func (c firstWrite) Write(b []byte) (int, error) {
	c.mu.Lock()
	if *c.hello == nil {
		*c.hello = bytes.Clone(b)
	}
	c.mu.Unlock()
	return c.Conn.Write(b)
}

// A network that blocks the node and reads names in ClientHellos sees the CDN host on a CDN lane,
// unless the CDN publishes ECH, as Chrome would use: then it sees the CDN's public name alone.
func TestCDNLanesHideTheirHostWithECH(t *testing.T) {
	const host, public = "edge.cdn.test", "cdn-public.test"
	for _, ech := range []bool{false, true} {
		edgeSecret := []byte("edge")
		n := startNode(t, "127.0.0.1:9", func(c *server.Config) {
			c.CDN = &server.CDNConfig{Path: "/static/socket", Verify: server.EdgeHeader("Edge-Signature", edgeSecret, nil)}
		})
		key, list := echKey(t, public)
		route := &tectonic.CDNRoute{Host: host, Path: "/static/socket"}
		var mods []func(*tls.Config)
		if ech {
			route.ECH = list
			mods = append(mods, func(c *tls.Config) { c.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{key} })
		}
		route.Edge = edge(t, n.addr, edgeSecret, mods...)
		p := n.profile(t)
		p.CDN = route
		var mu sync.Mutex
		var hello []byte
		c, err := tectonic.Dial(context.Background(), tectonic.Config{
			Profile: p, RootCAs: certs().roots, SNIMode: tectonic.SNIOwn,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr == n.addr {
					return nil, errors.New("connection timed out") // the node's address is null-routed
				}
				conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return firstWrite{conn, &mu, &hello}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err = c.WaitForSession(ctx, 0)
		cancel()
		c.Close()
		if err != nil {
			t.Fatalf("ech %v: %v", ech, err)
		}
		mu.Lock()
		clear := bytes.Contains(hello, []byte(host))
		named := bytes.Contains(hello, []byte(public))
		mu.Unlock()
		switch {
		case !ech && !clear:
			t.Fatal("without ECH the ClientHello did not carry the CDN host, so this test sees nothing")
		case ech && clear:
			t.Fatal("with ECH the CDN host still went in the clear")
		case ech && !named:
			t.Fatal("with ECH the ClientHello did not name the CDN's public name")
		}
	}
}
