package tectonic_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/pangeavpn/tectonic"
)

// countConn counts what the node sends.
type countConn struct {
	net.Conn
	n *atomic.Int64
}

func (c countConn) Read(b []byte) (int, error) {
	k, err := c.Conn.Read(b)
	c.n.Add(int64(k))
	return k, err
}

// The next Conn's first lane resumes TLS when the daemon shares the cache, as a returning browser
// would: the node sends no certificate, and the session is up on less.
func TestTheNextConnResumesWithASharedSessionCache(t *testing.T) {
	n := startNode(t, "127.0.0.1:9", nil)
	second := func(shared bool) (int64, time.Duration) {
		cache := utls.NewLRUClientSessionCache(8)
		var down atomic.Int64
		var took time.Duration
		for i := range 2 {
			down.Store(0)
			cfg := tectonic.Config{Profile: n.profile(t), RootCAs: certs().roots, SNIMode: tectonic.SNIOwn, Network: "home", Lanes: 1,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
					if err != nil {
						return nil, err
					}
					return countConn{c, &down}, nil
				}}
			if shared {
				cfg.SessionCache = cache
			}
			start := time.Now()
			c, err := tectonic.Dial(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.WaitForSession(context.Background(), 5*time.Second); err != nil {
				t.Fatal(err)
			}
			took = time.Since(start)
			if i == 0 {
				time.Sleep(100 * time.Millisecond) // the ticket follows the handshake
			}
			c.Close()
		}
		return down.Load(), took
	}
	full, fullTook := second(false)
	resumed, resumedTook := second(true)
	t.Logf("the second Conn's session was up after %d bytes from the node in %v alone, %d in %v with a shared cache",
		full, fullTook.Round(time.Microsecond), resumed, resumedTook.Round(time.Microsecond))
	if resumed >= full {
		t.Fatalf("with a shared cache the node sent %d bytes, without %d: the first lane did not resume", resumed, full)
	}
}
