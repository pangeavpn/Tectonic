package tectonic_test

import (
	"context"
	"crypto/tls"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/pangeavpn/tectonic"
	"github.com/pangeavpn/tectonic/server"
)

// The next Conn's first lane resumes TLS when the daemon shares the cache, as a returning browser
// would: the node sends it no certificate.
func TestTheNextConnResumesWithASharedSessionCache(t *testing.T) {
	var full atomic.Int64
	n := startNode(t, "127.0.0.1:9", func(c *server.Config) {
		own := c.OwnCertificate
		c.OwnCertificate = func() (*tls.Certificate, error) {
			full.Add(1)
			return own()
		}
	})
	second := func(shared bool) int64 {
		cache := utls.NewLRUClientSessionCache(8)
		for i := range 2 {
			full.Store(0)
			cfg := tectonic.Config{Profile: n.profile(t), RootCAs: certs().roots, SNIMode: tectonic.SNIOwn, Network: "home", Lanes: 1}
			if shared {
				cfg.SessionCache = cache
			}
			c, err := tectonic.Dial(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.WaitForSession(context.Background(), 5*time.Second); err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				time.Sleep(100 * time.Millisecond) // the ticket follows the handshake
			}
			c.Close()
		}
		return full.Load()
	}
	if k := second(false); k == 0 {
		t.Fatal("the second Conn resumed without a shared cache, so this test shows nothing")
	}
	if k := second(true); k != 0 {
		t.Fatalf("with a shared cache the node sent the second Conn its certificate %d times: the first lane did not resume", k)
	}
}
