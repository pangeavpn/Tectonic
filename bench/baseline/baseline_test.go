package baseline

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/bench/link"
	"github.com/pangeavpn/tectonic/bench/wgnet"
	utls "github.com/refraction-networking/utls"
)

var kinds = []Kind{Reality, AnyTLS}

// udpEcho starts a UDP echo server on loopback.
func udpEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 65536)
		for {
			n, addr, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			pc.WriteTo(b[:n], addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

// serve runs Serve on l until the test ends.
func serve(t *testing.T, kind Kind, l net.Listener, wg *net.UDPAddr) {
	t.Helper()
	cert, err := SelfSignedCert("www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, kind, l, cert, wg) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
}

// pingPong sends datagrams of assorted sizes one at a time and checks each
// echo.
func pingPong(t *testing.T, pc net.PacketConn, n int) {
	t.Helper()
	buf := make([]byte, 65536)
	for i := range n {
		size := 1 + (i*97)%1420
		if i == n-1 {
			size = 8000 // larger than a TLS record at first
		}
		want := make([]byte, size)
		rand.Read(want)
		if _, err := pc.WriteTo(want, nil); err != nil {
			t.Fatalf("datagram %d: write: %v", i, err)
		}
		pc.SetReadDeadline(time.Now().Add(5 * time.Second))
		m, addr, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d: read: %v", i, err)
		}
		if addr == nil {
			t.Fatalf("datagram %d: nil address", i)
		}
		if !bytes.Equal(buf[:m], want) {
			t.Fatalf("datagram %d: got %d bytes, want %d", i, m, size)
		}
	}
}

func TestRoundTripLoopback(t *testing.T) {
	for _, kind := range kinds {
		t.Run(kind.String(), func(t *testing.T) {
			echo := udpEcho(t)
			l, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			serve(t, kind, l, echo)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pc, err := Dial(ctx, kind, func(ctx context.Context) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", l.Addr().String())
			}, "www.example.com")
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			st := pc.(*packetConn).conn.(*utls.UConn).ConnectionState()
			if st.Version != utls.VersionTLS13 || st.NegotiatedProtocol != "h2" {
				t.Errorf("negotiated version %#x ALPN %q, want TLS 1.3 and h2", st.Version, st.NegotiatedProtocol)
			}
			pingPong(t, pc, 40) // well past AnyTLS's padded writes
		})
	}
}

func TestRoundTripOverLink(t *testing.T) {
	for _, kind := range kinds {
		t.Run(kind.String(), func(t *testing.T) {
			l, err := link.New(link.Config{RTT: 10 * time.Millisecond, Bandwidth: 50e6})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { l.Close() }) // after Serve's cleanup stops it
			ln, err := l.Server.ListenTCP(443)
			if err != nil {
				t.Fatal(err)
			}
			serve(t, kind, ln, udpEcho(t))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pc, err := Dial(ctx, kind, func(ctx context.Context) (net.Conn, error) {
				return l.Client.DialTCP(ctx, netip.AddrPortFrom(link.ServerAddr, 443))
			}, "www.example.com")
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			pingPong(t, pc, 10)
			if fl := l.Flows(); len(fl) != 1 || fl[0].Proto != link.ProtoTCP {
				t.Errorf("flows %v, want exactly one TCP connection", fl)
			}
		})
	}
}

// TestWireGuardOverBaseline is the shape of a benchmark run: a WireGuard
// client whose datagrams ride a baseline PacketConn, a baseline server
// forwarding to a WireGuard server on real loopback UDP, and a TCP stream
// inside the tunnel.
func TestWireGuardOverBaseline(t *testing.T) {
	for _, kind := range kinds {
		t.Run(kind.String(), func(t *testing.T) {
			l, err := link.New(link.Config{RTT: 20 * time.Millisecond, Bandwidth: 100e6})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { l.Close() }) // after Serve's cleanup stops it
			ln, err := l.Server.ListenTCP(443)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// The server WireGuard has to exist before the client's
			// transport, so start it with a throwaway client bind and
			// point Serve at its port.
			probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			wgPort := probe.LocalAddr().(*net.UDPAddr).Port
			probe.Close()
			serve(t, kind, ln, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: wgPort})

			pc, err := Dial(ctx, kind, func(ctx context.Context) (net.Conn, error) {
				return l.Client.DialTCP(ctx, netip.AddrPortFrom(link.ServerAddr, 443))
			}, "www.example.com")
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			client, server, err := wgnet.NewPair(wgnet.PairConfig{
				ClientBind:       wgnet.NewPacketConnBind(pc),
				ServerListenPort: uint16(wgPort),
				ServerEndpoint:   "192.0.2.1:51820", // ignored by the transport
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			defer server.Close()

			tl, err := server.Net.ListenTCPAddrPort(netip.AddrPortFrom(server.Addr, 80))
			if err != nil {
				t.Fatal(err)
			}
			defer tl.Close()
			go func() {
				c, err := tl.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				io.Copy(c, c)
			}()
			c, err := client.Net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(server.Addr, 80))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			want := make([]byte, 512<<10)
			rand.Read(want)
			go c.Write(want)
			got := make([]byte, len(want))
			if _, err := io.ReadFull(c, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("tunnel corrupted the stream")
			}
		})
	}
}

func TestPacketConnDeadlineAndClose(t *testing.T) {
	echo := udpEcho(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serve(t, Reality, l, echo)
	pc, err := Dial(context.Background(), Reality, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", l.Addr().String())
	}, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := pc.ReadFrom(make([]byte, 10)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom past deadline: %v", err)
	}
	pc.SetReadDeadline(time.Time{})
	pingPong(t, pc, 2)

	errc := make(chan error, 1)
	go func() {
		_, _, err := pc.ReadFrom(make([]byte, 10))
		errc <- err
	}()
	time.Sleep(20 * time.Millisecond)
	pc.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("ReadFrom after Close: %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock ReadFrom")
	}
	if _, err := pc.WriteTo([]byte("x"), nil); !errors.Is(err, net.ErrClosed) {
		t.Errorf("WriteTo after Close: %v, want net.ErrClosed", err)
	}
}

func TestPaddingScheme(t *testing.T) {
	s := defaultPadding
	if s.stop != 8 {
		t.Errorf("stop = %d, want 8", s.stop)
	}
	if got := s.sizes(0); len(got) != 1 || got[0] != 30 {
		t.Errorf("sizes(0) = %v, want [30]", got)
	}
	for range 100 {
		if got := s.sizes(1); len(got) != 1 || got[0] < 100 || got[0] >= 400 {
			t.Fatalf("sizes(1) = %v, want one size in [100, 400)", got)
		}
		got := s.sizes(2)
		if len(got) != 9 || got[0] < 400 || got[0] >= 500 {
			t.Fatalf("sizes(2) = %v", got)
		}
		for i := 1; i < 9; i += 2 {
			if got[i] != checkMark || got[i+1] < 500 || got[i+1] >= 1000 {
				t.Fatalf("sizes(2) = %v, want c,500-1000 pairs", got)
			}
		}
		if got := s.sizes(3); len(got) != 2 || got[0] != 9 {
			t.Fatalf("sizes(3) = %v, want [9, 500-1000)", got)
		}
	}
	if got := s.sizes(8); got != nil {
		t.Errorf("sizes(8) = %v, want none", got)
	}
	if _, err := parsePaddingScheme("0=30-30"); err == nil {
		t.Error("scheme without stop parsed")
	}
}

// recConn records the size of every Write.
type recConn struct {
	net.Conn
	writes []int
}

func (c *recConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, len(b))
	return len(b), nil
}

func TestAnyTLSWritePadding(t *testing.T) {
	rc := &recConn{}
	w := anytlsWriter{conn: rc, padding: defaultPadding}
	write := func(n int) []int {
		rc.writes = nil
		if err := w.writeConn(make([]byte, n)); err != nil {
			t.Fatal(err)
		}
		return rc.writes
	}
	// Write 1: 100-400, padded.
	if got := write(60); len(got) != 1 || got[0] < 100 || got[0] >= 400 {
		t.Errorf("write 1 sizes %v", got)
	}
	// Write 2: a small payload fills the first piece and stops at "c".
	if got := write(150); len(got) != 1 || got[0] < 400 || got[0] >= 500 {
		t.Errorf("write 2 sizes %v", got)
	}
	// Write 3: 9 bytes, then the rest padded to 500-1000.
	if got := write(100); len(got) != 2 || got[0] != 9 || got[1] < 500 || got[1] >= 1000 {
		t.Errorf("write 3 sizes %v", got)
	}
	// Write 4: a payload bigger than its piece is split, the rest sent as is.
	if got := write(1500); len(got) != 2 || got[0] < 500 || got[0] >= 1000 || got[0]+got[1] != 1500 {
		t.Errorf("write 4 sizes %v", got)
	}
	for i := 5; i < 8; i++ {
		write(10)
	}
	// Write 8 onwards: no padding.
	if got := write(10); len(got) != 1 || got[0] != 10 {
		t.Errorf("write 8 sizes %v, want [10]", got)
	}
}
