package wgnet

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/bench/link"
	"golang.zx2c4.com/wireguard/conn"
)

// echoOverTunnel runs a TCP echo server on the server peer's tunnel address
// and checks that n random bytes come back intact through the client.
func echoOverTunnel(t *testing.T, client, server *Peer, port uint16, n int) {
	t.Helper()
	ln, err := server.Net.ListenTCPAddrPort(netip.AddrPortFrom(server.Addr, port))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(server.Addr, port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))

	want := make([]byte, n)
	rand.Read(want)
	go c.Write(want)
	got := make([]byte, n)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("echoed bytes differ")
	}
}

func TestPairStdNetBind(t *testing.T) {
	client, server, err := NewPair(PairConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()
	port, err := server.ListenPort()
	if err != nil || port == 0 {
		t.Fatalf("ListenPort = %d, %v", port, err)
	}
	t.Logf("server WireGuard on UDP port %d", port)
	echoOverTunnel(t, client, server, 7, 1<<20)
}

// TestPairPacketConnBind runs the client through PacketConnBind on a real
// loopback socket against a StdNetBind server on a fixed port, the shape a
// transport client and a Tectonic server forwarding to loopback will have.
func TestPairPacketConnBind(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// Find a free port for the server.
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(probe.LocalAddr().(*net.UDPAddr).Port)
	probe.Close()

	client, server, err := NewPair(PairConfig{
		ClientBind:          NewPacketConnBind(pc),
		ServerListenPort:    port,
		PersistentKeepalive: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()
	if got, err := server.ListenPort(); err != nil || got != port {
		t.Fatalf("server ListenPort = %d, %v; want %d", got, err, port)
	}
	echoOverTunnel(t, client, server, 7, 256<<10)
}

func TestPairOverLink(t *testing.T) {
	l, err := link.New(link.Config{RTT: 10 * time.Millisecond, Bandwidth: 50e6})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cpc, err := l.Client.ListenUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	defer cpc.Close()
	spc, err := l.Server.ListenUDP(51820)
	if err != nil {
		t.Fatal(err)
	}
	defer spc.Close()

	client, server, err := NewPair(PairConfig{
		ClientBind:     NewPacketConnBind(cpc),
		ServerBind:     NewPacketConnBind(spc),
		ServerEndpoint: netip.AddrPortFrom(link.ServerAddr, 51820).String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()
	echoOverTunnel(t, client, server, 7, 256<<10)

	up, down := l.Stats()
	t.Logf("link up %+v down %+v", up, down)
	flows := l.Flows()
	if len(flows) != 1 || flows[0].Proto != link.ProtoUDP || flows[0].Dst.Port() != 51820 {
		t.Errorf("flows %v, want one UDP flow to port 51820", flows)
	}
}

// TestBindReopen checks the bind's close/reopen cycle, which wireguard-go
// runs on every Up and listen-port change: Close unblocks a pending receive
// with net.ErrClosed without closing the PacketConn, and a reopened bind
// receives again. (A full Down/Up of a device works too, but WireGuard then
// waits out its 5 s rekey timeout before the next handshake.)
func TestBindReopen(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	b := NewPacketConnBind(pc)
	bufs, sizes, eps := [][]byte{make([]byte, 1500)}, make([]int, 1), make([]conn.Endpoint, 1)

	for round := range 3 {
		fns, port, err := b.Open(0)
		if err != nil {
			t.Fatal(err)
		}
		if int(port) != pc.LocalAddr().(*net.UDPAddr).Port {
			t.Fatalf("Open reported port %d", port)
		}
		if _, _, err := b.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
			t.Fatalf("second Open: %v", err)
		}

		// A datagram sent to the bind's own address comes back through
		// the receive function with a usable endpoint.
		ep, err := b.ParseEndpoint(pc.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte(fmt.Sprintf("round %d", round))
		if err := b.Send([][]byte{msg}, ep); err != nil {
			t.Fatal(err)
		}
		n, err := fns[0](bufs, sizes, eps)
		if err != nil || n != 1 || string(bufs[0][:sizes[0]]) != string(msg) {
			t.Fatalf("receive = %d, %v, %q", n, err, bufs[0][:sizes[0]])
		}
		if eps[0].DstToString() != pc.LocalAddr().String() {
			t.Errorf("endpoint %q, want %q", eps[0].DstToString(), pc.LocalAddr())
		}

		errc := make(chan error, 1)
		go func() {
			_, err := fns[0](bufs, sizes, eps)
			errc <- err
		}()
		time.Sleep(20 * time.Millisecond)
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-errc:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("receive after Close: %v, want net.ErrClosed", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Close did not unblock receive")
		}
	}
}
