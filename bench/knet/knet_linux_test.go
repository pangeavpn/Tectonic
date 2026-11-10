//go:build linux

package knet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/bench/link"
)

// The tests need their own namespaces, so the test binary re-executes
// itself in them. If that or New is impossible here, every test skips.
var (
	topo    *Topology
	topoErr error
)

func TestMain(m *testing.M) {
	code, ran, err := Reexec()
	if ran {
		os.Exit(code)
	}
	if err != nil {
		topoErr = err
	} else {
		topo, topoErr = New()
	}
	code = m.Run()
	if topo != nil {
		topo.Close()
	}
	os.Exit(code)
}

func setup(t *testing.T, cfg link.Config) *Topology {
	t.Helper()
	if topoErr != nil {
		t.Skipf("no kernel path here: %v", topoErr)
	}
	if err := topo.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	return topo
}

func pair(t *testing.T, tp *Topology, port uint16) (client, server net.Conn) {
	t.Helper()
	ln, err := tp.Server().ListenTCP(port)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err = tp.Client().DialTCP(ctx, netip.AddrPortFrom(ServerAddr, port))
	if err != nil {
		t.Fatal(err)
	}
	server = <-ch
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

func TestRTT(t *testing.T) {
	tp := setup(t, link.Config{RTT: 80 * time.Millisecond})
	ln, err := tp.Server().ListenTCP(1000)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	t0 := time.Now()
	c, err := tp.Client().DialTCP(context.Background(), netip.AddrPortFrom(ServerAddr, 1000))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if d := time.Since(t0); d < 80*time.Millisecond || d > 95*time.Millisecond {
		t.Fatalf("connect took %v on an 80 ms path", d)
	}
}

// download pushes data server→client for d and returns goodput in bit/s.
func download(t *testing.T, client, server net.Conn, warm, d time.Duration) float64 {
	t.Helper()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			if _, err := server.Write(buf); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 64<<10)
	var n int64
	start := time.Now()
	client.SetReadDeadline(start.Add(warm + d))
	var measureFrom time.Time
	for {
		m, err := client.Read(buf)
		if time.Since(start) >= warm {
			if measureFrom.IsZero() {
				measureFrom = time.Now()
			}
			n += int64(m)
		}
		if err != nil {
			break
		}
	}
	return float64(n) * 8 / time.Since(measureFrom).Seconds()
}

func TestBandwidth(t *testing.T) {
	tp := setup(t, link.Config{Bandwidth: 50e6, RTT: 20 * time.Millisecond})
	c, s := pair(t, tp, 1001)
	bps := download(t, c, s, 2*time.Second, 3*time.Second)
	t.Logf("one TCP flow: %.1f Mbit/s on a 50 Mbit/s path", bps/1e6)
	// Goodput is the rate less Ethernet, IP and TCP headers (~5%).
	if bps < 0.88*50e6 || bps > 50e6 {
		t.Fatalf("goodput %.1f Mbit/s, want 44–50", bps/1e6)
	}
	up, down := tp.Stats()
	if down.Packets == 0 || up.Packets == 0 || down.Bytes < down.Packets*1000 {
		t.Fatalf("stats look wrong: up %+v down %+v", up, down)
	}
}

func TestPerConnCap(t *testing.T) {
	tp := setup(t, link.Config{Bandwidth: 100e6, RTT: 20 * time.Millisecond, PerConnRate: 4e6})
	c1, s1 := pair(t, tp, 1002)
	c2, s2 := pair(t, tp, 1003)
	res := make(chan float64, 2)
	go func() { res <- download(t, c1, s1, time.Second, 3*time.Second) }()
	go func() { res <- download(t, c2, s2, time.Second, 3*time.Second) }()
	for range 2 {
		bps := <-res
		t.Logf("capped flow: %.2f Mbit/s", bps/1e6)
		if bps < 3.2e6 || bps > 4.1e6 {
			t.Fatalf("a flow capped at 4 Mbit/s got %.2f Mbit/s", bps/1e6)
		}
	}
}

func TestLoss(t *testing.T) {
	tp := setup(t, link.Config{Loss: 0.05, Seed: 1})
	pc, err := tp.Server().ListenUDP(1004)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	c, err := tp.Client().DialUDP(netip.AddrPortFrom(ServerAddr, 1004))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	const n = 4000
	done := make(chan int)
	go func() { // read as they arrive, or the socket buffer drops them
		got := 0
		buf := make([]byte, 200)
		for {
			pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if _, _, err := pc.ReadFrom(buf); err != nil {
				done <- got
				return
			}
			got++
		}
	}()
	for range n {
		c.Write(make([]byte, 100))
		time.Sleep(50 * time.Microsecond)
	}
	got := <-done
	loss := 1 - float64(got)/n
	up, _ := tp.Stats()
	t.Logf("loss %.3f; stats %+v", loss, up)
	if loss < 0.035 || loss > 0.065 {
		t.Fatalf("lost %.3f of packets, want about 0.05", loss)
	}
	if up.DroppedLoss == 0 {
		t.Fatal("netem drops not counted")
	}
}

func TestResetFlow(t *testing.T) {
	tp := setup(t, link.Config{RTT: 10 * time.Millisecond})
	c, s := pair(t, tp, 1005)
	flows, err := tp.TCPFlows(1005)
	if err != nil || len(flows) != 1 {
		t.Fatalf("flows %v, %v", flows, err)
	}
	if err := tp.ResetFlow(flows[0]); err != nil {
		t.Fatal(err)
	}
	for side, conn := range map[string]net.Conn{"client": c, "server": s} {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err := conn.Read(make([]byte, 1))
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("%s still open after reset: %v", side, err)
		}
		if side == "server" && !errors.Is(err, syscall.ECONNRESET) && err != io.EOF {
			t.Logf("server saw %v", err)
		}
	}
}

func TestServerCC(t *testing.T) {
	tp := setup(t, link.Config{RTT: 10 * time.Millisecond})
	tp.ServerCC = "bbr"
	defer func() { tp.ServerCC = "" }()
	_, s := pair(t, tp, 1006)
	s.Write([]byte("x"))
	if out := tp.SS(true, 1006); !strings.Contains(out, "bbr") {
		t.Fatalf("accepted connection is not BBR:\n%s", out)
	}
}

func TestTUN(t *testing.T) {
	tp := setup(t, link.Config{})
	for _, server := range []bool{false, true} {
		dev, err := tp.TUN(server, netip.MustParseAddr("192.168.99.1"), 1420)
		if err != nil {
			t.Fatal(err)
		}
		if mtu, _ := dev.MTU(); mtu != 1420 {
			t.Fatalf("MTU %d", mtu)
		}
		dev.Close()
	}
	tp.WaitGone(time.Second)
}
