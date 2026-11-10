package link

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newLink(t *testing.T, cfg Config) *Link {
	t.Helper()
	l, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// tcpPair returns the two ends of a TCP connection dialled from the client
// host to the server host.
func tcpPair(t *testing.T, l *Link, port uint16) (client, server net.Conn) {
	t.Helper()
	ln, err := l.Server.ListenTCP(port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err = l.Client.DialTCP(ctx, netip.AddrPortFrom(ServerAddr, port))
	if err != nil {
		t.Fatal(err)
	}
	server, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

func within(t *testing.T, what string, got, lo, hi time.Duration) {
	t.Helper()
	t.Logf("%s: %v", what, got)
	if got < lo || got > hi {
		t.Errorf("%s = %v, want within [%v, %v]", what, got, lo, hi)
	}
}

func TestRTT(t *testing.T) {
	const rtt = 40 * time.Millisecond
	l := newLink(t, Config{RTT: rtt, Bandwidth: 100e6})
	lo, hi := rtt-time.Millisecond, rtt+25*time.Millisecond

	ln, err := l.Server.ListenTCP(80)
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
			go io.Copy(c, c)
		}
	}()

	start := time.Now()
	c, err := l.Client.DialTCP(context.Background(), netip.AddrPortFrom(ServerAddr, 80))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	within(t, "TCP connect", time.Since(start), lo, hi)

	buf := make([]byte, 5)
	start = time.Now()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	within(t, "TCP echo", time.Since(start), lo, hi)

	srv, err := l.Server.ListenUDP(7)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, addr, err := srv.ReadFrom(b)
			if err != nil {
				return
			}
			srv.WriteTo(b[:n], addr)
		}
	}()
	cli, err := l.Client.ListenUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ServerAddr, 7))
	for range 3 {
		start = time.Now()
		if _, err := cli.WriteTo([]byte("ping"), dst); err != nil {
			t.Fatal(err)
		}
		cli.SetReadDeadline(time.Now().Add(time.Second))
		if _, _, err := cli.ReadFrom(buf); err != nil {
			t.Fatal(err)
		}
		within(t, "UDP echo", time.Since(start), lo, hi)
	}
}

// udpBlast sends n numbered datagrams of size bytes from the client host to
// the server host and returns the arrival time of each one received, indexed
// by sequence number (zero if lost). It stops waiting once the link has been
// quiet for idle.
func udpBlast(t *testing.T, l *Link, n, size int, pace func(i int), idle time.Duration) []time.Time {
	t.Helper()
	srv, err := l.Server.ListenUDP(9)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := l.Client.ListenUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	arrivals := make([]time.Time, n)
	var last uint32 // highest sequence seen, to check ordering
	var outOfOrder atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65536)
		for {
			srv.SetReadDeadline(time.Now().Add(idle))
			m, _, err := srv.ReadFrom(b)
			if err != nil {
				return
			}
			now := time.Now()
			if m < 4 {
				continue
			}
			seq := binary.BigEndian.Uint32(b)
			if int(seq) < n {
				arrivals[seq] = now
			}
			if seq < last {
				outOfOrder.Add(1)
			}
			last = seq
		}
	}()

	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ServerAddr, 9))
	p := make([]byte, size)
	for i := range n {
		binary.BigEndian.PutUint32(p, uint32(i))
		if _, err := cli.WriteTo(p, dst); err != nil {
			t.Fatal(err)
		}
		if pace != nil {
			pace(i)
		}
	}
	<-done
	if k := outOfOrder.Load(); k > 0 {
		t.Errorf("%d datagrams arrived out of order", k)
	}
	return arrivals
}

func TestBandwidth(t *testing.T) {
	const bw = 20e6
	const n, size = 600, 1000
	ipSize := size + 28
	l := newLink(t, Config{Bandwidth: bw, RTT: 10 * time.Millisecond, QueueBytes: 4 << 20})
	arr := udpBlast(t, l, n, size, nil, 300*time.Millisecond)
	for i, a := range arr {
		if a.IsZero() {
			t.Fatalf("datagram %d lost on a lossless link", i)
		}
	}
	got := float64((n-1)*ipSize*8) / arr[n-1].Sub(arr[0]).Seconds()
	t.Logf("delivered %.2f Mbit/s (IP level) on a %.0f Mbit/s link", got/1e6, bw/1e6)
	if got < 0.9*bw || got > 1.1*bw {
		t.Errorf("rate %.2f Mbit/s, want ≈ %.0f", got/1e6, bw/1e6)
	}
	up, _ := l.Stats()
	if up.Packets != n || up.Bytes != uint64(n*ipSize) || up.DroppedQueue != 0 {
		t.Errorf("stats %+v, want %d packets, %d bytes, no drops", up, n, n*ipSize)
	}

	t.Run("queue overflow", func(t *testing.T) {
		l := newLink(t, Config{Bandwidth: bw, RTT: 10 * time.Millisecond, QueueBytes: 64 << 10})
		udpBlast(t, l, n, size, nil, 200*time.Millisecond)
		up, _ := l.Stats()
		t.Logf("stats %+v", up)
		if up.DroppedQueue == 0 || up.Packets+up.DroppedQueue != n {
			t.Errorf("stats %+v, want queue drops accounting for all %d datagrams", up, n)
		}
	})
}

func TestLoss(t *testing.T) {
	const n = 3000
	l := newLink(t, Config{Loss: 0.1, Seed: 1, RTT: 2 * time.Millisecond})
	// Pace lightly so the receiving socket never overflows.
	arr := udpBlast(t, l, n, 64, func(i int) {
		if i%100 == 99 {
			time.Sleep(time.Millisecond)
		}
	}, 200*time.Millisecond)
	lost := 0
	for _, a := range arr {
		if a.IsZero() {
			lost++
		}
	}
	rate := float64(lost) / n
	t.Logf("lost %d/%d = %.3f", lost, n, rate)
	if rate < 0.07 || rate > 0.13 {
		t.Errorf("loss rate %.3f, want ≈ 0.10", rate)
	}
	up, _ := l.Stats()
	if up.DroppedLoss != uint64(lost) {
		t.Errorf("DroppedLoss = %d, application saw %d lost", up.DroppedLoss, lost)
	}
}

// TestBurstLoss checks the Gilbert–Elliott chain directly: its loss rate and
// that losses come in runs rather than alone.
func TestBurstLoss(t *testing.T) {
	ge := &GilbertElliott{PGoodToBad: 0.02, PBadToGood: 0.25, LossBad: 1}
	l := &Link{cfg: Config{Burst: ge, Seed: 7}}
	d := newDirection(l, dirUp, nil)
	const n = 200000
	lost, runs := 0, 0
	prev := false
	for range n {
		x := d.lose()
		if x {
			lost++
			if !prev {
				runs++
			}
		}
		prev = x
	}
	rate := float64(lost) / n
	want := ge.LossBad * ge.PGoodToBad / (ge.PGoodToBad + ge.PBadToGood)
	meanRun := float64(lost) / float64(runs)
	t.Logf("loss %.4f (want %.4f), mean burst %.2f packets (want %.2f)", rate, want, meanRun, 1/ge.PBadToGood)
	if rate < 0.8*want || rate > 1.2*want {
		t.Errorf("loss rate %.4f, want ≈ %.4f", rate, want)
	}
	if meanRun < 3 || meanRun > 5 {
		t.Errorf("mean burst %.2f, want ≈ 4", meanRun)
	}
}

// download streams from the server end of each connection to the client end
// for d and returns each client's goodput in bits/s over the final measure
// interval.
func download(t *testing.T, pairs [][2]net.Conn, d, measure time.Duration) []float64 {
	t.Helper()
	var wg sync.WaitGroup
	rates := make([]float64, len(pairs))
	start := time.Now()
	for i, p := range pairs {
		client, server := p[0], p[1]
		wg.Add(2)
		go func() {
			defer wg.Done()
			b := make([]byte, 32<<10)
			server.SetWriteDeadline(start.Add(d))
			for {
				if _, err := server.Write(b); err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			b := make([]byte, 64<<10)
			from := start.Add(d - measure)
			var n int64
			client.SetReadDeadline(start.Add(d))
			for {
				m, err := client.Read(b)
				if time.Now().After(from) {
					n += int64(m)
				}
				if err != nil {
					break
				}
			}
			rates[i] = float64(n*8) / measure.Seconds()
		}()
	}
	wg.Wait()
	return rates
}

// TestTCPThroughput is the accuracy check from the design document's
// reference link: one TCP flow over 100 Mbit/s with a 50 ms RTT.
func TestTCPThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	const bw = 100e6
	l := newLink(t, Config{Bandwidth: bw, RTT: 50 * time.Millisecond})
	c, s := tcpPair(t, l, 5001)
	const total, measure = 3 * time.Second, 2 * time.Second
	rate := download(t, [][2]net.Conn{{c, s}}, total, measure)[0]
	_, down := l.Stats()
	t.Logf("single TCP flow, 100 Mbit/s, 50 ms RTT: %.1f Mbit/s goodput over the last %v (%.0f%% of link); queue drops %d",
		rate/1e6, measure, 100*rate/bw, down.DroppedQueue)
	if raceEnabled {
		return // the race detector slows the stacks too much to judge
	}
	if rate < 0.5*bw {
		t.Errorf("goodput %.1f Mbit/s, want at least half the link", rate/1e6)
	}
}

func TestPerConnCap(t *testing.T) {
	const capRate = 4e6
	l := newLink(t, Config{PerConnRate: capRate, Bandwidth: 100e6, RTT: 20 * time.Millisecond})
	c1, s1 := tcpPair(t, l, 6001)
	c2, s2 := tcpPair(t, l, 6002)
	rates := download(t, [][2]net.Conn{{c1, s1}, {c2, s2}}, 2*time.Second, time.Second)
	_, down := l.Stats()
	t.Logf("two flows under a %.0f Mbit/s per-connection cap: %.2f and %.2f Mbit/s; cap drops %d",
		capRate/1e6, rates[0]/1e6, rates[1]/1e6, down.DroppedCap)
	for i, r := range rates {
		// Goodput excludes 52 bytes of IP and TCP headers per 1500.
		if r < 0.7*capRate || r > 1.05*capRate {
			t.Errorf("flow %d: %.2f Mbit/s, want ≈ %.0f each", i, r/1e6, capRate/1e6)
		}
	}
}

func findFlow(t *testing.T, l *Link, proto uint8, port uint16) Flow {
	t.Helper()
	for _, f := range l.Flows() {
		if f.Proto == proto && (f.Dst.Port() == port || f.Src.Port() == port) {
			return f
		}
	}
	t.Fatalf("no flow on port %d among %v", port, l.Flows())
	return Flow{}
}

// readErr reads from c until it fails and reports the error and how long
// that took.
func readErr(c net.Conn, timeout time.Duration) <-chan error {
	ch := make(chan error, 1)
	go func() {
		c.SetReadDeadline(time.Now().Add(timeout))
		b := make([]byte, 64<<10)
		for {
			if _, err := c.Read(b); err != nil {
				ch <- err
				return
			}
		}
	}()
	return ch
}

func checkReset(t *testing.T, side string, ch <-chan error) {
	t.Helper()
	err := <-ch
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Errorf("%s: still open after reset: %v", side, err)
	} else {
		t.Logf("%s: %v", side, err)
	}
}

func TestResetFlow(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		l := newLink(t, Config{RTT: 20 * time.Millisecond})
		c, s := tcpPair(t, l, 443)
		if _, err := c.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(s, make([]byte, 5)); err != nil {
			t.Fatal(err)
		}
		f := findFlow(t, l, ProtoTCP, 443)
		if f.Src.Addr() != ClientAddr || f.Dst != netip.AddrPortFrom(ServerAddr, 443) {
			t.Errorf("flow %v, want client → server:443", f)
		}
		ce, se := readErr(c, time.Second), readErr(s, time.Second)
		time.Sleep(50 * time.Millisecond) // let the delayed ACK go out
		if err := l.ResetFlow(f); err != nil {
			t.Fatal(err)
		}
		checkReset(t, "client", ce)
		checkReset(t, "server", se)
	})

	t.Run("mid-transfer", func(t *testing.T) {
		l := newLink(t, Config{RTT: 20 * time.Millisecond, Bandwidth: 50e6})
		c, s := tcpPair(t, l, 443)
		go func() {
			b := make([]byte, 16<<10)
			for {
				if _, err := s.Write(b); err != nil {
					return
				}
			}
		}()
		ce := readErr(c, 2*time.Second)
		time.Sleep(300 * time.Millisecond)
		// The reversed orientation must work too.
		f := findFlow(t, l, ProtoTCP, 443)
		if err := l.ResetFlow(Flow{Proto: f.Proto, Src: f.Dst, Dst: f.Src}); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		checkReset(t, "client", ce)
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Errorf("client noticed the reset after %v", d)
		}
		// The writer fails once the reset lands.
		s.SetWriteDeadline(time.Now().Add(time.Second))
		var err error
		for err == nil {
			_, err = s.Write(make([]byte, 1024))
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Errorf("server: writes still succeed after reset")
		}
	})

	t.Run("errors", func(t *testing.T) {
		l := newLink(t, Config{})
		if err := l.ResetFlow(Flow{Proto: ProtoUDP}); err == nil {
			t.Error("reset of a UDP flow succeeded")
		}
		if err := l.ResetFlow(Flow{Proto: ProtoTCP, Src: netip.MustParseAddrPort("10.0.0.1:1"), Dst: netip.MustParseAddrPort("10.0.0.2:2")}); err == nil {
			t.Error("reset of an unknown flow succeeded")
		}
	})
}

func TestBlackholeFlow(t *testing.T) {
	l := newLink(t, Config{RTT: 10 * time.Millisecond})
	c, s := tcpPair(t, l, 22)
	go io.Copy(s, s)
	echo := func(c net.Conn) error {
		c.SetDeadline(time.Now().Add(300 * time.Millisecond))
		defer c.SetDeadline(time.Time{})
		if _, err := c.Write([]byte("ping")); err != nil {
			return err
		}
		_, err := io.ReadFull(c, make([]byte, 4))
		return err
	}
	if err := echo(c); err != nil {
		t.Fatal(err)
	}
	l.BlackholeFlow(findFlow(t, l, ProtoTCP, 22))
	var ne net.Error
	if err := echo(c); !errors.As(err, &ne) || !ne.Timeout() {
		t.Errorf("echo over a blackholed flow: %v, want a timeout", err)
	}
	_, down := l.Stats()
	up, _ := l.Stats()
	if up.DroppedBlackhole == 0 {
		t.Errorf("no blackhole drops counted: up %+v down %+v", up, down)
	}

	// Other flows are unaffected.
	c2, s2 := tcpPair(t, l, 23)
	go io.Copy(s2, s2)
	if err := echo(c2); err != nil {
		t.Errorf("echo on a fresh flow: %v", err)
	}
}
