package lane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/shape"
	"github.com/pangeavpn/tectonic/wire"
)

func wgInitiation() []byte {
	p := make([]byte, 148)
	p[0] = 1
	return p
}

func wgKeepalive() []byte {
	p := make([]byte, 32)
	p[0] = 4
	return p
}

func TestDialOwnModeCarriesDataBothWays(t *testing.T) {
	serverSink := newSink()
	n := newTestNode(t, func(n *testNode) { n.handler.Data = serverSink.handler })
	clientSink := newSink()
	cfg := n.dialConfig(t, SNIOwn)
	cfg.FirstPacket = wgInitiation()
	cfg.Lane.Handler.Data = clientSink.handler
	cl := dial(t, cfg)

	if sni := uconnSNI(t, n); sni != coverDomain {
		t.Fatalf("SNI = %q, want %q", sni, coverDomain)
	}
	sl := n.acceptLane(t)
	w := waitWelcome(t, cl)
	if w.SessionID[0] != 0x42 || w.MaxLanes != 6 || w.ResumeWindow != time.Minute {
		t.Fatalf("WELCOME = %+v", w)
	}

	// The first WireGuard packet rode in with HELLO.
	got := serverSink.wait(t, 1)
	if !bytes.Equal(got[0], wgInitiation()) {
		t.Fatal("first packet corrupted")
	}

	for i := range 50 {
		if !cl.Send([]byte(fmt.Sprintf("up %d", i))) {
			t.Fatal("client Send refused")
		}
		if !sl.Send([]byte(fmt.Sprintf("down %d", i))) {
			t.Fatal("server Send refused")
		}
	}
	up := serverSink.wait(t, 51)
	down := clientSink.wait(t, 50)
	for i := range 50 {
		if string(up[i+1]) != fmt.Sprintf("up %d", i) || string(down[i]) != fmt.Sprintf("down %d", i) {
			t.Fatalf("packet %d out of place: %q %q", i, up[i+1], down[i])
		}
	}
	st := cl.Stats()
	if st.PacketsSent != 51 || st.DataRecv == 0 || st.BytesSent < st.DataSent {
		t.Fatalf("stats = %+v", st)
	}
}

func TestSNIModes(t *testing.T) {
	for _, mode := range []SNIMode{SNIBorrowed, SNINone} {
		t.Run(mode.String(), func(t *testing.T) {
			n := newTestNode(t, nil)
			cl := dial(t, n.dialConfig(t, mode))
			sni := uconnSNI(t, n)
			want := map[SNIMode]string{SNIBorrowed: "allowed.example", SNINone: ""}[mode]
			if sni != want {
				t.Fatalf("SNI = %q, want %q", sni, want)
			}
			n.acceptLane(t)
			waitWelcome(t, cl)
		})
	}
}

func TestPinMismatchFails(t *testing.T) {
	n := newTestNode(t, nil)
	for _, mode := range []SNIMode{SNIBorrowed, SNINone} {
		cfg := n.dialConfig(t, mode)
		cfg.Pins = []Pin{{1, 2, 3}}
		cfg.RootCAs = nil
		if _, err := Dial(context.Background(), cfg); err == nil {
			t.Fatalf("%v: dial succeeded with the wrong pin", mode)
		}
	}
	// Own mode checks the name: a server with a certificate for another
	// name must fail.
	cfg := n.dialConfig(t, SNIOwn)
	cfg.ServerName = "other.test"
	if _, err := Dial(context.Background(), cfg); err == nil {
		t.Fatal("own mode accepted a certificate for the wrong name")
	}
}

func TestSecondLaneResumesTLS(t *testing.T) {
	n := newTestNode(t, nil)
	cache := lruCache()
	for i, mode := range []SNIMode{SNIOwn, SNIBorrowed, SNINone} {
		cfg := n.dialConfig(t, mode)
		cfg.SessionCache = cache
		first := dial(t, cfg)
		waitWelcome(t, first) // tickets arrive before WELCOME
		if ResumedTLS(first) {
			t.Fatalf("%v: first lane resumed", mode)
		}
		second := dial(t, cfg)
		waitWelcome(t, second)
		if !ResumedTLS(second) {
			t.Fatalf("%v: second lane did not resume TLS", mode)
		}
		for range 2 {
			n.acceptLane(t)
		}
		_ = i
	}
}

func TestLoginFailure(t *testing.T) {
	n := newTestNode(t, func(n *testNode) { n.refuse = true })
	cl := dial(t, n.dialConfig(t, SNIOwn))
	err := waitDone(t, cl)
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("err = %v, want ErrLoginFailed", err)
	}

	// A HELLO signed with the wrong key also gets the website.
	n2 := newTestNode(t, nil)
	cfg := n2.dialConfig(t, SNIOwn)
	cfg.DeviceKey[0] ^= 1
	cl = dial(t, cfg)
	if err := waitDone(t, cl); !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("bad key: err = %v", err)
	}
}

func TestRetireDrainsAndClosesCleanly(t *testing.T) {
	sink := newSink()
	retired := make(chan struct{}, 1)
	n := newTestNode(t, func(n *testNode) {
		n.handler.Data = sink.handler
		n.handler.Retire = func(*Lane) { retired <- struct{}{} }
	})
	cl := dial(t, n.dialConfig(t, SNIOwn))
	sl := n.acceptLane(t)
	waitWelcome(t, cl)
	accepted := 0
	for i := range 200 {
		if cl.Send(bytes.Repeat([]byte{byte(i)}, 1000)) {
			accepted++
		}
	}
	if accepted < 64 {
		t.Fatalf("only %d sends accepted", accepted)
	}
	cl.Retire()
	if cl.Send([]byte("late")) {
		t.Fatal("Send accepted after Retire")
	}
	select {
	case <-retired:
	case <-time.After(5 * time.Second):
		t.Fatal("server never saw RETIRE")
	}
	if !sl.Retiring() {
		t.Fatal("server lane not retiring")
	}
	if err := waitDone(t, cl); err != nil {
		t.Fatalf("client lane err = %v, want clean retire", err)
	}
	if err := waitDone(t, sl); err != nil {
		t.Fatalf("server lane err = %v", err)
	}
	// Everything queued before RETIRE is delivered before the lane closes.
	if got := len(sink.wait(t, accepted)); got != accepted {
		t.Fatalf("delivered %d of %d queued packets", got, accepted)
	}
}

func TestServerRetire(t *testing.T) {
	n := newTestNode(t, nil)
	retired := make(chan struct{}, 1)
	cfg := n.dialConfig(t, SNIOwn)
	cfg.Lane.Handler.Retire = func(*Lane) { retired <- struct{}{} }
	cl := dial(t, cfg)
	sl := n.acceptLane(t)
	waitWelcome(t, cl)
	sl.Retire()
	select {
	case <-retired:
	case <-time.After(5 * time.Second):
		t.Fatal("client never saw RETIRE")
	}
	if err := waitDone(t, cl); err != nil {
		t.Fatalf("client err = %v", err)
	}
}

func TestSendClose(t *testing.T) {
	reason := make(chan wire.CloseReason, 1)
	n := newTestNode(t, func(n *testNode) {
		n.handler.Close = func(_ *Lane, r wire.CloseReason) { reason <- r }
	})
	cl := dial(t, n.dialConfig(t, SNIOwn))
	sl := n.acceptLane(t)
	waitWelcome(t, cl)
	cl.SendClose(wire.CloseShutdown)
	select {
	case r := <-reason:
		if r != wire.CloseShutdown {
			t.Fatalf("reason = %v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never saw CLOSE")
	}
	if err := waitDone(t, sl); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("server lane err = %v", err)
	}
	if err := waitDone(t, cl); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("client lane err = %v", err)
	}
}

func TestCDNCarrier(t *testing.T) {
	sink := newSink()
	n := newTestNode(t, func(n *testNode) {
		n.ws = true
		n.handler.Data = sink.handler
	})
	cfg := n.dialConfig(t, 0)
	cfg.Carrier = CDN
	cfg.ServerName = coverDomain
	cfg.Path = "/ws"
	cfg.FirstPacket = wgInitiation()
	clientSink := newSink()
	cfg.Lane.Handler.Data = clientSink.handler
	cl := dial(t, cfg)
	sl := n.acceptLane(t)
	waitWelcome(t, cl)
	big := bytes.Repeat([]byte{7}, 1400)
	for range 20 {
		cl.Send(big)
		sl.Send(big)
	}
	if got := sink.wait(t, 21); !bytes.Equal(got[0], wgInitiation()) || !bytes.Equal(got[20], big) {
		t.Fatal("CDN lane corrupted packets")
	}
	clientSink.wait(t, 20)
	cl.Retire()
	if err := waitDone(t, cl); err != nil {
		t.Fatalf("retire over websocket: %v", err)
	}
}

func TestEndIsCalledWhenTheReaderStops(t *testing.T) {
	a, b := tcpPair(t)
	var mu sync.Mutex
	ended := 0
	la := New(a, nil, Options{Role: Server, Handler: Handler{
		End: func(*Lane) { mu.Lock(); ended++; mu.Unlock() },
	}})
	defer la.Close()
	if err := la.Start(nil); err != nil {
		t.Fatal(err)
	}
	b.Close()
	if err := waitDone(t, la); err == nil {
		t.Fatal("lane ended cleanly after its peer vanished")
	}
	mu.Lock()
	defer mu.Unlock()
	if ended != 1 {
		t.Fatalf("End called %d times, want once", ended)
	}
}

func TestPingEstimatesWithoutTCPInfo(t *testing.T) {
	a, b := tcpPair(t)
	// Delay one direction to give the RTT something to measure. Raw is
	// left unset, so the lanes can't use TCP_INFO and fall back to PINGs.
	ca := New(&slowConn{Conn: a, delay: 15 * time.Millisecond}, nil, Options{Role: Server, PingInterval: 20 * time.Millisecond})
	cb := New(b, nil, Options{Role: Server, PingInterval: 20 * time.Millisecond})
	defer ca.Close()
	defer cb.Close()
	if err := ca.Start(nil); err != nil {
		t.Fatal(err)
	}
	if err := cb.Start(nil); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ca.Send(make([]byte, 1000))
		time.Sleep(5 * time.Millisecond)
		if ca.rttSampled.Load() && ca.rateSeen.Load() {
			break
		}
	}
	st := ca.Stats()
	if st.TCPInfo {
		t.Fatal("pipe reported TCP_INFO")
	}
	if !ca.rttSampled.Load() || st.SRTT < 15*time.Millisecond || st.SRTT > time.Second {
		t.Fatalf("SRTT = %v (sampled %v)", st.SRTT, ca.rttSampled.Load())
	}
	if !ca.rateSeen.Load() || st.Rate <= 0 {
		t.Fatalf("rate never sampled: %+v", st)
	}
}

func TestTCPInfoOnRealSockets(t *testing.T) {
	n := newTestNode(t, nil)
	cl := dial(t, n.dialConfig(t, SNIOwn))
	n.acceptLane(t)
	waitWelcome(t, cl)
	st := cl.Stats()
	if !st.TCPInfo {
		t.Skip("no TCP_INFO on this platform")
	}
	for range 50 {
		cl.Send(make([]byte, 1200))
	}
	time.Sleep(300 * time.Millisecond)
	if st := cl.Stats(); st.SRTT <= 0 || st.SRTT > time.Second {
		t.Fatalf("SRTT from TCP_INFO = %v", st.SRTT)
	}
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-ch
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// slowConn delays every write, adding latency in one direction.
type slowConn struct {
	net.Conn
	delay time.Duration
}

func (c *slowConn) Write(p []byte) (int, error) {
	time.Sleep(c.delay)
	return c.Conn.Write(p)
}

// pipeLanes returns a lane writing through a recordConn and a reader that
// drains the far end.
func pipeLane(t *testing.T, prof *shape.Profile) (*Lane, *recordConn) {
	t.Helper()
	a, b := net.Pipe()
	rc := &recordConn{Conn: a}
	l := New(rc, nil, Options{Role: Server, Planner: shape.NewPlanner(prof)})
	go io.Copy(io.Discard, b)
	t.Cleanup(func() { l.Close(); b.Close() })
	return l, rc
}

func TestRecordShaping(t *testing.T) {
	prof := shape.Default()
	prof.ServerFirstFlight = shape.IntRange{Min: 2000, Max: 2000}
	l, rc := pipeLane(t, prof)
	welcome := wire.Welcome{}
	if err := l.Start(wire.AppendFrame(nil, wire.TypeWelcome, welcome.AppendBody(nil))); err != nil {
		t.Fatal(err)
	}
	// Lane start: the first flight is padded to the profile's size.
	if got := rc.sizes(); len(got) != 1 || got[0] != 2000 {
		t.Fatalf("first flight sizes %v, want [2000]", got)
	}

	// Interactive: a handshake-sized record rounds up to a bucket.
	l.Send(wgInitiation())
	waitWrites(t, rc, 2)
	if got := rc.sizes()[1]; got != 192 {
		t.Fatalf("interactive record = %d, want 192", got)
	}

	// Bulk: a large backlog goes out in full, unpadded records.
	l.mu.Lock() // hold the writer while the backlog builds
	for range 40 {
		l.data = append(l.data, make([]byte, 1420))
		l.dataAt = append(l.dataAt, time.Now().UnixNano())
		l.queued += 1423
	}
	l.mu.Unlock()
	l.signal(l.wake)
	waitBytes(t, rc, 2000+192+40*1423)
	sizes := rc.sizes()[2:]
	for i, s := range sizes[:len(sizes)-1] {
		if s > shape.MaxRecord || s < shape.MaxRecord-1423 {
			t.Fatalf("bulk record %d = %d bytes", i, s)
		}
	}
}

func TestRecordWaitsAMomentToFill(t *testing.T) {
	prof := shape.Default()
	prof.ServerFirstFlight = shape.IntRange{Min: 2000, Max: 2000}
	l, rc := pipeLane(t, prof)
	if err := l.Start(nil); err != nil {
		t.Fatal(err)
	}
	// Two packets a fraction of a millisecond apart, as the packets of one
	// train inside the tunnel are: they leave in one record, not two.
	l.Send(wgInitiation())
	time.Sleep(200 * time.Microsecond)
	l.Send(wgInitiation())
	waitWrites(t, rc, 2)
	time.Sleep(20 * time.Millisecond)
	// Two 151-byte frames, with or without a PING, round up to 384.
	if got := rc.sizes()[1:]; len(got) != 1 || got[0] != 384 {
		t.Fatalf("records %v, want one of 384 bytes", got)
	}
	// A packet on its own still goes within the flush delay.
	start := time.Now()
	l.Send(wgInitiation())
	waitWrites(t, rc, 3)
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("a lone packet waited %v", d)
	}
}

func TestInteractiveRecordsAreDividedToFitBuckets(t *testing.T) {
	prof := shape.Default()
	prof.ServerFirstFlight = shape.IntRange{Min: 2000, Max: 2000}
	l, rc := pipeLane(t, prof)
	if err := l.Start(nil); err != nil {
		t.Fatal(err)
	}
	// Three full-size packets in one record would be padded from 4.4 KB to
	// the 6144 bucket. Two and then one pad to 3072 and 1536, and both
	// records go out without waiting on each other.
	l.mu.Lock() // hold the writer while the packets queue
	for range 3 {
		l.data = append(l.data, make([]byte, 1452))
		l.dataAt = append(l.dataAt, time.Now().UnixNano())
		l.queued += 1455
	}
	l.mu.Unlock()
	l.signal(l.wake)
	waitWrites(t, rc, 3)
	time.Sleep(20 * time.Millisecond)
	if got := rc.sizes()[1:]; len(got) != 2 || got[0] != 3072 || got[1] != 1536 {
		t.Fatalf("records %v, want [3072 1536]", got)
	}
}

func TestIdleKeepalivesAreDelayedAndPadded(t *testing.T) {
	prof := shape.Default()
	prof.IdleAfter = shape.Duration(time.Millisecond)
	prof.KeepaliveDelay = shape.DurationRange{Min: shape.Duration(150 * time.Millisecond), Max: shape.Duration(150 * time.Millisecond)}
	l, rc := pipeLane(t, prof)
	if err := l.Start(nil); err != nil {
		t.Fatal(err)
	}
	waitWrites(t, rc, 1)
	time.Sleep(10 * time.Millisecond) // become idle
	start := time.Now()
	l.Send(wgKeepalive())
	waitWrites(t, rc, 2)
	rc.mu.Lock()
	sent := rc.times[1]
	size := rc.writes[1]
	rc.mu.Unlock()
	if d := sent.Sub(start); d < 140*time.Millisecond {
		t.Fatalf("keepalive went out after %v, want the 150ms idle delay", d)
	}
	ok := false
	for _, s := range prof.IdleSizes {
		ok = ok || s == size
	}
	if !ok {
		t.Fatalf("idle keepalive record = %d bytes, not an idle size", size)
	}

	// Real traffic is never delayed.
	start = time.Now()
	l.Send(wgInitiation())
	waitWrites(t, rc, 3)
	rc.mu.Lock()
	d := rc.times[2].Sub(start)
	rc.mu.Unlock()
	if d > 50*time.Millisecond {
		t.Fatalf("data delayed %v", d)
	}
}

func TestSendRefusesWhenQueueIsFull(t *testing.T) {
	// The lane is never started, so nothing drains its queue.
	a2, b2 := net.Pipe()
	defer b2.Close()
	l2 := New(a2, nil, Options{Role: Server})
	defer l2.Close()
	refused := false
	for range 10000 {
		if !l2.Send(make([]byte, 1400)) {
			refused = true
			break
		}
	}
	if !refused {
		t.Fatal("queue grew without limit")
	}
	if eta := l2.ETA(0); eta <= 0 {
		t.Fatalf("ETA = %v", eta)
	}
}

func TestPingTimeoutEndsLane(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	go io.Copy(io.Discard, b) // reads but never answers PINGs
	l := New(a, nil, Options{Role: Server, PingInterval: 10 * time.Millisecond, PingTimeout: 200 * time.Millisecond})
	if err := l.Start(nil); err != nil {
		t.Fatal(err)
	}
	l.Send([]byte("x"))
	if err := waitDone(t, l); !errors.Is(err, ErrPingTimeout) {
		t.Fatalf("err = %v, want ErrPingTimeout", err)
	}
}

func waitWrites(t *testing.T, rc *recordConn, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for len(rc.sizes()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("saw %d writes, want %d", len(rc.sizes()), n)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitBytes(t *testing.T, rc *recordConn, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		total := 0
		for _, s := range rc.sizes() {
			total += s
		}
		if total >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("wrote %d bytes, want %d", total, n)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPins(t *testing.T) {
	p := getPKI(t)
	back, err := ParsePin("sha256/" + p.defaultPin.String())
	if err != nil || back != p.defaultPin {
		t.Fatalf("ParsePin: %v %v", back, err)
	}
	if _, err := ParsePin("bm90IGEgcGlu"); err == nil {
		t.Fatal("short pin accepted")
	}
	if err := verifyPinned(p.defaultCert.Certificate, []Pin{p.defaultPin}, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := verifyPinned(p.cover.Certificate, []Pin{p.defaultPin}, p.roots, ""); err == nil {
		t.Fatal("cover cert matched the default pin")
	}
}

func TestSNIModeStrings(t *testing.T) {
	for _, m := range []SNIMode{SNIOwn, SNIBorrowed, SNINone} {
		back, err := ParseSNIMode(m.String())
		if err != nil || back != m {
			t.Fatalf("%v: %v %v", m, back, err)
		}
	}
	if _, err := ParseSNIMode("bogus"); err == nil {
		t.Fatal("bogus mode parsed")
	}
	if Direct.String() != "direct" || CDN.String() != "cdn" {
		t.Fatal("carrier strings")
	}
}

// Without TCP_NOTSENT_LOWAT a lane must not stuff the kernel: until PONGs
// confirm delivery it writes at most one small first window, and it keeps a
// PING outstanding so a PONG can reopen it.
func TestFallbackWindowBoundsUnconfirmedBytes(t *testing.T) {
	a, b := tcpPair(t)
	go io.Copy(io.Discard, b) // reads everything, answers nothing
	l := New(a, nil, Options{Role: Server})
	defer l.Close()
	if err := l.Start(nil); err != nil {
		t.Fatal(err)
	}
	first := l.Stats().BytesSent
	// The first burst fills the window; the second finds it closed.
	for range 2 {
		for range 2000 {
			l.Send(make([]byte, 1400))
		}
		time.Sleep(100 * time.Millisecond)
	}
	st := l.Stats()
	if st.NotSentLowat {
		t.Skip("raw socket unexpectedly has TCP_NOTSENT_LOWAT")
	}
	written := st.BytesSent - first
	if written < windowMin-shape.MaxRecord || written > windowMin+2*shape.MaxRecord {
		t.Fatalf("wrote %d bytes with nothing confirmed; window is %d", written, windowMin)
	}
	if st.PingsOut == 0 {
		t.Fatal("gated with no PING outstanding: nothing could ever reopen the window")
	}
	if st.Queued == 0 {
		t.Fatal("the backlog should wait in the lane's queue, not the kernel")
	}
}
