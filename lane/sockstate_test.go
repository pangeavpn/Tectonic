package lane

import (
	"net"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/shape"
	"github.com/pangeavpn/tectonic/wire"
)

// A connection that has just opened on a 150 ms path: ten segments of
// window, nothing sent yet, and no pacing.
func coldSock() *sockState {
	return &sockState{cwnd: 10 * 1448, rtt: 150 * time.Millisecond, rto: 350 * time.Millisecond}
}

func TestWaitIsNothingWithinTheWindow(t *testing.T) {
	s := coldSock()
	if w := s.wait(10_000, 0); w != 0 {
		t.Fatalf("wait for 10 KB in an empty 14.5 KB window = %v", w)
	}
	// Beyond the window, bytes leave as acknowledgements come back: a
	// window's worth each round trip. 5520 bytes over is 0.38 of a window.
	if w := s.wait(20_000, 0); !near(w, 57*time.Millisecond, time.Millisecond) {
		t.Fatalf("wait for 20 KB = %v, want about 57 ms", w)
	}
	// What is in flight uses the window up.
	s.inflight = 10 * 1448
	if w := s.wait(1448, 0); !near(w, 15*time.Millisecond, time.Millisecond) {
		t.Fatalf("wait for one segment behind a full window = %v, want about 15 ms", w)
	}
}

func TestWaitCountsWhatTheKernelHolds(t *testing.T) {
	// The kernel has taken 30 KB it cannot send: the window is full. The
	// lane's own queue may be empty, but a packet given to it now waits
	// behind all of that.
	s := coldSock()
	s.inflight, s.notsent = s.cwnd, 30_000
	want := time.Duration(31_448 / (s.cwnd / 0.15) * float64(time.Second))
	if w := s.wait(1448, 0); !near(w, want, time.Millisecond) {
		t.Fatalf("wait behind 30 KB unsent = %v, want about %v", w, want)
	}
}

func TestWaitFollowsThePacingRate(t *testing.T) {
	// A connection that spaces its packets out sends at its pacing rate
	// however much window it has: 15 KB at 275 KB/s take 55 ms.
	s := coldSock()
	s.pacing = 275e3
	if w := s.wait(15_000, 0); !near(w, 55*time.Millisecond, time.Millisecond) {
		t.Fatalf("wait for 15 KB at 275 KB/s = %v, want about 55 ms", w)
	}
	// A fast one hardly waits at all.
	s = &sockState{cwnd: 900 * 1448, rtt: 50 * time.Millisecond, pacing: 15e6}
	if w := s.wait(30_000, 0); w > 3*time.Millisecond {
		t.Fatalf("wait for 30 KB at 15 MB/s = %v", w)
	}
	// Without figures there is nothing to go by.
	if w := (&sockState{}).wait(1e6, 0); w != 0 {
		t.Fatalf("wait with no window reported = %v", w)
	}
}

func TestIdleConnectionIsTakenToHaveLostItsWindow(t *testing.T) {
	// The kernel still reports the window the connection had; it halves
	// it for each timeout the connection sat idle, on the next send.
	s := &sockState{cwnd: 800 * 1448, rtt: 50 * time.Millisecond, rto: 250 * time.Millisecond}
	if w := s.wait(100_000, 100*time.Millisecond); w != 0 {
		t.Fatalf("wait on a connection idle for less than a timeout = %v", w)
	}
	// Idle for three timeouts: an eighth of the window, 144.8 KB.
	if w := s.wait(100_000, 800*time.Millisecond); w != 0 {
		t.Fatalf("wait for 100 KB in an eighth of the window = %v", w)
	}
	if w := s.wait(200_000, 800*time.Millisecond); w <= 0 {
		t.Fatal("no wait for more than an idle connection's window holds")
	}
	// However long it idles, it keeps an initial window.
	if w := s.wait(idleWindow, time.Hour); w != 0 {
		t.Fatalf("wait for an initial window after a long idle = %v", w)
	}
	if w := s.wait(2*idleWindow, time.Hour); w <= 0 {
		t.Fatal("no wait beyond an initial window after a long idle")
	}
	// A connection with packets in flight is not idle.
	s.inflight = 1448
	if w := s.wait(200_000, time.Hour); w != 0 {
		t.Fatalf("wait on a busy connection = %v", w)
	}
}

func TestRecordLimitFollowsTheSendingRate(t *testing.T) {
	// A new connection on a 150 ms path, paced at 275 KB/s, sends 1100
	// bytes in the 4 ms a record may take: one packet to a record.
	s := coldSock()
	s.pacing = 275e3
	if got := s.recordLimit(); got != 1100 {
		t.Fatalf("record limit at 275 KB/s = %d, want 1100", got)
	}
	// At 100 Mbit/s on a 50 ms path a full record takes about a millisecond.
	s = &sockState{cwnd: 600 * 1448, rtt: 50 * time.Millisecond, pacing: 12.5e6}
	if got := s.recordLimit(); got != shape.MaxRecord {
		t.Fatalf("record limit at 12.5 MB/s = %d, want a full record", got)
	}
	// A connection that does not pace sends what its window has room for
	// at once, so that much can share a record: here the whole window.
	s = coldSock()
	if got := s.recordLimit(); got != 10*1448 {
		t.Fatalf("record limit for a cold connection that does not pace = %d, want its window", got)
	}
	// With the window full, bytes leave a window each round trip: 14.5 KB
	// in 150 ms, 386 bytes in 4 ms.
	s.inflight = s.cwnd
	if got := s.recordLimit(); got < 300 || got > 500 {
		t.Fatalf("record limit behind a full window = %d", got)
	}
	if got := (&sockState{}).recordLimit(); got != shape.MaxRecord {
		t.Fatalf("record limit with nothing reported = %d", got)
	}
}

// laneWithSock returns a started lane that takes s for its connection's
// state, as a lane with TCP_NOTSENT_LOWAT does, and the records it writes.
func laneWithSock(t *testing.T, s *sockState) (*Lane, *recordConn) {
	t.Helper()
	prof := shape.Default()
	prof.ServerFirstFlight = []shape.IntRange{{Min: 2000, Max: 2000}}
	l, rc := pipeLane(t, prof)
	l.lowat = true
	l.sock.Store(s)
	if err := l.Start(nil); err != nil {
		t.Fatal(err)
	}
	waitWrites(t, rc, 1)
	return l, rc
}

// queue puts n full-size packets on the lane at once.
func queue(l *Lane, n int) {
	l.mu.Lock()
	for range n {
		l.data = append(l.data, make([]byte, 1420))
		l.dataAt = append(l.dataAt, time.Now().UnixNano())
		l.queued += wire.HeaderLen + 1420
	}
	l.mu.Unlock()
	l.signal(l.wake)
}

func TestSlowConnectionSendsSmallRecords(t *testing.T) {
	// Nothing in a record can be used until all of it has arrived. At
	// 275 KB/s a 16 KB record takes 58 ms; one packet takes five.
	slow := coldSock()
	slow.pacing = 275e3
	l, rc := laneWithSock(t, slow)
	queue(l, 8)
	waitBytes(t, rc, 2000+8*1423)
	sizes := rc.sizes()[1:]
	// A record holds no more than a packet: one whole, or the end of one
	// and the start of the next.
	for _, s := range sizes {
		if s > 1536 {
			t.Fatalf("records %v: each should hold a packet or less", sizes)
		}
	}
	// They follow one another at once: a record cut short does not wait
	// to fill.
	rc.mu.Lock()
	span := rc.times[len(rc.times)-1].Sub(rc.times[1])
	rc.mu.Unlock()
	if span > 20*time.Millisecond {
		t.Fatalf("8 records took %v", span)
	}
}

func TestFastConnectionSendsFullRecords(t *testing.T) {
	l, rc := laneWithSock(t, &sockState{cwnd: 600 * 1448, rtt: 50 * time.Millisecond, pacing: 12.5e6})
	queue(l, 40)
	waitBytes(t, rc, 2000+40*1423)
	sizes := rc.sizes()[1:]
	for i, s := range sizes[:len(sizes)-1] {
		if s > shape.MaxRecord || s < shape.MaxRecord-1423 {
			t.Fatalf("record %d of %v is not full", i, sizes)
		}
	}
}

func TestLaneEstimatesFromItsConnection(t *testing.T) {
	n := newTestNode(t, nil)
	cl := dial(t, n.dialConfig(t, SNIOwn))
	n.acceptLane(t)
	waitWelcome(t, cl)
	if st := cl.Stats(); !st.NotSentLowat || !st.TCPInfo {
		t.Skip("no TCP_NOTSENT_LOWAT or TCP_INFO on this platform")
	}
	s := cl.sock.Load()
	if s == nil || s.cwnd <= 0 || s.rtt <= 0 {
		t.Skipf("the platform does not report a window: %+v", s)
	}
	// Idle on loopback: nothing waits, so the estimate is half a round trip.
	if eta := cl.ETA(1200); eta > cl.RTT()/2+time.Millisecond {
		t.Fatalf("ETA of an idle lane = %v with a round trip of %v", eta, cl.RTT())
	}
	// More than the window holds does wait.
	if eta := cl.ETA(int(4 * s.cwnd)); eta <= cl.RTT()/2 {
		t.Fatalf("ETA for four windows = %v, no more than for nothing", eta)
	}
	// Writing refreshes what the lane knows.
	before := s.at
	for range 20 {
		cl.Send(make([]byte, 1200))
	}
	deadline := time.Now().Add(2 * time.Second)
	for !cl.sock.Load().at.After(before) {
		if time.Now().After(deadline) {
			t.Fatal("the lane wrote and did not look at its connection again")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPacingIsTakenFromWhatTheConnectionDoes(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	l := New(a, nil, Options{Role: Server})
	t.Cleanup(func() { l.Close() })
	now := time.Now()
	// The kernel reports a pacing rate for every connection. One that
	// sends all it is given is not held to it.
	ti := tcpInfo{rtt: 50 * time.Millisecond, cwnd: 20 * 1448, mss: 1448, pacing: 1e6}
	if s := l.noteTCPInfo(ti, now); s == nil || s.pacing != 0 {
		t.Fatalf("state %+v: a connection that held nothing back was taken to pace", s)
	}
	// Bytes unsent behind a full window say nothing either way.
	ti.inflight, ti.notsent = ti.cwnd, 8*1448
	if s := l.noteTCPInfo(ti, now); s.pacing != 0 {
		t.Fatal("a full window was taken for pacing")
	}
	// Segments held back with window to spare do, once seen a few times.
	ti.inflight, ti.notsent = 4*1448, 3*1448
	for i := 1; i <= pacedAfter; i++ {
		s := l.noteTCPInfo(ti, now)
		if paced := s.pacing != 0; paced != (i == pacedAfter) {
			t.Fatalf("after %d sightings: pacing %v", i, s.pacing)
		}
	}
	// And from then on, whatever it is doing.
	ti.notsent = 0
	if s := l.noteTCPInfo(ti, now); s.pacing != 1e6 {
		t.Fatalf("pacing %v after the connection was seen to pace", s.pacing)
	}
}
