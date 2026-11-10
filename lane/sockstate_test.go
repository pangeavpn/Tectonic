package lane

import (
	"net"
	"testing"
	"time"
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
