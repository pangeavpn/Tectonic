package lane

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/shape"
)

// fakeLimiter holds DATA back while hold is set and notes what it is told.
type fakeLimiter struct {
	mu      sync.Mutex
	hold    bool
	wrote   int
	reports []Progress
}

func (f *fakeLimiter) Wait(time.Time) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hold {
		return 50 * time.Millisecond
	}
	return 0
}

func (f *fakeLimiter) Wrote(_ time.Time, n int) {
	f.mu.Lock()
	f.wrote += n
	f.mu.Unlock()
}

func (f *fakeLimiter) Report(_ time.Time, p Progress) {
	f.mu.Lock()
	f.reports = append(f.reports, p)
	f.mu.Unlock()
}

func (f *fakeLimiter) set(hold bool) {
	f.mu.Lock()
	f.hold = hold
	f.mu.Unlock()
}

func (f *fakeLimiter) written() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wrote
}

func TestSendLimitHoldsDataAndNothingElse(t *testing.T) {
	prof := shape.Default()
	prof.ServerFirstFlight = []shape.IntRange{{Min: 2000, Max: 2000}}
	l, rc := pipeLane(t, prof)
	lim := &fakeLimiter{hold: true}
	l.limit = lim
	if err := l.Start(nil); err != nil {
		t.Fatal(err)
	}
	waitWrites(t, rc, 1)

	// The session is over its limit: full-size packets wait in the lane.
	for range 4 {
		l.Send(make([]byte, 1400))
	}
	time.Sleep(30 * time.Millisecond)
	if got := rc.sizes()[1:]; len(got) != 0 {
		t.Fatalf("records %v written while the limit held DATA back", got)
	}
	// A small packet does not wait: a ping, an ACK inside the tunnel.
	start := time.Now()
	l.Send(make([]byte, 100))
	waitWrites(t, rc, 2)
	if d := time.Since(start); d > 20*time.Millisecond {
		t.Fatalf("a small packet waited %v behind the limit", d)
	}
	if got := rc.sizes()[1]; got > 256 {
		t.Fatalf("the record that carried the small packet is %d bytes: it took DATA with it", got)
	}
	// Nor does a control frame.
	l.Retire()
	waitWrites(t, rc, 3)
	if lim.written() != 0 {
		t.Fatalf("%d bytes counted against the limit for records that carried none of what it holds", lim.written())
	}
	// When the limit lets go, the packets follow, and are counted.
	lim.set(false)
	waitBytes(t, rc, 2000+4*1403)
	deadline := time.Now().Add(time.Second)
	for lim.written() < 4*1403 {
		if time.Now().After(deadline) {
			t.Fatalf("%d bytes counted against the limit, want at least %d", lim.written(), 4*1403)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLaneReportsWhatItsConnectionDid(t *testing.T) {
	l, _ := pipeLane(t, nil)
	lim := &fakeLimiter{}
	l.limit = lim
	now := time.Now()
	base := tcpInfo{rtt: 50 * time.Millisecond, minRTT: 50 * time.Millisecond, cwnd: 100 * 1448, mss: 1448}
	at := func(sent, resent uint64, segs, delivered uint32, rtt time.Duration) tcpInfo {
		ti := base
		ti.bytesSent, ti.bytesResent, ti.segsSent, ti.delivered, ti.rtt = sent, resent, segs, delivered, rtt
		return ti
	}
	// The first reading only says where the connection stands.
	l.noteTCPInfo(at(100_000, 0, 100, 90, 50*time.Millisecond), now)
	if len(lim.reports) != 0 {
		t.Fatalf("reports %+v from the first reading", lim.reports)
	}
	// 50 KB more sent in 50 segments, 5 KB of it again; 40 segments
	// delivered, taken at the 1000 bytes the connection's segments
	// average. The round trip has risen by half: a queue on the path.
	l.noteTCPInfo(at(150_000, 5_000, 150, 130, 75*time.Millisecond), now)
	want := Progress{Sent: 50_000, Resent: 5_000, Delivered: 40_000, RTT: 75 * time.Millisecond, Queued: true}
	if len(lim.reports) != 1 || lim.reports[0] != want {
		t.Fatalf("reports %+v, want %+v", lim.reports, want)
	}
	// Nothing more sent, but acknowledgements still arriving.
	l.noteTCPInfo(at(150_000, 5_000, 150, 150, 52*time.Millisecond), now)
	want = Progress{Delivered: 20_000, RTT: 52 * time.Millisecond}
	if len(lim.reports) != 2 || lim.reports[1] != want {
		t.Fatalf("second report %+v, want %+v", lim.reports[len(lim.reports)-1], want)
	}
	// A reading taken earlier that arrives late adds nothing, and a later
	// one is still counted from the right place.
	l.noteTCPInfo(at(120_000, 0, 120, 100, 50*time.Millisecond), now)
	l.noteTCPInfo(at(160_000, 5_000, 160, 160, 50*time.Millisecond), now)
	want = Progress{Sent: 10_000, Delivered: 10_000, RTT: 50 * time.Millisecond}
	if len(lim.reports) != 3 || lim.reports[2] != want {
		t.Fatalf("reports %+v, want a third of %+v", lim.reports, want)
	}
	// Nothing new at all: nothing to report.
	l.noteTCPInfo(at(160_000, 5_000, 160, 160, 50*time.Millisecond), now)
	if len(lim.reports) != 3 {
		t.Fatalf("%d reports, want 3", len(lim.reports))
	}
}

func TestEstimateCountsAQueueTheLimitIsHolding(t *testing.T) {
	// The connection has all the window it could want, so by the kernel's
	// figures nothing waits. But the session's send limit is holding the
	// lane to 100 KB/s, which is what its queue has been leaving at.
	l, _ := laneWithSock(t, &sockState{cwnd: 900 * 1448, rtt: 50 * time.Millisecond})
	half := l.RTT() / 2
	if eta := l.ETA(50_000); eta != half {
		t.Fatalf("ETA with a free window and nothing known about the queue = %v, want %v", eta, half)
	}
	l.drain.Store(math.Float64bits(100e3))
	if eta := l.ETA(50_000); !near(eta, half+500*time.Millisecond, 5*time.Millisecond) {
		t.Fatalf("ETA for 50 KB in a queue leaving at 100 KB/s = %v, want about %v", eta, half+500*time.Millisecond)
	}
}
