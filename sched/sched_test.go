package sched

import (
	"math/rand/v2"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/wire"
)

// stubLane is a scheduler lane with a fixed ETA.
type stubLane struct {
	mu      sync.Mutex
	eta     time.Duration
	rtt     time.Duration
	full    bool
	retrans bool
	got     [][]byte
	lost    []wire.Lost // notices the lane was given
}

func (l *stubLane) Send(pkt []byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.full {
		return false
	}
	l.got = append(l.got, append([]byte(nil), pkt...))
	return true
}
func (l *stubLane) ETA(int) time.Duration { return l.eta }
func (l *stubLane) Retransmitting() bool  { return l.retrans }
func (l *stubLane) RTT() time.Duration    { return l.rtt }

func (l *stubLane) Lost(lost wire.Lost) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.full {
		return false
	}
	l.lost = append(l.lost, lost)
	return true
}
func (l *stubLane) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.got)
}

func TestSchedulerPicksEarliestETA(t *testing.T) {
	a := &stubLane{eta: 10 * time.Millisecond}
	b := &stubLane{eta: 5 * time.Millisecond}
	c := &stubLane{eta: 20 * time.Millisecond}
	var s Scheduler
	if s.Send([]byte("x")) {
		t.Fatal("sent with no lanes")
	}
	s.SetLanes([]Lane{a, b, c})
	for range 10 {
		if !s.Send(make([]byte, 500)) {
			t.Fatal("Send failed")
		}
	}
	if a.count() != 0 || b.count() != 10 || c.count() != 0 {
		t.Fatalf("counts a=%d b=%d c=%d", a.count(), b.count(), c.count())
	}

	// The best lane is full: the next-best takes the packet.
	b.full = true
	s.Send(make([]byte, 500))
	if a.count() != 1 {
		t.Fatal("did not fall back to the next-best lane")
	}
	// Everything full: the packet is dropped, like on a congested link.
	a.full, c.full = true, true
	if s.Send(make([]byte, 500)) {
		t.Fatal("Send succeeded with every lane full")
	}
	if st := s.Stats(); st.Dropped != 1 || st.Sent != 11 {
		t.Fatalf("stats %+v", st)
	}
}

func TestSchedulerPrefersEarlierLanesUntilTheyFallBehind(t *testing.T) {
	if SpillAfter(0) != SpillMin || SpillAfter(time.Second) != SpillMax || SpillAfter(80*time.Millisecond) != 5*time.Millisecond {
		t.Fatal("SpillAfter is not a sixteenth of srtt within its bounds")
	}
	// srtt 80 ms: a preferred lane keeps the traffic until its estimate is
	// more than 5 ms behind the best.
	a := &stubLane{eta: 20 * time.Millisecond, rtt: 80 * time.Millisecond}
	b := &stubLane{eta: 20 * time.Millisecond, rtt: 80 * time.Millisecond}
	var s Scheduler
	s.SetLanes([]Lane{a, b}) // a is preferred
	send := func() { t.Helper(); s.Send(make([]byte, 500)) }
	send()
	if a.count() != 1 {
		t.Fatal("the preferred lane did not take the first packet")
	}
	b.eta = 15 * time.Millisecond // a is 5 ms behind: not enough to spill
	send()
	if a.count() != 2 || b.count() != 0 {
		t.Fatalf("spilled for a 5 ms gain: a=%d b=%d", a.count(), b.count())
	}
	a.eta = 26 * time.Millisecond // now 11 ms behind
	send()
	if b.count() != 1 {
		t.Fatal("did not spill past a lane that fell behind")
	}
	// The traffic returns to the preferred lane as soon as it is back
	// within the margin, not only once it is the earliest.
	a.eta = 19 * time.Millisecond
	send()
	if a.count() != 3 || b.count() != 1 {
		t.Fatalf("did not return to the preferred lane: a=%d b=%d", a.count(), b.count())
	}
	// A full preferred lane hands over to the earliest other lane.
	a.full = true
	send()
	if b.count() != 2 {
		t.Fatalf("b=%d, want the packet a had no room for", b.count())
	}
	a.full = false
	// With three lanes, the most preferred of those within the margin wins:
	// a is 20 ms behind c, b only 4 ms.
	c := &stubLane{eta: 10 * time.Millisecond, rtt: 80 * time.Millisecond}
	a.eta, b.eta = 30*time.Millisecond, 14*time.Millisecond
	s.SetLanes([]Lane{a, b, c})
	send()
	if a.count() != 3 || b.count() != 3 || c.count() != 0 {
		t.Fatalf("a=%d b=%d c=%d, want the packet on b", a.count(), b.count(), c.count())
	}
	// A lane that leaves the scheduler is forgotten.
	s.SetLanes([]Lane{a, c})
	send()
	if c.count() != 1 {
		t.Fatal("the best remaining lane did not take over")
	}
}

func TestDuplicationOnlyWhileRetransmitting(t *testing.T) {
	a := &stubLane{eta: time.Millisecond}
	b := &stubLane{eta: 2 * time.Millisecond}
	var s Scheduler
	s.SetLanes([]Lane{a, b})
	// Build up some budget with bulk traffic.
	for range 1000 {
		s.Send(make([]byte, 1400))
	}
	s.Send(make([]byte, 64))
	if b.count() != 0 {
		t.Fatal("duplicated with no lane retransmitting")
	}

	a.retrans = true
	s.Send(make([]byte, 64))
	if b.count() != 1 {
		t.Fatal("small packet not duplicated onto the next-best lane")
	}
	s.Send(make([]byte, 129))
	if b.count() != 1 {
		t.Fatal("a packet over 128 bytes was duplicated")
	}
}

func TestDuplicationCappedAtFivePercent(t *testing.T) {
	a := &stubLane{eta: time.Millisecond, retrans: true}
	b := &stubLane{eta: 2 * time.Millisecond}
	var s Scheduler
	s.SetLanes([]Lane{a, b})
	const n = 20000
	for range n {
		s.Send(make([]byte, 100))
	}
	sent := s.Stats().Sent
	dup := s.Stats().Duplicated
	if sent != n {
		t.Fatalf("sent %d", sent)
	}
	share := float64(dup) / float64(sent)
	if share > DupShare*1.01 || share < DupShare*0.9 {
		t.Fatalf("duplicated %.2f%% of bytes, want about 5%%", share*100)
	}
}

func TestChurnDistributions(t *testing.T) {
	c := DefaultChurn()
	rng := rand.New(rand.NewPCG(1, 2))
	const n = 20001
	lifes := make([]time.Duration, n)
	budgets := make([]uint64, n)
	for i := range n {
		lifes[i] = c.Lifetime(rng)
		budgets[i] = c.Budget(rng)
		if lifes[i] < 20*time.Second || lifes[i] > 6*time.Minute {
			t.Fatalf("lifetime %v out of range", lifes[i])
		}
		if budgets[i] < c.BytesMin || budgets[i] > c.BytesMax {
			t.Fatalf("budget %d out of range", budgets[i])
		}
	}
	slices.Sort(lifes)
	slices.Sort(budgets)
	if m := lifes[n/2]; m < 80*time.Second || m > 100*time.Second {
		t.Fatalf("median lifetime %v, want about 90s", m)
	}
	if m := budgets[n/2]; m < 36<<20 || m > 44<<20 {
		t.Fatalf("median budget %d MB, want about 40", m>>20)
	}
	// The spread is real: plenty of short and long lanes.
	if lifes[n/10] > 50*time.Second || lifes[n*9/10] < 150*time.Second {
		t.Fatalf("lifetimes too narrow: p10=%v p90=%v", lifes[n/10], lifes[n*9/10])
	}
}

func rates(r float64, n int) []laneRate {
	out := make([]laneRate, n)
	for i := range out {
		out[i] = laneRate{rate: r, settled: true}
	}
	return out
}

func TestThrottleAddsLanesWhileTheyPayOff(t *testing.T) {
	th := newThrottle()
	const capRate = 500 << 10 // each connection capped at 4 Mbit/s
	now := time.Unix(1000, 0)
	lanes := 2
	extra := 0
	for step := range 120 {
		now = now.Add(time.Second)
		ready := true
		if lanes < 2+extra {
			lanes++ // the probe lane came up
			th.laneAdded(now)
			ready = true
		}
		extra = th.update(now, rates(capRate, lanes), 2, 6, ready)
		if lanes > 2+extra {
			lanes = 2 + extra
		}
		_ = step
	}
	if extra != 4 || !th.throttled {
		t.Fatalf("capped network: extra = %d (throttled %v), want 4", extra, th.throttled)
	}
}

func TestThrottleBacksOffWhenLanesDontHelp(t *testing.T) {
	th := newThrottle()
	const total = 10 << 20 // one shared bottleneck, not per connection
	now := time.Unix(1000, 0)
	lanes, extra, maxSeen := 2, 0, 0
	for range 60 {
		now = now.Add(time.Second)
		if lanes < 2+extra {
			lanes++
			th.laneAdded(now)
		}
		extra = th.update(now, rates(float64(total)/float64(lanes), lanes), 2, 6, true)
		maxSeen = max(maxSeen, extra)
		if lanes > 2+extra {
			lanes = 2 + extra
		}
	}
	if extra != 0 || th.throttled {
		t.Fatalf("shared bottleneck: extra = %d", extra)
	}
	if maxSeen != 1 {
		t.Fatalf("probed up to %d extra lanes within the backoff", maxSeen)
	}
	if th.backoff < th.backoffMin {
		t.Fatalf("backoff = %v", th.backoff)
	}
}

func TestThrottleResetsWhenLoadStops(t *testing.T) {
	th := newThrottle()
	th.extra, th.throttled = 3, true
	now := time.Unix(1000, 0)
	for range 12 {
		now = now.Add(time.Second)
		th.update(now, rates(1000, 5), 2, 6, true)
	}
	if th.extra != 0 || th.throttled {
		t.Fatalf("extra = %d after load stopped", th.extra)
	}
}

func TestThrottleIgnoresUnevenLanes(t *testing.T) {
	th := newThrottle()
	now := time.Unix(1000, 0)
	for range 10 {
		now = now.Add(time.Second)
		th.update(now, []laneRate{{rate: 5 << 20, settled: true}, {rate: 1 << 20, settled: true}}, 2, 6, true)
	}
	if th.extra != 0 || th.probing {
		t.Fatal("probed although lanes ran at different rates")
	}
}

// wgPacket is a WireGuard data packet of size bytes with the given key
// index and counter.
func wgPacket(idx uint32, ctr uint64, size int) []byte {
	return wgData(idx, ctr, size)
}

func TestSchedulerReportsWhatItDrops(t *testing.T) {
	// Every lane is full for counters 3 to 5, so they are dropped. The
	// receiver would wait for them; the lane that takes counter 6 tells it
	// not to.
	a := &stubLane{eta: 10 * time.Millisecond}
	b := &stubLane{eta: 10 * time.Millisecond}
	var s Scheduler
	s.SetLanes([]Lane{a, b})
	for c := uint64(0); c < 3; c++ {
		if !s.Send(wgPacket(9, c, 1200)) {
			t.Fatalf("counter %d not sent", c)
		}
	}
	a.full, b.full = true, true
	for c := uint64(3); c < 6; c++ {
		if s.Send(wgPacket(9, c, 1200)) {
			t.Fatalf("counter %d sent on a full lane", c)
		}
	}
	if len(a.lost)+len(b.lost) != 0 {
		t.Fatal("a notice went out on a lane that takes nothing")
	}
	a.full = false
	if !s.Send(wgPacket(9, 6, 1200)) {
		t.Fatal("counter 6 not sent")
	}
	want := []wire.Lost{{Index: 9, Counter: 3, Count: 3}}
	if !slices.Equal(a.lost, want) || len(b.lost) != 0 {
		t.Fatalf("notices %+v on a, %+v on b; want %+v on a", a.lost, b.lost, want)
	}
	if st := s.Stats(); st.Dropped != 3 || st.Reported != 3 {
		t.Fatalf("stats %+v", st)
	}
	// Nothing is reported twice.
	s.Send(wgPacket(9, 7, 1200))
	if len(a.lost) != 1 {
		t.Fatalf("notices %+v after the next packet", a.lost)
	}
}

func TestSchedulerReportsCountersItNeverSaw(t *testing.T) {
	// WireGuard's counters rise by one. If 2 and 3 never reach the
	// scheduler (a socket buffer overflowed, say), no lane will carry them.
	a := &stubLane{eta: 10 * time.Millisecond}
	var s Scheduler
	s.SetLanes([]Lane{a})
	for _, c := range []uint64{0, 1, 4, 5} {
		s.Send(wgPacket(9, c, 1200))
	}
	if want := []wire.Lost{{Index: 9, Counter: 2, Count: 2}}; !slices.Equal(a.lost, want) {
		t.Fatalf("notices %+v, want %+v", a.lost, want)
	}
	// Small packets count too: they take a counter like any other.
	s.Send(wgPacket(9, 7, 32))
	if want := (wire.Lost{Index: 9, Counter: 6, Count: 1}); len(a.lost) != 2 || a.lost[1] != want {
		t.Fatalf("notices %+v, want %+v last", a.lost, want)
	}
	// Each key has its own counters, and one seen for the first time
	// starts wherever it is.
	s.Send(wgPacket(10, 500, 1200))
	s.Send(wgPacket(10, 501, 1200))
	// A packet out of turn, or far ahead, reports nothing.
	s.Send(wgPacket(9, 3, 1200))
	s.Send(wgPacket(9, 1<<30, 1200))
	if len(a.lost) != 2 {
		t.Fatalf("notices %+v", a.lost)
	}
	// Packets that are not WireGuard data are not followed.
	s.Send(make([]byte, 148))
	if len(a.lost) != 2 {
		t.Fatalf("notices %+v", a.lost)
	}
}

func TestSchedulerKeepsANoticeTheLaneWouldNotTake(t *testing.T) {
	a := &stubLane{eta: 10 * time.Millisecond}
	var s Scheduler
	s.SetLanes([]Lane{a})
	s.Send(wgPacket(9, 0, 1200))
	s.Send(wgPacket(9, 2, 1200)) // 1 is missing
	if len(a.lost) != 1 {
		t.Fatalf("notices %+v", a.lost)
	}
	// More runs than are kept: the oldest go unreported, the newest stay.
	a.full = true
	for i := range uint64(maxLostPending + 4) {
		s.Send(wgPacket(9, 10+2*i, 1200)) // each dropped, and each skips one
	}
	a.full = false
	s.Send(wgPacket(9, 1000, 1200))
	if n := len(a.lost) - 1; n < 1 || n > maxLostPending {
		t.Fatalf("%d notices after a long run of drops, want at most %d", n, maxLostPending)
	}
	last := a.lost[len(a.lost)-1]
	if last.Index != 9 || last.Counter+uint64(last.Count) != 1000 {
		t.Fatalf("last notice %+v does not reach the packet sent", last)
	}
}
