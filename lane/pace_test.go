package lane

import (
	"math"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// pacedLane returns a lane that paces itself on PONGs (it has no raw socket,
// so no TCP_NOTSENT_LOWAT), not started, with a base RTT of 50 ms and a rate
// of rate bytes per second already measured.
func pacedLane(t *testing.T, rate float64) *Lane {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	l := New(a, nil, Options{Role: Server, InitialRTT: 50 * time.Millisecond})
	t.Cleanup(func() { l.Close() })
	if l.lowat {
		t.Fatal("a pipe has TCP_NOTSENT_LOWAT")
	}
	l.baseRTT.Store(int64(50 * time.Millisecond))
	l.ponged.Store(true)
	if rate > 0 {
		l.rate.Store(math.Float64bits(rate))
		l.rateSeen.Store(true)
	}
	return l
}

// near reports whether got is within tol of want.
func near(got, want, tol time.Duration) bool {
	return got >= want-tol && got <= want+tol
}

func TestNewLaneIsNotCountedOnUntilItsFirstPong(t *testing.T) {
	a, b := tcpPair(t)
	const rtt = 40 * time.Millisecond
	la := New(a, nil, Options{Role: Server, InitialRTT: rtt})
	lb := New(b, nil, Options{Role: Server})
	defer la.Close()
	defer lb.Close()
	// Nothing is known to have arrived yet: the lane is a round trip away
	// from being any use, on top of the half round trip a packet takes.
	if eta := la.ETA(0); eta != rtt+rtt/2 {
		t.Fatalf("ETA before the first PONG = %v, want %v", eta, rtt+rtt/2)
	}
	if err := la.Start(nil); err != nil {
		t.Fatal(err)
	}
	if st := la.Stats(); st.PingsOut != 1 {
		t.Fatalf("%d PINGs outstanding after the first flight, want 1", st.PingsOut)
	}
	if err := lb.Start(nil); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !la.ponged.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the first flight's PING was never answered")
		}
		time.Sleep(time.Millisecond)
	}
	// The PONG measured the real round trip (loopback), and nothing is
	// outstanding any more.
	if eta := la.ETA(0); eta >= rtt/2 {
		t.Fatalf("ETA after the first PONG = %v", eta)
	}
	if st := la.Stats(); st.Unconfirmed != 0 || st.PingsOut != 0 {
		t.Fatalf("after the first PONG: %+v", st)
	}
}

func TestETACountsBytesWaitingBelowTheLane(t *testing.T) {
	const rate = 1e6 // bytes/s: 50 KB per base RTT
	l := pacedLane(t, rate)
	base := 50 * time.Millisecond
	if eta := l.ETA(0); eta != base/2 {
		t.Fatalf("idle ETA = %v, want half the base RTT", eta)
	}
	// While PONGs are on time the lane is taken to carry probeGain times
	// what it delivers in a base RTT: 62.5 KB. Up to there nothing waits.
	l.lastPong.Store(time.Now().UnixNano())
	l.tracked.Store(60_000)
	if eta := l.ETA(0); !near(eta, base/2, 2*time.Millisecond) {
		t.Fatalf("ETA with 60 KB outstanding = %v, want about %v", eta, base/2)
	}
	// Beyond it, the excess waits in the kernel and is delivered at the
	// lane's rate: 100 KB outstanding is 37.5 KB over, so 37.5 ms.
	l.lastPong.Store(time.Now().UnixNano())
	l.tracked.Store(100_000)
	if eta := l.ETA(0); !near(eta, base/2+37500*time.Microsecond, 3*time.Millisecond) {
		t.Fatalf("ETA with 100 KB outstanding = %v", eta)
	}
	// What is queued in the lane itself waits behind that.
	if eta := l.ETA(10_000); !near(eta, base/2+47500*time.Microsecond, 3*time.Millisecond) {
		t.Fatalf("ETA with 10 KB more queued = %v", eta)
	}
	// Late PONGs mean bytes are already waiting: no allowance beyond what
	// the lane delivers, so 50 KB over.
	l.late.Store(true)
	l.lastPong.Store(time.Now().UnixNano())
	if eta := l.ETA(0); !near(eta, base/2+50*time.Millisecond, 3*time.Millisecond) {
		t.Fatalf("ETA with 100 KB outstanding and late PONGs = %v", eta)
	}
	// Between PONGs the lane goes on delivering: a PING spacing later
	// (an eighth of a second at most; here a quarter of the RTT estimate)
	// that much less is outstanding.
	l.late.Store(false)
	spacing := l.pingSpacing()
	l.lastPong.Store(time.Now().Add(-time.Second).UnixNano())
	want := base/2 + 37500*time.Microsecond - spacing
	if eta := l.ETA(0); !near(eta, want, 3*time.Millisecond) {
		t.Fatalf("ETA long after the last PONG = %v, want about %v", eta, want)
	}
	// A confirmation brings it back down.
	l.confirmedA.Store(100_000)
	if eta := l.ETA(0); eta != base/2 {
		t.Fatalf("ETA with everything confirmed = %v", eta)
	}
}

func TestColdLaneIsOfferedHalfAnInitialWindow(t *testing.T) {
	l := pacedLane(t, 0)
	if got := l.clear(); got != coldWindow {
		t.Fatalf("clear = %v before any rate sample, want %v", got, coldWindow)
	}
	l.lastPong.Store(time.Now().UnixNano())
	l.tracked.Store(coldWindow)
	base := 50 * time.Millisecond
	if eta := l.ETA(0); !near(eta, base/2, time.Millisecond) {
		t.Fatalf("ETA within the cold window = %v", eta)
	}
	if eta := l.ETA(1448); eta <= base/2+time.Millisecond {
		t.Fatalf("ETA beyond the cold window = %v: a cold lane was offered more than it carries at once", eta)
	}
}

func TestWindowFollowsWhatPongsShow(t *testing.T) {
	const rate = 4e6 // 200 KB per base RTT
	l := pacedLane(t, rate)
	bdp := rate * 0.05
	if got := l.windowBytes(); got != windowGain*bdp {
		t.Fatalf("window = %v on time and steady, want %v", got, windowGain*bdp)
	}
	l.growing.Store(true)
	if got := l.windowBytes(); got != growthGain*bdp {
		t.Fatalf("window = %v while growing, want %v", got, growthGain*bdp)
	}
	// Late PONGs take precedence: bytes are waiting below the lane.
	l.late.Store(true)
	if got := l.windowBytes(); got != lateGain*bdp {
		t.Fatalf("window = %v with late PONGs, want %v", got, lateGain*bdp)
	}
	// A slow lane keeps a window it can at least fill a few records with.
	l.rate.Store(math.Float64bits(10_000))
	if got := l.windowBytes(); got != windowMin {
		t.Fatalf("window = %v on a slow lane, want the minimum %v", got, windowMin)
	}
	// And a lane with no rate sample gets the minimum too.
	if got := pacedLane(t, 0).windowBytes(); got != windowMin {
		t.Fatalf("window = %v before any sample", got)
	}
}

func TestRateFollowsPongsUpQuicklyAndDownSlowly(t *testing.T) {
	l := pacedLane(t, 0)
	base := 50 * time.Millisecond
	start := time.Now()
	var bytes uint64
	// pong feeds a PONG confirming n more bytes, d after the last one.
	at := start
	pong := func(d time.Duration, n uint64, sojourn time.Duration, limited bool) {
		at = at.Add(d)
		bytes += n
		l.pingMu.Lock()
		l.paceOnPong(outPing{bytes: bytes, limited: limited}, sojourn, at)
		l.pingMu.Unlock()
	}
	pong(0, 0, base, false)
	if l.rateSeen.Load() {
		t.Fatal("a rate from a single PONG")
	}
	// 100 KB in one base RTT: 2 MB/s. The first sample is taken as it is.
	pong(base, 100_000, base, false)
	if got := l.Rate(); !l.rateSeen.Load() || math.Abs(got-2e6) > 1e3 {
		t.Fatalf("rate = %v after the first sample, want 2e6", got)
	}
	// Twice as much in the next: a connection in slow start. On time, so
	// the estimate follows at once, and the lane counts as growing.
	pong(base, 200_000, base, false)
	if got := l.Rate(); math.Abs(got-4e6) > 1e3 {
		t.Fatalf("rate = %v after doubling, want 4e6", got)
	}
	if !l.growing.Load() || l.late.Load() || l.full.Load() {
		t.Fatalf("growing %v late %v full %v after a rising, on-time sample", l.growing.Load(), l.late.Load(), l.full.Load())
	}
	// A lower sample from a lane that was not kept busy says nothing.
	pong(base, 50_000, base, true)
	if got := l.Rate(); math.Abs(got-4e6) > 1e3 {
		t.Fatalf("rate = %v after an idle sample, want it unchanged", got)
	}
	if l.growing.Load() {
		t.Fatal("still growing after a sample well under the estimate")
	}
	// A lower sample from a busy lane brings it down, a sixteenth at a time.
	pong(base, 100_000, base, false)
	if got, want := l.Rate(), 4e6-(4e6-2e6)/16; math.Abs(got-want) > 1e3 {
		t.Fatalf("rate = %v after a busy, slower sample, want %v", got, want)
	}
	// A late PONG with the rate no longer rising: the lane is at capacity.
	pong(base, 190_000, 2*base, false)
	if !l.late.Load() || !l.full.Load() || l.growing.Load() {
		t.Fatalf("late %v full %v growing %v after a late PONG at a steady rate", l.late.Load(), l.full.Load(), l.growing.Load())
	}
	// A late PONG while the rate is still rising is a connection in slow
	// start that was given more than its window: not at capacity, and the
	// estimate moves only halfway.
	before := l.Rate()
	pong(base, 400_000, 2*base, false)
	if l.full.Load() {
		t.Fatal("a lane whose rate doubled was taken to be at capacity")
	}
	if got, want := l.Rate(), before+(8e6-before)/2; math.Abs(got-want) > 1e3 {
		t.Fatalf("rate = %v after a late, faster sample, want %v", got, want)
	}
	// On time again: no longer late or full.
	pong(base, 300_000, base, false)
	if l.late.Load() || l.full.Load() {
		t.Fatal("still late or full after a PONG on time")
	}
}

func TestIdleLaneStartsOver(t *testing.T) {
	l := pacedLane(t, 8e6)
	l.late.Store(true)
	l.full.Store(true)
	l.restart()
	if l.rateSeen.Load() || l.late.Load() || l.full.Load() || l.growing.Load() {
		t.Fatal("restart kept what the lane had learnt")
	}
	if got, want := l.Rate(), initialWindow/0.05; math.Abs(got-want) > 1 {
		t.Fatalf("rate = %v after restart, want an initial window per base RTT (%v)", got, want)
	}
	if got := l.clear(); got != coldWindow {
		t.Fatalf("clear = %v after restart", got)
	}
}

func TestQueueIsFullOnceItsOldestPacketHasWaitedARoundTrip(t *testing.T) {
	// The lane is never started, so nothing drains its queue.
	a, b := net.Pipe()
	defer b.Close()
	const rtt = 60 * time.Millisecond
	l := New(a, nil, Options{Role: Server, InitialRTT: rtt})
	defer l.Close()
	// Far more than the lane's rate estimate says it delivers in a round
	// trip (an initial window): how full the queue is goes by how long its
	// packets have waited, which the estimate has no part in.
	for i := range 200 {
		if !l.Send(make([]byte, 1400)) {
			t.Fatalf("packet %d refused while the queue was fresh", i)
		}
	}
	time.Sleep(rtt + 20*time.Millisecond)
	if l.Send(make([]byte, 1400)) {
		t.Fatal("packet taken although the queue has waited more than a round trip")
	}
}

func TestPacerSpacesRecordsOutAfterABurst(t *testing.T) {
	var p pacer
	now := time.Now()
	const rate = 1e6 // bytes/s
	if w := p.wait(now, rate); w != 0 {
		t.Fatalf("a fresh pacer waits %v", w)
	}
	// The burst is at least TCP's initial window: 14.48 ms at this rate.
	burst := time.Duration(initialWindow / rate * float64(time.Second))
	p.wrote(now, 10_000, rate) // 10 ms worth
	if w := p.wait(now, rate); w != 0 {
		t.Fatalf("waits %v inside the burst", w)
	}
	p.wrote(now, 10_000, rate) // 20 ms worth in all
	if w := p.wait(now, rate); !near(w, 20*time.Millisecond-burst, time.Microsecond) {
		t.Fatalf("waits %v after 20 ms worth, want %v", w, 20*time.Millisecond-burst)
	}
	// Time pays the debt off.
	if w := p.wait(now.Add(10*time.Millisecond), rate); w != 0 {
		t.Fatalf("still waits %v 10 ms later", w)
	}
	// Idle time is not saved up: after a long pause the burst is the same.
	later := now.Add(time.Second)
	p.wrote(later, 20_000, rate)
	if w := p.wait(later, rate); !near(w, 20*time.Millisecond-burst, time.Microsecond) {
		t.Fatalf("waits %v after a pause and 20 ms worth", w)
	}
	// At a high rate the burst is paceBurst.
	p = pacer{}
	p.wrote(now, 100_000, 10e6) // 10 ms worth
	if w := p.wait(now, 10e6); !near(w, 10*time.Millisecond-paceBurst, time.Microsecond) {
		t.Fatalf("waits %v at 10 MB/s, want %v", w, 10*time.Millisecond-paceBurst)
	}
}

func TestPacingOnlyHoldsALaneThatIsFull(t *testing.T) {
	// A lane writes freely while it is growing, however low its rate
	// estimate; what it wrote then must not be held against it later.
	a, b := tcpPair(t)
	var got atomic.Int64
	la := New(a, nil, Options{Role: Server})
	lb := New(b, nil, Options{Role: Server, Handler: Handler{
		Data: func(_ *Lane, pkt []byte) { got.Add(int64(len(pkt))) },
	}})
	defer la.Close()
	defer lb.Close()
	if err := la.Start(nil); err != nil {
		t.Fatal(err)
	}
	if err := lb.Start(nil); err != nil {
		t.Fatal(err)
	}
	const pkts, size = 2000, 1400
	start := time.Now()
	for i := 0; i < pkts; {
		if la.Send(make([]byte, size)) {
			i++
		} else {
			time.Sleep(time.Millisecond)
		}
	}
	deadline := start.Add(5 * time.Second)
	for got.Load() < pkts*size {
		if time.Now().After(deadline) {
			t.Fatalf("delivered %d of %d bytes in 5 s over loopback: %+v", got.Load(), pkts*size, la.Stats())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAnsweringPingsLeavesNothingOutstanding(t *testing.T) {
	// A lane that only answers the other end's PINGs sends no PING of its
	// own, so nothing would ever confirm the records its PONGs go in. They
	// must not count as bytes still on their way.
	a, b := tcpPair(t)
	la := New(a, nil, Options{Role: Server})
	lb := New(b, nil, Options{Role: Server})
	defer la.Close()
	defer lb.Close()
	if err := la.Start(nil); err != nil {
		t.Fatal(err)
	}
	if err := lb.Start(nil); err != nil {
		t.Fatal(err)
	}
	first := la.Stats().BytesSent
	for range 200 {
		lb.Send(make([]byte, 1000))
		time.Sleep(time.Millisecond)
	}
	deadline := time.Now().Add(2 * time.Second)
	for la.Stats().BytesSent == first || la.Stats().Unconfirmed != 0 || lb.Stats().PingsOut != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the answering lane: %+v", la.Stats())
		}
		time.Sleep(time.Millisecond)
	}
	if st := la.Stats(); st.Unconfirmed != 0 {
		t.Fatalf("%d bytes outstanding on a lane that only answered PINGs", st.Unconfirmed)
	}
}
