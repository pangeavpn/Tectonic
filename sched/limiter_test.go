package sched

import (
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/lane"
)

// A path that carries 10 MB/s with a 50 ms round trip, in stretches of the
// least length.
const (
	pathRate = 10e6
	stretch  = limitSpanMin
)

// feed reports one stretch of a session that sent at sentRate bytes a
// second, of which the share lost was sent again, on a path that delivered
// at pathRate at most, with or without a queue on it. It returns the time at
// the end of the stretch.
func feed(g *Limiter, now time.Time, sentRate, lost float64, queued bool) time.Time {
	secs := stretch.Seconds()
	sent := sentRate * secs
	now = now.Add(stretch)
	g.Report(now, lane.Progress{
		Sent:      uint64(sent),
		Resent:    uint64(sent * lost),
		Delivered: uint64(min(sent*(1-lost), pathRate*secs)),
		RTT:       50 * time.Millisecond,
		Queued:    queued,
	})
	return now
}

// overload reports stretches like a lane in BBR's start-up makes them: a
// third more than the path carries, a quarter of it lost, a queue on the
// path. It returns once the limit is on.
func overload(t *testing.T, g *Limiter, now time.Time) time.Time {
	t.Helper()
	now = feed(g, now, 0, 0, false) // starts the first stretch
	for range limitStrikes {
		if g.Stats().Rate != 0 {
			t.Fatal("the limit came on before the path had been overloaded twice in a row")
		}
		now = feed(g, now, 1.33*pathRate, 0.25, true)
	}
	if g.Stats().Rate == 0 {
		t.Fatal("the limit did not come on")
	}
	return now
}

func TestLimiterIsOffUntilThePathIsOverloaded(t *testing.T) {
	var g Limiter
	now := time.Now()
	if g.Wait(now) != 0 {
		t.Fatal("a new limiter holds DATA back")
	}
	now = feed(&g, now, 0, 0, false)
	for range 20 {
		// A session using the whole path with nothing going wrong.
		now = feed(&g, now, pathRate, 0, false)
	}
	for range 20 {
		// Loss at random, and plenty of it, with no queue on the path:
		// lanes that ride that out are doing what they should.
		now = feed(&g, now, 0.5*pathRate, 0.1, false)
	}
	for range 20 {
		// A queue on the path and the little loss a connection that
		// backs off sees at the top of its climb.
		now = feed(&g, now, pathRate, 0.01, true)
	}
	for range 20 {
		// Heavy loss and a queue, on next to no traffic.
		now = feed(&g, now, 0.005*pathRate, 0.3, true)
	}
	// One bad stretch, then a good one: the connection has backed off.
	for range 10 {
		now = feed(&g, now, 1.3*pathRate, 0.25, true)
		now = feed(&g, now, 0.7*pathRate, 0, true)
	}
	if st := g.Stats(); st.Rate != 0 || st.On != 0 || g.Wait(now) != 0 {
		t.Fatalf("the limit came on: %+v", st)
	}
}

func TestLimiterHoldsTheSessionToWhatThePathDelivers(t *testing.T) {
	var g Limiter
	now := overload(t, &g, time.Now())
	st := g.Stats()
	if st.On != 1 {
		t.Fatalf("stats %+v", st)
	}
	// What the path delivered, less a little.
	if want := limitEase * pathRate; st.Rate < 0.98*want || st.Rate > 1.02*want {
		t.Fatalf("rate %.0f after an overload on a %.0f path, want about %.0f", st.Rate, pathRate, want)
	}
	// A burst goes at once; after it the session is spaced out at the rate.
	if w := g.Wait(now); w != 0 {
		t.Fatalf("the first record waits %v", w)
	}
	wrote := 0
	for g.Wait(now) == 0 {
		g.Wrote(now, 16<<10)
		wrote += 16 << 10
	}
	if burst := float64(wrote); burst > st.Rate*0.02 {
		t.Fatalf("%d bytes went at once, more than 20 ms at the rate", wrote)
	}
	w := g.Wait(now)
	if w <= 0 || w > 10*time.Millisecond {
		t.Fatalf("after the burst the next record waits %v", w)
	}
	// Later it may write again, and over a second it gets about the rate.
	if g.Wait(now.Add(w)) != 0 {
		t.Fatal("the wait the limiter gave was not enough")
	}
	var g2 Limiter
	now = overload(t, &g2, time.Now())
	rate, total := g2.Stats().Rate, 0
	for end := now.Add(stretch / 2); now.Before(end); now = now.Add(100 * time.Microsecond) {
		if g2.Wait(now) == 0 {
			g2.Wrote(now, 4<<10)
			total += 4 << 10
		}
	}
	if got, want := float64(total), rate*(stretch/2).Seconds(); got < 0.9*want || got > 1.3*want {
		t.Fatalf("wrote %.0f bytes in half a stretch at a rate of %.0f a second, want about %.0f", got, rate, want)
	}
}

// drive runs the limiter for n stretches with a session that writes all the
// limit allows, on a path that delivers pathRate, and returns the time and
// the share of what it sent that the path had to drop.
func drive(g *Limiter, now time.Time, n int, queueAbove float64) (time.Time, float64) {
	var sent, dropped float64
	for range n {
		rate := g.Stats().Rate
		g.Wrote(now, int(rate*stretch.Seconds()))
		lost := max(1-pathRate/rate, 0)
		sent += rate
		dropped += rate * lost
		now = feed(g, now, rate, lost, rate > queueAbove*pathRate)
	}
	return now, dropped / sent
}

func TestLimiterFollowsThePath(t *testing.T) {
	var g Limiter
	now := overload(t, &g, time.Now())
	// The session keeps writing all it is allowed. The rate settles just
	// over what the path carries, where the path drops about limitAim of
	// it, and stays there: the session was losing a quarter.
	now, _ = drive(&g, now, 50, 0.97)
	lowest, highest := g.Stats().Rate, g.Stats().Rate
	var lost float64
	for range 100 {
		now, lost = drive(&g, now, 1, 0.97)
		lowest, highest = min(lowest, g.Stats().Rate), max(highest, g.Stats().Rate)
		if lost > 0.03 {
			t.Fatalf("the path dropped %.1f%% of what a limited session sent in a stretch", lost*100)
		}
	}
	if lowest < 0.99*pathRate || highest > 1.03*pathRate {
		t.Fatalf("the rate moved between %.0f and %.0f on a %.0f path, want it settled just above", lowest, highest, pathRate)
	}
	if st := g.Stats(); st.Eased != 0 {
		t.Fatalf("the rate had to jump back %d times on a steady path", st.Eased)
	}
	// The path loses half of what it carried: the rate jumps down to what
	// is delivered now, in one stretch.
	rate := g.Stats().Rate
	g.Wrote(now, int(rate*stretch.Seconds()))
	now = now.Add(stretch)
	g.Report(now, lane.Progress{
		Sent: uint64(rate * stretch.Seconds()), Resent: uint64(0.5 * rate * stretch.Seconds()),
		Delivered: uint64(0.5 * pathRate * stretch.Seconds()), RTT: 50 * time.Millisecond, Queued: true,
	})
	if st := g.Stats(); st.Eased != 1 || st.Rate > 1.02*pathRate {
		t.Fatalf("after the path lost half its capacity: %+v", st)
	}
	// The path gets faster: with no queue on it the rate grows every
	// stretch the session is held by it.
	before := g.Stats().Rate
	for range 10 {
		rate := g.Stats().Rate
		g.Wrote(now, int(rate*stretch.Seconds()))
		now = feed(&g, now, rate, 0, false)
	}
	if got := g.Stats().Rate / before; got < 1.2 {
		t.Fatalf("the rate grew %.2fx in ten stretches with room on the path", got)
	}
	// And not at all while the session is sending well under it.
	before = g.Stats().Rate
	for range 5 {
		g.Wrote(now, int(0.6*before*stretch.Seconds()))
		now = feed(&g, now, 0.6*before, 0, false)
	}
	if got := g.Stats().Rate; got != before {
		t.Fatalf("the rate moved from %.0f to %.0f while the session was not held by it", before, got)
	}
}

func TestLimiterGoesWhenTheSessionDoesNotNeedIt(t *testing.T) {
	var g Limiter
	now := overload(t, &g, time.Now())
	// The session falls to a fifth of the rate: nothing to hold back.
	for i := range limitSlackSpans {
		if g.Stats().Rate == 0 {
			t.Fatalf("the limit went after %d quiet stretches", i)
		}
		rate := g.Stats().Rate
		g.Wrote(now, int(0.2*rate*stretch.Seconds()))
		now = feed(&g, now, 0.2*rate, 0, false)
	}
	if st := g.Stats(); st.Rate != 0 || g.Wait(now) != 0 {
		t.Fatalf("the limit stayed on an idle session: %+v", st)
	}
	// A session whose lanes have gone quiet altogether reports nothing;
	// the limit goes the next time anyone asks.
	now = overload(t, &g, now)
	if g.Wait(now.Add(time.Minute)) != 0 || g.Stats().Rate != 0 {
		t.Fatal("the limit outlived a minute of silence")
	}
}

func TestLimiterStandsDownOnAPathItDoesNotFit(t *testing.T) {
	// A path that limits each connection: three lanes that may carry a
	// third of pathRate each. Whatever the session is allowed, the
	// scheduler gives most of it to one lane, the path drops what is over
	// that lane's share, and so the session delivers less than it is
	// allowed, every time.
	var g Limiter
	now := overload(t, &g, time.Now())
	start := g.Stats().Rate
	for i := 0; g.Stats().Rate != 0; i++ {
		if i > 40 {
			t.Fatalf("the limit kept ratcheting down: %.0f, from %.0f", g.Stats().Rate, start)
		}
		rate := g.Stats().Rate
		g.Wrote(now, int(rate*stretch.Seconds()))
		secs := stretch.Seconds()
		now = now.Add(stretch)
		g.Report(now, lane.Progress{
			Sent: uint64(rate * secs), Resent: uint64(0.2 * rate * secs),
			Delivered: uint64(0.8 * rate * secs), RTT: 50 * time.Millisecond, Queued: true,
		})
	}
	if st := g.Stats(); st.StoodDown != 1 {
		t.Fatalf("stats %+v", st)
	}
	// It leaves the lanes to themselves for a while, whatever they show.
	for range 20 {
		now = feed(&g, now, 1.33*pathRate, 0.25, true)
	}
	if g.Stats().Rate != 0 {
		t.Fatal("the limit came back on while standing down")
	}
	// And is ready again afterwards.
	now = now.Add(limitRest)
	overload(t, &g, now)
}

func TestLimiterStandsDownForLongerEachTime(t *testing.T) {
	var g Limiter
	now := time.Now()
	for n, want := range []time.Duration{limitRest, 2 * limitRest, 4 * limitRest} {
		now = overload(t, &g, now)
		for g.Stats().Rate != 0 {
			rate := g.Stats().Rate
			g.Wrote(now, int(rate*stretch.Seconds()))
			now = now.Add(stretch)
			g.Report(now, lane.Progress{
				Sent: uint64(rate * stretch.Seconds()), Resent: uint64(0.3 * rate * stretch.Seconds()),
				Delivered: uint64(0.7 * rate * stretch.Seconds()), RTT: 50 * time.Millisecond, Queued: true,
			})
		}
		// Just short of the rest it does not come back, however the path looks.
		now = now.Add(want - 10*stretch)
		for range 5 {
			now = feed(&g, now, 1.33*pathRate, 0.25, true)
		}
		if g.Stats().Rate != 0 {
			t.Fatalf("stand-down %d ended before %v", n+1, want)
		}
		now = now.Add(10 * stretch)
	}
}
