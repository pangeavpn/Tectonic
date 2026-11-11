package sched

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/shape"
)

// idleTimings is a profile whose tunnel is idle after idleAfter and closes
// its last lane a fixed hold later, and does not reopen within a test.
func idleTimings(t *testing.T, idleAfter, hold time.Duration) *shape.Set {
	return testProfiles(t, func(p *shape.Profile) {
		p.IdleAfter = shape.Duration(idleAfter)
		p.IdleClose = shape.DurationRange{Min: shape.Duration(hold), Max: shape.Duration(hold)}
		p.IdleReopen = shape.DurationRange{Min: shape.Duration(time.Minute), Max: shape.Duration(time.Minute)}
	})
}

// The pool does not shrink to one lane the instant the tunnel goes idle,
// which put a connection's close at the same offset from the last traffic
// in every session. The moment is drawn for each idle period, between the
// tunnel going idle and its last lane closing.
func TestPoolIdleShrinkIsDrawnPerIdlePeriod(t *testing.T) {
	const (
		idleAfter = 100 * time.Millisecond
		hold      = 800 * time.Millisecond
		sessions  = 16
	)
	type result struct {
		shrink, closed time.Duration // since the session's last real traffic
		err            string
	}
	profiles := idleTimings(t, idleAfter, hold)
	results := make(chan result, sessions)
	fastTicks(t) // once, before any pool runs: the pools read it
	for range sessions {
		d := newFakeDialer()
		d.welcome = 1
		start := time.Now() // a new pool counts as active from here
		p := NewPool(PoolConfig{Dial: d.dial, Profiles: profiles})
		t.Cleanup(func() { p.Close() })
		go func() {
			var lanes [2]*fakeLane
			for i := range lanes {
				select {
				case lanes[i] = <-d.lanes:
				case <-time.After(5 * time.Second):
					results <- result{err: "no lane dialed"}
					return
				}
			}
			var r result
			for r.closed == 0 {
				n := 0
				for _, l := range lanes {
					if l.wasRetired() {
						n++
					}
				}
				el := time.Since(start)
				if n >= 1 && r.shrink == 0 {
					r.shrink = el
				}
				if n == 2 {
					r.closed = el
				}
				if el > 10*time.Second {
					r.err = fmt.Sprintf("%d lanes retired after %v", n, el)
					break
				}
				time.Sleep(2 * time.Millisecond)
			}
			results <- r
		}()
	}
	var shrinks []time.Duration
	for range sessions {
		r := <-results
		if r.err != "" {
			t.Fatal(r.err)
		}
		if r.shrink < idleAfter {
			t.Errorf("shrank to one lane after %v, before the tunnel was idle (%v)", r.shrink, idleAfter)
		}
		if r.closed < idleAfter+hold {
			t.Errorf("last lane closed after %v, want %v", r.closed, idleAfter+hold)
		}
		if r.shrink > r.closed {
			t.Errorf("shrank after %v, later than the last lane closed (%v)", r.shrink, r.closed)
		}
		shrinks = append(shrinks, r.shrink.Round(time.Millisecond))
	}
	slices.Sort(shrinks)
	t.Logf("shrank to one lane after: %v", shrinks)
	// Sixteen draws over 800 ms fall within 250 ms of each other about once
	// in two million runs. The fixed timer put them all within a tick.
	if spread := shrinks[len(shrinks)-1] - shrinks[0]; spread < 250*time.Millisecond {
		t.Fatalf("every session shrank within %v of the same moment: %v", spread, shrinks)
	}
}

// Keeping its lanes for a while into an idle period does not make the pool
// treat the tunnel as active: a lane whose lifetime ends then is not
// replaced, as before.
func TestPoolDoesNotChurnWhileItWaitsToShrink(t *testing.T) {
	d := newFakeDialer()
	d.welcome = 1
	newTestPool(t, d, PoolConfig{
		Profiles: idleTimings(t, 100*time.Millisecond, 600*time.Millisecond),
		Churn: Churn{
			LifetimeMedian: 300 * time.Millisecond, LifetimeMin: 300 * time.Millisecond, LifetimeMax: 300 * time.Millisecond,
			Lead: 50 * time.Millisecond, Overlap: 40 * time.Millisecond,
		},
	})
	l1, l2 := d.next(t), d.next(t)
	// Both lanes are due for replacement 250 ms in, when the tunnel has
	// been idle for 150 ms and may hold both for up to 700 ms.
	d.none(t, 900*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for !l1.wasRetired() || !l2.wasRetired() {
		if time.Now().After(deadline) {
			t.Fatalf("lanes not closed once idle: retired %v %v", l1.wasRetired(), l2.wasRetired())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// While it waits to shrink the pool keeps what it has: a lane that dies
// then is not replaced, since one lane is all an idle tunnel wants.
func TestPoolOpensNoLaneWhileItWaitsToShrink(t *testing.T) {
	d := newFakeDialer()
	d.welcome = 1
	newTestPool(t, d, PoolConfig{Profiles: idleTimings(t, 50*time.Millisecond, 2*time.Second)})
	l1, l2 := d.next(t), d.next(t)
	time.Sleep(100 * time.Millisecond) // idle now
	// The older lane is the one a shrink would have retired, so it dying
	// leaves the pool one lane whether or not it has shrunk yet.
	l1.end(errors.New("reset"))
	d.none(t, 400*time.Millisecond)
	if l2.wasRetired() {
		t.Fatal("the remaining lane was retired with the idle period still running")
	}
}

// The pool acts at the moment it drew, not on its next tick after it: ticks
// keep time from the pool's last event, so closes rounded to them would
// share a half-second grid.
func TestPoolShrinksAtTheMomentDrawnNotOnTheTickAfter(t *testing.T) {
	const (
		sessions = 6
		late     = 100 * time.Millisecond // against a 500 ms tick
	)
	if activeTick < 4*late {
		t.Fatalf("activeTick is %v; this test needs the pool's real tick", activeTick)
	}
	profiles := idleTimings(t, 50*time.Millisecond, 600*time.Millisecond)
	results := make(chan string, sessions)
	for range sessions {
		d := newFakeDialer()
		d.welcome = 1
		p := NewPool(PoolConfig{Dial: d.dial, Profiles: profiles})
		t.Cleanup(func() { p.Close() })
		l1, l2 := d.next(t), d.next(t)
		drawn := make(chan time.Time, 1)
		p.post(func() { drawn <- time.Unix(0, p.lastActive.Load()).Add(p.idleShrink) })
		due := <-drawn
		go func() {
			for !l1.wasRetired() && !l2.wasRetired() {
				if time.Since(due) > 5*time.Second {
					results <- "the pool never shrank"
					return
				}
				time.Sleep(time.Millisecond)
			}
			if el := time.Since(due); el < -5*time.Millisecond || el > late {
				results <- fmt.Sprintf("shrank %v after the moment drawn", el)
				return
			}
			results <- ""
		}()
	}
	for range sessions {
		if msg := <-results; msg != "" {
			t.Error(msg)
		}
	}
}
