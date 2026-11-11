package sched

import (
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

// replacedAt is the age at which a lane carrying a steady rate (bytes/s) has
// its replacement opened.
func replacedAt(c Churn, l laneLife, rate float64) time.Duration {
	for age := time.Duration(0); ; age += 250 * time.Millisecond {
		if c.due(l, age, uint64(rate*age.Seconds())) {
			return age
		}
	}
}

func TestChurnBudgetCutsALaneNoShorterThanItsFloor(t *testing.T) {
	c := Churn{Lead: 5 * time.Second}
	l := laneLife{lifetime: 200 * time.Second, budget: 1000, floor: 60 * time.Second}
	for _, tc := range []struct {
		name    string
		l       laneLife
		age     time.Duration
		carried uint64
		want    bool
	}{
		{"young and under budget", l, 30 * time.Second, 100, false},
		{"over budget but younger than its floor", l, 30 * time.Second, 1 << 40, false},
		{"over budget just short of the lead before its floor", l, 54 * time.Second, 1 << 40, false},
		{"over budget, the lead before its floor", l, 55 * time.Second, 1 << 40, true},
		{"past its floor, under budget", l, 100 * time.Second, 899, false},
		{"past its floor, within a tenth of its budget", l, 100 * time.Second, 900, true},
		{"the lead before its lifetime, having carried nothing", l, 195 * time.Second, 0, true},
		{"floor beyond the lifetime: the lifetime decides",
			laneLife{lifetime: 60 * time.Second, budget: 1000, floor: 200 * time.Second}, 55 * time.Second, 0, true},
	} {
		if got := c.due(tc.l, tc.age, tc.carried); got != tc.want {
			t.Errorf("%s: due = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// However fast a tunnel runs, its lanes turn over about as often as their
// lifetimes say: the byte budget brings a lane's replacement forward, but
// never to before a second lifetime drawn for it.
func TestChurnTurnoverIsBoundedByTimeNotThroughput(t *testing.T) {
	c := DefaultChurn()
	const n = 2000
	median := map[string]time.Duration{}
	early := map[string]float64{}
	for _, r := range []struct {
		name string
		rate float64 // bytes/s
	}{
		{"4 Mbit/s", 0.5e6}, {"40 Mbit/s", 5e6}, {"100 Mbit/s", 12.5e6},
		{"1 Gbit/s", 125e6}, {"10 Gbit/s", 1250e6},
	} {
		rng := rand.New(rand.NewPCG(3, 4))
		ages := make([]time.Duration, n)
		cut := 0
		for i := range ages {
			l := c.draw(rng)
			ages[i] = replacedAt(c, l, r.rate)
			if ages[i] < c.LifetimeMin-c.Lead {
				t.Fatalf("%s: a lane was replaced at %v, before the shortest lifetime", r.name, ages[i])
			}
			if ages[i] < l.lifetime-c.Lead {
				cut++
			}
		}
		slices.Sort(ages)
		median[r.name], early[r.name] = ages[n/2], float64(cut)/n
		t.Logf("%-10s replaced at: median %v, p5 %v; %2.0f%% before their lifetime",
			r.name, ages[n/2], ages[n/20], 100*early[r.name])
	}
	// Left to the lifetime alone, the median lane is replaced Lead before
	// 90 s. The shorter of two lifetimes has a median of about 61 s.
	if m := median["4 Mbit/s"]; m < 78*time.Second || m > 92*time.Second {
		t.Errorf("at 4 Mbit/s the median lane is replaced at %v, want about 85s", m)
	}
	if e := early["40 Mbit/s"]; e > 0.10 {
		t.Errorf("at 40 Mbit/s the byte budget cut %.0f%% of lanes short, want it to leave nearly all alone", 100*e)
	}
	for name, m := range median {
		if m < 48*time.Second {
			t.Errorf("at %s the median lane is replaced at %v: throughput is setting the turnover", name, m)
		}
	}
	// The budget still does something where a lane can spend it.
	if e := early["1 Gbit/s"]; e < 0.35 || e > 0.65 {
		t.Errorf("at 1 Gbit/s the byte budget cut %.0f%% of lanes short, want about half", 100*e)
	}
	if median["10 Gbit/s"] < median["1 Gbit/s"]-3*time.Second {
		t.Errorf("turnover still rises with the rate: median %v at 1 Gbit/s, %v at 10 Gbit/s",
			median["1 Gbit/s"], median["10 Gbit/s"])
	}
}

// carryAll records n bytes arriving on the lane, as payload and on the wire.
func (l *fakeLane) carryAll(n uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stats.DataRecv += n
	l.stats.BytesRecv += n
}

func TestPoolDoesNotReplaceALaneForWhatItCarriesAlone(t *testing.T) {
	const lifetime, lead = 400 * time.Millisecond, 50 * time.Millisecond
	d := newFakeDialer()
	d.welcome = 1
	start := time.Now()
	p := newTestPool(t, d, PoolConfig{Churn: Churn{
		LifetimeMedian: lifetime, LifetimeMin: lifetime, LifetimeMax: lifetime,
		BytesMedian: 1 << 10, BytesMin: 1 << 10, BytesMax: 1 << 10,
		Lead: lead, Overlap: 40 * time.Millisecond,
	}})
	stop := make(chan struct{})
	defer close(stop)
	go func() { // keep the tunnel active
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
				p.Send(make([]byte, 100))
			}
		}
	}()
	// Every lane has carried a thousand times its budget the moment it is
	// up, as on a fast download.
	l1, l2 := d.next(t), d.next(t)
	l1.carryAll(1 << 20)
	l2.carryAll(1 << 20)
	r := d.next(t)
	if r.req.Reason != "churn" {
		t.Fatalf("third lane dialed for %q, want churn", r.req.Reason)
	}
	if el := time.Since(start); el < lifetime-lead-20*time.Millisecond {
		t.Fatalf("a lane was replaced %v after the pool started for what it carried, with %v of its lifetime to run",
			el, lifetime-lead)
	}
	// And so on down the generations: over the next second each lane is
	// replaced as its lifetime ends, not as fast as replacements can open.
	r.carryAll(1 << 20)
	dials := 1
	deadline := time.After(time.Second)
	for done := false; !done; {
		select {
		case l := <-d.lanes:
			l.carryAll(1 << 20)
			dials++
		case <-deadline:
			done = true
		}
	}
	if dials > 10 {
		t.Fatalf("%d lanes replaced in %v with a %v lifetime: the byte budget is driving the turnover",
			dials, time.Since(start).Round(time.Millisecond), lifetime)
	}
}
