package sched

import "time"

// Throttle detection (design §7): under load, if every lane settles at about
// the same rate and adding a lane adds about that much more again, the
// network is limiting each connection separately. The client keeps adding
// lanes while each one pays off, and closes lanes once they stop helping.
//
// throttle is a pure state machine over per-lane throughput samples, so it
// can be tested without a network. The pool feeds it once per sample period
// and gets back how many lanes to run beyond the base count.
type throttle struct {
	// Tunables.
	minLoad     float64       // bytes/s in the busier direction that counts as load
	loadFor     time.Duration // load must last this long before probing
	settle      time.Duration // how long a new lane gets before it is judged
	payoff      float64       // the gain, as a share of one lane's rate, that counts as paying off
	evenness    float64       // slowest/fastest lane rate above which lanes count as capped alike
	unloadReset time.Duration // no load for this long drops the extra lanes
	backoffMin  time.Duration
	backoffMax  time.Duration

	extra     int
	probing   bool
	probeAt   time.Time
	baseline  float64
	perLane   float64
	nextProbe time.Time
	backoff   time.Duration
	loaded    time.Time // when the current stretch of load began; zero if none
	unloaded  time.Time // when the current stretch without load began
	uneven    int       // consecutive loaded samples with uneven lanes
	hist      [3]float64
	histN     int
	throttled bool
}

func newThrottle() *throttle {
	return &throttle{
		minLoad:     128 << 10, // about 1 Mbit/s
		loadFor:     3 * time.Second,
		settle:      4 * time.Second,
		payoff:      0.5,
		evenness:    0.66,
		unloadReset: 10 * time.Second,
		backoffMin:  20 * time.Second,
		backoffMax:  5 * time.Minute,
	}
}

// laneRate is one lane's measured throughput in the busier direction.
type laneRate struct {
	rate    float64 // bytes/s
	settled bool    // the lane has been carrying traffic long enough to judge
}

// update takes one sample: the rate of every lane in the busier direction,
// the number of lanes the pool is aiming for without extras (base), and the
// most it may run. ready says whether the pool currently has as many lanes
// as it asked for. It returns the number of extra lanes to run.
func (t *throttle) update(now time.Time, lanes []laneRate, base, limit int, ready bool) int {
	var agg, lo, hi float64
	settled := 0
	for i, l := range lanes {
		agg += l.rate
		if i == 0 || l.rate < lo {
			lo = l.rate
		}
		if l.rate > hi {
			hi = l.rate
		}
		if l.settled {
			settled++
		}
	}
	t.hist[t.histN%len(t.hist)] = agg
	t.histN++
	avg := t.average()

	if agg < t.minLoad {
		t.loaded = time.Time{}
		if t.unloaded.IsZero() {
			t.unloaded = now
		}
		if now.Sub(t.unloaded) >= t.unloadReset {
			t.extra, t.probing, t.throttled = 0, false, false
		}
		return t.clamp(base, limit)
	}
	t.unloaded = time.Time{}
	if t.loaded.IsZero() {
		t.loaded = now
	}
	even := len(lanes) > 0 && hi > 0 && lo/hi >= t.evenness && settled == len(lanes)

	if t.probing {
		if !ready || now.Sub(t.probeAt) < t.settle || settled < len(lanes) {
			return t.clamp(base, limit)
		}
		t.probing = false
		if avg-t.baseline >= t.payoff*t.perLane {
			// The new lane paid off: each connection is capped. Keep it
			// and try another as soon as things settle.
			t.throttled = true
			t.backoff = t.backoffMin
			t.nextProbe = now
		} else {
			t.extra = max(0, t.extra-1)
			t.backoff = min(max(t.backoff*2, t.backoffMin), t.backoffMax)
			t.nextProbe = now.Add(t.backoff)
		}
		return t.clamp(base, limit)
	}

	if !even {
		// Lanes running at very different rates aren't held to a common
		// cap, so extra lanes aren't what's helping.
		t.uneven++
		if t.extra > 0 && t.uneven >= 3 {
			t.extra--
			t.uneven = 0
		}
		return t.clamp(base, limit)
	}
	t.uneven = 0

	n := len(lanes)
	if ready && now.Sub(t.loaded) >= t.loadFor && !now.Before(t.nextProbe) && base+t.extra < limit && n > 0 {
		t.baseline = avg
		t.perLane = avg / float64(n)
		t.extra++
		t.probing = true
		t.probeAt = now
	}
	return t.clamp(base, limit)
}

func (t *throttle) average() float64 {
	n := min(t.histN, len(t.hist))
	var s float64
	for i := range n {
		s += t.hist[i]
	}
	return s / float64(n)
}

func (t *throttle) clamp(base, limit int) int {
	t.extra = max(0, min(t.extra, limit-base))
	return t.extra
}

// laneAdded tells the throttle a lane came up. While probing, the probe is
// judged only once that lane has had time to settle.
func (t *throttle) laneAdded(now time.Time) {
	if t.probing {
		t.probeAt = now
		t.histN = 0
	}
}
