package sched

import (
	"math"
	"math/rand/v2"
	"time"
)

// Churn describes how long lanes live and how much they carry (design §7).
//
// Time decides how often lanes turn over. Each lane's lifetime is drawn
// from a browser-like distribution, log-normal with a median of about 90 s
// and clamped to 20 s to 6 min, and its replacement opens when that is up.
//
// The byte budget, drawn the same way around 2 GiB, can bring that forward
// only within the same distribution: a lane that has carried its budget is
// replaced early, but no sooner than a second lifetime drawn for it. A
// budget that replaced a lane by itself would turn throughput into a
// connection rate (40 MB at 5 MB/s is a new connection every 8 s, for as
// long as a download lasts), which marks a client far more plainly than
// anything one connection carries. As it is, a tunnel at any speed opens
// connections no more often than the shorter of two lifetimes allows: a
// median of about 60 s, still within 20 s to 6 min.
type Churn struct {
	LifetimeMedian time.Duration
	LifetimeMin    time.Duration
	LifetimeMax    time.Duration
	BytesMedian    uint64
	BytesMin       uint64
	BytesMax       uint64
	// Sigma is the log-normal spread.
	Sigma float64
	// Lead is how long before a lane expires its replacement starts
	// opening, so the new lane is carrying traffic before the old one goes.
	Lead time.Duration
	// Overlap is the least time the replacement carries traffic alongside
	// the old lane before the old one is retired, and how long the old
	// lane must then have carried nothing. A new connection takes the
	// traffic only as fast as TCP lets it grow, which next to a busy
	// connection can take many seconds, so an old lane that is still
	// carrying something stays, up to MaxOverlap or BytesMax in all.
	Overlap    time.Duration
	MaxOverlap time.Duration
}

// DefaultChurn returns the design's lane lifetimes and byte budgets.
//
// The budget is set where time decides at the rates a tunnel usually runs
// at, and bytes only trim the longest-lived lanes above them. 2 GiB over a
// 90 s lifetime is about 190 Mbit/s. At 40 Mbit/s the budget touches one
// lane in twenty, and none before it is a minute and a half old; at
// 100 Mbit/s one in five. Its range scales the lifetime's: 20 s to 6 min
// around 90 s becomes 455 MiB to 8 GiB around 2 GiB.
func DefaultChurn() Churn {
	return Churn{
		LifetimeMedian: 90 * time.Second,
		LifetimeMin:    20 * time.Second,
		LifetimeMax:    6 * time.Minute,
		BytesMedian:    2 << 30,
		BytesMin:       455 << 20,
		BytesMax:       8 << 30,
		Sigma:          0.7,
		Lead:           5 * time.Second,
		Overlap:        time.Second,
		MaxOverlap:     30 * time.Second,
	}
}

func (c Churn) withDefaults() Churn {
	d := DefaultChurn()
	if c.LifetimeMedian <= 0 {
		c.LifetimeMedian, c.LifetimeMin, c.LifetimeMax = d.LifetimeMedian, d.LifetimeMin, d.LifetimeMax
	}
	if c.BytesMedian == 0 {
		c.BytesMedian, c.BytesMin, c.BytesMax = d.BytesMedian, d.BytesMin, d.BytesMax
	}
	if c.Sigma <= 0 {
		c.Sigma = d.Sigma
	}
	if c.Lead <= 0 {
		c.Lead = d.Lead
	}
	if c.Overlap <= 0 {
		c.Overlap = d.Overlap
	}
	if c.MaxOverlap <= 0 {
		c.MaxOverlap = max(d.MaxOverlap, c.Overlap)
	}
	return c
}

// lognormal draws median·e^(σ·N(0,1)) clamped to [lo, hi].
func lognormal(rng *rand.Rand, median, sigma, lo, hi float64) float64 {
	v := median * math.Exp(sigma*rng.NormFloat64())
	return min(max(v, lo), hi)
}

// Lifetime draws a lane lifetime.
func (c Churn) Lifetime(rng *rand.Rand) time.Duration {
	return time.Duration(lognormal(rng, float64(c.LifetimeMedian), c.Sigma, float64(c.LifetimeMin), float64(c.LifetimeMax)))
}

// Budget draws a lane byte budget.
func (c Churn) Budget(rng *rand.Rand) uint64 {
	return uint64(lognormal(rng, float64(c.BytesMedian), c.Sigma, float64(c.BytesMin), float64(c.BytesMax)))
}

// laneLife is what a lane draws when it opens.
type laneLife struct {
	// lifetime is the age at which the lane is replaced, whatever it has
	// carried.
	lifetime time.Duration
	// budget is how much the lane may carry, both ways and padding
	// included, before it is replaced early.
	budget uint64
	// floor is a second lifetime: however fast the lane spends its budget,
	// it is not replaced younger than this.
	floor time.Duration
}

// draw draws a lane's lifetime, byte budget and floor.
func (c Churn) draw(rng *rand.Rand) laneLife {
	return laneLife{lifetime: c.Lifetime(rng), budget: c.Budget(rng), floor: c.Lifetime(rng)}
}

// due reports whether a lane of this age, having carried this much, should
// have its replacement opened: Lead before its lifetime is up, or, once it
// is within a tenth of its byte budget, Lead before its floor.
func (c Churn) due(l laneLife, age time.Duration, carried uint64) bool {
	if age >= l.lifetime-c.Lead {
		return true
	}
	return carried >= l.budget/10*9 && age >= l.floor-c.Lead
}
