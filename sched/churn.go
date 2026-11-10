package sched

import (
	"math"
	"math/rand/v2"
	"time"
)

// Churn describes how long lanes live and how much they carry (design §7):
// each lane's lifetime is drawn from a browser-like distribution, median
// about 90 s within 20 s to 6 min, and its byte budget the same way, median
// about 40 MB. Both are log-normal around the median and clamped.
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
	// Overlap is how long the replacement carries traffic alongside the
	// old lane before the old one is retired, so the new connection is past
	// TCP slow start by the time it takes over.
	Overlap time.Duration
}

// DefaultChurn returns the design's lane lifetimes and byte budgets. The
// byte budget's range scales the lifetime's: 20 s to 6 min around a 90 s
// median becomes about 9 MB to 160 MB around 40 MB.
func DefaultChurn() Churn {
	return Churn{
		LifetimeMedian: 90 * time.Second,
		LifetimeMin:    20 * time.Second,
		LifetimeMax:    6 * time.Minute,
		BytesMedian:    40 << 20,
		BytesMin:       9 << 20,
		BytesMax:       160 << 20,
		Sigma:          0.7,
		Lead:           5 * time.Second,
		Overlap:        time.Second,
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
