package sched

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/pangeavpn/tectonic/lane"
	"github.com/pangeavpn/tectonic/shape"
)

// What the tunnel cannot carry is meant to wait in a lane's queue, where it
// can be steered or dropped, and the lanes' own congestion control is meant
// to say how much that is: a connection that is sending all it may takes no
// more, its lane's queue fills, and a full queue drops (design §7).
//
// Not every congestion control says so. BBR starts a connection at nearly
// three times the rate it has measured and leaves that phase only after
// several round trips with data always waiting to be sent. The TCP inside
// the tunnel is clocked by its own acknowledgements and rarely offers a
// lane more than the lane is carrying, so a BBR lane can stay in that phase
// for as long as it lives, passing on whatever it is given. Nothing then
// stands between the TCP inside the tunnel and the queue on the path, which
// overflows: on a clean link with a BBR node the lanes retransmitted a
// quarter of what they sent, twice what one BBR connection does, and
// stalled on every loss.
//
// A Limiter is the limit of Tectonic's own for that case, shared by the
// lanes of a session because they share a path and the scheduler moves
// traffic between them. It does nothing until the lanes' connections show
// that the path is being offered more than it carries: over a stretch of a
// couple of round trips they retransmitted more than limitLoss of what they
// sent, and their round trips had risen, which means a queue on the path.
// Loss alone is not taken for that. A path can lose packets at random, and
// a lane that rides that out is doing what it should.
//
// It takes two such stretches in a row to bring the limit on. A connection
// whose congestion control backs off when it loses packets has done so by
// the second, and needs no help.
//
// From then on the session writes no faster than a rate, which starts at
// what the path has been delivering. What the tunnel offers beyond the rate
// waits in the lanes' queues, where a full queue drops, and the TCP inside
// the tunnel slows down for that as it would for a full link.
//
// The rate then follows the path, and it has to do so smoothly: every time
// it falls, the lanes' queues fill and drop, and a TCP connection that is
// made to back off every second never gets back to what the path carries.
// So while the session is held by the rate it moves a little each stretch.
// With no queue on the path there is room, and it grows: by limitRoom while
// it is well under what the path has delivered lately, by limitStep
// otherwise. With a queue on the path it settles where the path drops about
// limitAim of what it is sent: it creeps up while less is lost and comes
// down by as much as more is. Only when the path is found overloaded again
// does it jump, back to what is being delivered. The limit goes when the
// session has not needed half of it for a while.
//
// All of this takes the lanes to share one path, where what the session
// delivers when it is overloaded is what the path carries. A path that
// limits each connection separately is different: a lane given more than
// its connection may carry loses the excess while another has room, so what
// the session delivers is less than it could be, and holding the session to
// that makes it deliver less again. If the rate falls under limitFall of
// the highest it has been, that is what is happening, and the limit stands
// down for a while, longer each time, and leaves the lanes to themselves
// as they were without it.

const (
	// A stretch is two of the lanes' round trips, within these bounds:
	// retransmissions follow the losses they repair by a round trip.
	limitSpanMin = 100 * time.Millisecond
	limitSpanMax = time.Second
	// limitLoss is the share of what the lanes sent in a stretch that
	// they had to send again for the path to count as dropping what it is
	// offered, if it is also queueing. BBR's own start-up overruns a queue
	// by far more than this; random loss this heavy with a queue on the
	// path is rare, and a sender that slows down for it does no wrong.
	limitLoss = 0.05
	// limitMinSent is the least the lanes must have sent in a stretch for
	// it to say anything.
	limitMinSent = 64 << 10
	// limitEase is the share of what the path delivers that the session
	// is held to when the path is found overloaded: a little under, so
	// that the queue on the path drains. What the path delivers is taken
	// as the most it delivered in any of the last limitPeak stretches: the
	// stretch that shows the overload is often a poor one, with a burst of
	// loss in it, and a rate set too low takes many stretches to grow
	// back, where one set too high is put right by the next.
	limitEase = 0.98
	limitPeak = 5
	// limitStrikes is how many stretches in a row must show the path
	// overloaded before the limit comes on.
	limitStrikes = 2
	// The limit stands down once its rate has fallen under limitFall of
	// the highest it has been since it came on: for limitRest the first
	// time, and twice as long each time after, up to limitRestMax. A path
	// that limits each connection goes on doing so.
	limitFall    = 0.7
	limitRest    = 30 * time.Second
	limitRestMax = 10 * time.Minute
	// With no queue on the path, the rate grows by limitRoom in a stretch
	// in which the session was held by it and the rate is under limitNear
	// of what the path has delivered lately, and by limitStep otherwise.
	limitRoom = 1.05
	limitStep = 1.02
	limitNear = 0.9
	// With a queue on the path, the rate moves by the difference between
	// limitAim and the share the lanes had to send again, and by no more
	// than limitCreep up or limitGive down in one stretch.
	limitAim   = 0.02
	limitCreep = 0.01
	limitGive  = 0.01
	// limitBound is the share of the rate the session must be writing at
	// to count as held by it.
	limitBound = 0.9
	// The limit goes after limitSlackSpans stretches in a row in which
	// the session wrote at under limitSlack of it: what the path carried
	// then says little about what it carries now.
	limitSlack      = 0.5
	limitSlackSpans = 10
	// limitFloor is the least the rate is ever set to, in bytes a second.
	limitFloor = 32 << 10
	// limitBurst is how far ahead of the rate the session may write: this
	// long at the rate, and at least one full record.
	limitBurst = 5 * time.Millisecond
)

// Limiter limits what a session sends across its lanes to what its path
// delivers, once the path has shown that it is being offered more. The zero
// value is ready to use. It is safe for concurrent use.
type Limiter struct {
	// Log, if set, is told when the limit comes on, eases, stands down
	// and goes off.
	Log func(msg string, args ...any)

	on    atomic.Bool // a rate is in force
	mu    sync.Mutex
	start time.Time     // when the stretch being measured began
	span  time.Duration // how long it runs
	// What the lanes reported in the stretch, in bytes: sent, sent again,
	// delivered, and the part of sent that came from lanes with a queue on
	// their path. wrote is what the lanes wrote under the limit.
	sent, resent, delivered, queued, wrote float64
	rtt                                    time.Duration // the longest round trip reported
	rate                                   float64       // bytes a second; zero when there is no limit
	peaks                                  [limitPeak]float64
	nextPeak                               int
	until                                  time.Time // when what has been written will have gone at rate
	slack                                  int       // stretches in a row the session did not need the limit
	strikes                                int       // stretches in a row, with no limit, that showed the path overloaded
	best                                   float64   // the highest the rate has been since the limit came on
	rest                                   time.Time // until when the limit stands down
	rested                                 int       // how many times it has
	stats                                  LimiterStats
}

// LimiterStats says what a Limiter has done.
type LimiterStats struct {
	Rate      float64 // the limit now, in bytes a second; zero if there is none
	On        uint64  // how many times the limit came on
	Eased     uint64  // how many times it came down to what the path delivered
	StoodDown uint64  // how many times it gave up on a path it did not fit
}

var _ lane.Limiter = (*Limiter)(nil)

// Report takes what a lane's connection has done since the lane last
// reported.
func (g *Limiter) Report(now time.Time, p lane.Progress) {
	g.mu.Lock()
	g.sent += float64(p.Sent)
	g.resent += float64(p.Resent)
	g.delivered += float64(p.Delivered)
	if p.Queued {
		g.queued += float64(p.Sent)
	}
	g.rtt = max(g.rtt, p.RTT)
	g.roll(now)
	g.mu.Unlock()
}

// Wait returns how long a lane must hold its next DATA.
func (g *Limiter) Wait(now time.Time) time.Duration {
	if !g.on.Load() {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.roll(now) // an idle session's lanes report nothing
	if g.rate == 0 {
		return 0
	}
	burst := max(limitBurst, time.Duration(float64(shape.MaxRecord)/g.rate*float64(time.Second)))
	return max(g.until.Sub(now)-burst, 0)
}

// Wrote notes that a lane wrote n bytes of records carrying DATA.
func (g *Limiter) Wrote(now time.Time, n int) {
	if !g.on.Load() {
		return
	}
	g.mu.Lock()
	if g.rate > 0 {
		g.wrote += float64(n)
		if g.until.Before(now) {
			g.until = now
		}
		g.until = g.until.Add(time.Duration(float64(n) / g.rate * float64(time.Second)))
	}
	g.mu.Unlock()
}

// Stats returns what the limiter has done.
func (g *Limiter) Stats() LimiterStats {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.stats
	s.Rate = g.rate
	return s
}

// roll ends the stretch being measured, if it has run its length, and
// decides the rate for the next. Called with mu held.
func (g *Limiter) roll(now time.Time) {
	if g.start.IsZero() {
		g.start, g.span = now, limitSpanMin
		return
	}
	elapsed := now.Sub(g.start)
	if elapsed < g.span {
		return
	}
	secs := elapsed.Seconds()
	queued := g.queued*2 >= g.sent
	overloaded := g.sent >= limitMinSent && g.resent > limitLoss*g.sent && queued
	delivered := g.delivered / secs
	if g.sent >= limitMinSent {
		g.peaks[g.nextPeak%limitPeak] = delivered
		g.nextPeak++
	}
	// What the path carries: the most it has delivered lately, or what
	// was sent in this stretch and did not need sending again, which
	// counts what is still on its way.
	carried := max((g.sent-g.resent)/secs, 0)
	for _, p := range g.peaks {
		carried = max(carried, p)
	}
	switch {
	case g.rate == 0 && (!overloaded || now.Before(g.rest)):
		g.strikes = 0
	case g.rate == 0:
		if g.strikes++; g.strikes >= limitStrikes {
			g.set(max(carried*limitEase, limitFloor), now)
			g.best = g.rate
			g.stats.On++
			g.log("send limit on", delivered)
		}
	case g.wrote/secs < limitSlack*g.rate:
		if g.slack += max(int(elapsed/g.span), 1); g.slack >= limitSlackSpans {
			g.log("send limit off", delivered)
			g.set(0, now)
		}
	default:
		g.slack = 0
		switch {
		case overloaded:
			g.set(max(carried*limitEase, limitFloor), now)
			g.stats.Eased++
			g.log("send limit eased", delivered)
			if g.rate < limitFall*g.best {
				// Holding the session to what it delivers has only
				// made it deliver less: not a path the lanes share.
				g.log("send limit stands down", delivered)
				g.set(0, now)
				g.rest = now.Add(min(limitRest<<min(g.rested, 10), limitRestMax))
				g.rested++
				g.stats.StoodDown++
			}
		case g.wrote/secs < limitBound*g.rate:
			// The session isn't held by the limit: nothing to learn.
		case !queued && g.rate < limitNear*carried:
			g.rate *= limitRoom
		case !queued:
			g.rate *= limitStep
		default:
			lost := 0.0
			if g.sent >= limitMinSent {
				lost = g.resent / g.sent
			}
			g.rate *= 1 + min(max(limitAim-lost, -limitGive), limitCreep)
		}
	}
	g.best = max(g.best, g.rate)
	g.span = min(max(2*g.rtt, limitSpanMin), limitSpanMax)
	g.start = now
	g.sent, g.resent, g.delivered, g.queued, g.wrote, g.rtt = 0, 0, 0, 0, 0, 0
}

// set changes the rate; zero takes the limit away.
func (g *Limiter) set(rate float64, now time.Time) {
	g.rate, g.until, g.slack, g.strikes = rate, now, 0, 0
	if rate == 0 {
		g.best = 0
	}
	g.on.Store(rate > 0)
}

func (g *Limiter) log(msg string, delivered float64) {
	if g.Log != nil {
		loss := 0.0
		if g.sent > 0 {
			loss = g.resent / g.sent
		}
		g.Log(msg, "rate_mbit", g.rate*8/1e6, "delivered_mbit", delivered*8/1e6, "resent_share", loss)
	}
}
