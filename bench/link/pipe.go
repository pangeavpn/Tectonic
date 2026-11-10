package link

import (
	"container/heap"
	"math/rand/v2"
	"time"
)

// direction is one way of the link. Everything except the rng and wake
// channel is guarded by Link.mu.
//
// A packet enters through send, which decides loss, asks the flow's shaper
// for a release time and, once released, computes when the bottleneck
// finishes serializing it. Packets the shaper holds back wait in a heap
// ordered by release time; packets past the bottleneck wait in a FIFO
// ordered by delivery time. The run goroutine moves packets out of the heap
// as they are released and delivers FIFO entries when they fall due.
type direction struct {
	l   *Link
	idx int
	to  *endpoint
	rng *rand.Rand

	geBad bool // Gilbert–Elliott state

	seq       uint64      // arrival counter, breaks release-time ties
	shaped    pendingHeap // held by a per-flow shaper
	busyUntil time.Time   // when the bottleneck finishes its backlog
	wire      []inflight  // past the bottleneck, nondecreasing at
	stats     DirStats

	wake chan struct{}
}

type pending struct {
	at   time.Time // release time from the per-flow shaper
	seq  uint64
	pkt  []byte
	meta meta
	flow *flowState
}

type inflight struct {
	at   time.Time // delivery time at the far end
	pkt  []byte
	meta meta
	flow *flowState
}

func newDirection(l *Link, idx int, to *endpoint) *direction {
	return &direction{
		l:    l,
		idx:  idx,
		to:   to,
		rng:  rand.New(rand.NewPCG(uint64(l.cfg.Seed), uint64(idx)+0x7465637465)),
		wake: make(chan struct{}, 1),
	}
}

// send runs on the sending stack's goroutine for every outbound packet.
func (d *direction) send(pkt []byte) {
	l := d.l
	m := parse(pkt)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	now := time.Now()
	f := l.flowLocked(m, d.idx)
	if f != nil && f.blackholed {
		d.stats.DroppedBlackhole++
		return
	}
	if d.lose() {
		d.stats.DroppedLoss++
		return
	}

	// Push everything the shapers have released by now through the
	// bottleneck first, so it sees packets in release order.
	d.advanceLocked(now)

	release := now
	if l.cfg.PerConnRate > 0 && f != nil {
		r, ok := f.shapers[d.idx].admit(now, len(pkt), l.cfg.PerConnRate, l.capBurst, l.capQueue)
		if !ok {
			d.stats.DroppedCap++
			return
		}
		release = r
	}
	if release.After(now) {
		d.seq++
		heap.Push(&d.shaped, pending{at: release, seq: d.seq, pkt: pkt, meta: m, flow: f})
	} else {
		d.bottleneckLocked(now, pkt, m, f)
	}
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// lose decides random and burst loss for one packet.
func (d *direction) lose() bool {
	cfg := &d.l.cfg
	lost := false
	if b := cfg.Burst; b != nil {
		if d.geBad {
			if d.rng.Float64() < b.PBadToGood {
				d.geBad = false
			}
		} else if d.rng.Float64() < b.PGoodToBad {
			d.geBad = true
		}
		if d.geBad && d.rng.Float64() < b.LossBad {
			lost = true
		}
	}
	if cfg.Loss > 0 && d.rng.Float64() < cfg.Loss {
		lost = true
	}
	return lost
}

// advanceLocked moves packets released by now from the shaper heap into the
// bottleneck, using each packet's release time as its arrival time.
func (d *direction) advanceLocked(now time.Time) {
	for len(d.shaped) > 0 && !d.shaped[0].at.After(now) {
		p := heap.Pop(&d.shaped).(pending)
		d.bottleneckLocked(p.at, p.pkt, p.meta, p.flow)
	}
}

// bottleneckLocked queues a packet that reaches the bottleneck at t.
func (d *direction) bottleneckLocked(t time.Time, pkt []byte, m meta, f *flowState) {
	l := d.l
	done := t
	if bw := l.cfg.Bandwidth; bw > 0 {
		start := t
		if d.busyUntil.After(t) {
			// Bytes still waiting to be serialized ahead of this packet.
			backlog := int(d.busyUntil.Sub(t).Seconds() * float64(bw) / 8)
			if backlog+len(pkt) > l.queueBytes {
				d.stats.DroppedQueue++
				return
			}
			start = d.busyUntil
		}
		done = start.Add(txTime(len(pkt), bw))
		d.busyUntil = done
	}
	d.wire = append(d.wire, inflight{at: done.Add(l.cfg.RTT / 2), pkt: pkt, meta: m, flow: f})
}

// txTime is how long n bytes take to serialize at bw bits per second.
func txTime(n int, bw int64) time.Duration {
	return time.Duration(float64(n) * 8 * float64(time.Second) / float64(bw))
}

// run delivers packets when they fall due, until the link closes.
func (d *direction) run() {
	l := d.l
	defer l.wg.Done()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()

	var due []inflight
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return
		}
		now := time.Now()
		d.advanceLocked(now)
		n := 0
		for n < len(d.wire) && !d.wire[n].at.After(now) {
			n++
		}
		due = append(due[:0], d.wire[:n]...)
		clear(d.wire[:n])
		d.wire = d.wire[n:]
		kept := 0
		for _, p := range due {
			if p.flow != nil && p.flow.blackholed {
				d.stats.DroppedBlackhole++
				continue
			}
			d.stats.Packets++
			d.stats.Bytes += uint64(len(p.pkt))
			if p.flow != nil && p.meta.isTCP {
				p.flow.tcp[d.idx].observe(p.meta)
			}
			due[kept] = p
			kept++
		}
		clear(due[kept:])
		due = due[:kept]
		var next time.Time
		if len(d.wire) > 0 {
			next = d.wire[0].at
		}
		if len(d.shaped) > 0 && (next.IsZero() || d.shaped[0].at.Before(next)) {
			next = d.shaped[0].at
		}
		l.mu.Unlock()

		// Deliver outside the lock: the receiving stack may answer
		// synchronously, which re-enters send on the other direction.
		for _, p := range due {
			d.to.deliver(p.pkt)
		}
		clear(due)

		if next.IsZero() {
			select {
			case <-d.wake:
			case <-l.done:
				return
			}
			continue
		}
		wait := time.Until(next)
		if wait <= 0 {
			continue
		}
		timer.Reset(wait)
		select {
		case <-timer.C:
		case <-d.wake:
			timer.Stop()
		case <-l.done:
			return
		}
	}
}

// shaper is a token-bucket rate limiter in GCRA form. tat is the theoretical
// arrival time: when the next packet would leave if the flow sent at exactly
// the capped rate. A packet may leave up to the bucket depth ahead of tat.
type shaper struct {
	tat time.Time
}

// admit returns when a packet of size bytes arriving at now may leave, or
// false if the shaper's queue is full and the packet is dropped.
func (s *shaper) admit(now time.Time, size int, rate int64, burst, limit int) (time.Time, bool) {
	tat := s.tat
	if tat.Before(now) {
		tat = now
	}
	release := tat.Add(-txTime(burst, rate))
	if release.Before(now) {
		release = now
	} else if backlog := int(release.Sub(now).Seconds() * float64(rate) / 8); backlog+size > limit {
		return time.Time{}, false
	}
	s.tat = tat.Add(txTime(size, rate))
	return release, true
}

// pendingHeap is a min-heap of packets ordered by release time, then
// arrival order.
type pendingHeap []pending

func (h pendingHeap) Len() int { return len(h) }
func (h pendingHeap) Less(i, j int) bool {
	if !h[i].at.Equal(h[j].at) {
		return h[i].at.Before(h[j].at)
	}
	return h[i].seq < h[j].seq
}
func (h pendingHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *pendingHeap) Push(x any)   { *h = append(*h, x.(pending)) }
func (h *pendingHeap) Pop() any {
	old := *h
	p := old[len(old)-1]
	old[len(old)-1] = pending{}
	*h = old[:len(old)-1]
	return p
}
