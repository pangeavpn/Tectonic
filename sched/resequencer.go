package sched

import (
	"encoding/binary"
	"math"
	"sync"
	"time"
)

// Lanes are separate TCP connections, so packets spread across them arrive
// out of order, and a TCP connection inside the tunnel reads a packet that
// turns up several places late as a lost one: it retransmits and slows down
// for a loss that never happened. The receiver therefore merges the lanes
// back into one ordered stream before handing packets on (design §7).
//
// No sequence number is added for this. WireGuard's data header is in the
// clear: message type 4, the receiver's 32-bit key index, then a 64-bit
// counter that rises by one for every packet sent under that key.
//
// The merge rarely has to guess, because every lane is itself an ordered,
// reliable stream. The sender puts packets on a lane in counter order, so a
// lane that has delivered counter c will never deliver anything below c. A
// missing packet is therefore known to be lost, not late, the moment every
// lane has delivered something beyond it, and the packets behind it go on
// at once. Until then it is still on its way on some lane, and the packets
// behind it wait. A timer bounds that wait, for the two cases the lanes
// cannot settle: a lane that has stalled (it is retransmitting, or dead but
// not yet closed), and a lane that has carried nothing recent to judge by.

const (
	// HoldMin and HoldMax bound how long a packet waits for the ones before
	// it when the lanes cannot say whether those are lost. Within the
	// bounds the wait is one and a half times the receiving lane's round
	// trip: long enough for a lane that lost a segment to retransmit it,
	// so the TCP inside the tunnel sees a delay rather than a loss. HoldMax
	// keeps that delay under the 200 ms that TCP adds to its round trip
	// before it takes a packet for lost.
	HoldMin = 20 * time.Millisecond
	HoldMax = 150 * time.Millisecond

	// maxHeld is the most packets waiting at once. Past it the oldest gap
	// is given up on early.
	maxHeld = 4096
	// maxFlows is how many WireGuard keys are tracked at once: during a
	// rekey the old and new keys overlap.
	maxFlows = 8
	// startWindow: a key seen for the first time with a counter below this
	// is taken to be new, and its packets wait for counter 0.
	startWindow = 64
	// maxJump is a counter so far ahead that the flow is restarted there
	// rather than waited for.
	maxJump = 1 << 16

	wgTransport    = 4  // WireGuard message type for data
	wgTransportMin = 32 // header and authentication tag, no payload
)

// HoldFor returns how long a packet arriving on a lane with this round
// trip may wait for the packets before it.
func HoldFor(rtt time.Duration) time.Duration {
	return min(max(rtt+rtt/2, HoldMin), HoldMax)
}

// Resequencer merges the WireGuard data packets arriving on several lanes
// back into counter order. Each lane pushes through its own Source. Small
// packets (DupMaxSize bytes or less: ACKs inside the tunnel, keepalives)
// and packets that are not WireGuard data are handed on at once, and so is
// a packet that turns up after it was given up on.
//
// It is safe for concurrent use. deliver is called with the Resequencer's
// lock held, one packet at a time, and must not call back into it.
type Resequencer struct {
	deliver func(pkt []byte)

	mu      sync.Mutex
	flows   [maxFlows]reflow
	sources []*Source
	clock   uint64 // orders flows by last use
	held    int
	timer   *time.Timer
	timerAt time.Time
	closed  bool
	stats   ResequencerStats
	bufs    sync.Pool
}

// Source is one lane's way into a Resequencer. The packets pushed through
// a Source must be in the order the lane carried them.
type Source struct {
	r      *Resequencer
	closed bool
	// past[i] is how far this lane has got in flow i: it will deliver no
	// held-back packet with a counter below past[i].next.
	past [maxFlows]horizon
}

type horizon struct {
	next uint64
	ok   bool // the lane has carried a packet of this flow
}

type reflow struct {
	used  bool
	index uint32
	next  uint64 // the counter expected next
	seen  uint64
	// q[head:] is ascending by counter, all above next.
	q    []heldPkt
	head int
}

type heldPkt struct {
	ctr uint64
	due time.Time
	// buf is nil for a small packet that was handed on at once and is kept
	// only to mark its counter as seen.
	buf []byte
}

// ResequencerStats counts what the Resequencer has done.
type ResequencerStats struct {
	Held    uint64 // packets that arrived early and waited for earlier ones
	Skipped uint64 // missing packets given up on: lost, or later than the hold
	Late    uint64 // packets that arrived after being given up on, and duplicates
}

// NewResequencer returns a Resequencer that hands packets to deliver.
func NewResequencer(deliver func(pkt []byte)) *Resequencer {
	r := &Resequencer{deliver: deliver}
	r.bufs.New = func() any { return make([]byte, 0, 2048) }
	return r
}

// Source adds a lane. Close it when the lane will deliver nothing more;
// until then the packets other lanes deliver ahead of a gap wait for it.
func (r *Resequencer) Source() *Source {
	s := &Source{r: r}
	r.mu.Lock()
	if r.closed {
		s.closed = true
	} else {
		r.sources = append(r.sources, s)
	}
	r.mu.Unlock()
	return s
}

// Push takes one packet from the lane, whose round trip is rtt. pkt is only
// read during the call.
func (s *Source) Push(pkt []byte, rtt time.Duration) {
	r := s.r
	idx, ctr, ok := transportHeader(pkt)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if !ok {
		r.deliver(pkt)
		return
	}
	fi := r.flow(idx, ctr)
	f := &r.flows[fi]
	// Small packets go out of turn (the scheduler may also duplicate them
	// onto a second lane), so they say nothing about how far a lane has got.
	ordered := len(pkt) > DupMaxSize
	if ordered && !s.closed {
		if h := &s.past[fi]; !h.ok || ctr >= h.next {
			h.next, h.ok = ctr+1, true
		}
	}
	switch {
	case ctr < f.next:
		r.stats.Late++
		r.deliver(pkt)
	case ctr == f.next:
		r.deliver(pkt)
		f.next++
		r.drain(f)
	case ctr-f.next > maxJump:
		r.flush(f)
		r.deliver(pkt)
		f.next = ctr + 1
	default:
		i, dup := f.find(ctr)
		if dup {
			r.stats.Late++
			break
		}
		h := heldPkt{ctr: ctr, due: time.Now().Add(HoldFor(rtt))}
		if ordered {
			h.buf = append(r.bufs.Get().([]byte)[:0], pkt...)
			r.stats.Held++
		} else {
			r.deliver(pkt)
		}
		f.insert(i, h)
		r.held++
		for r.held > maxHeld && f.len() > 0 {
			r.skipTo(f, 0)
			r.drain(f)
		}
		if f.len() > 0 {
			r.schedule(h.due)
		}
	}
	if ordered {
		r.settle(fi)
	}
}

// Close tells the Resequencer the lane will deliver nothing more, so no
// packet waits for it again.
func (s *Source) Close() {
	r := s.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for i, o := range r.sources {
		if o == s {
			r.sources = append(r.sources[:i], r.sources[i+1:]...)
			break
		}
	}
	if r.closed {
		return
	}
	for fi := range r.flows {
		r.settle(fi)
	}
}

// Stats returns the Resequencer's counters.
func (r *Resequencer) Stats() ResequencerStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

// Close drops anything held and stops delivering.
func (r *Resequencer) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.timer != nil {
		r.timer.Stop()
	}
	for i := range r.flows {
		r.flows[i] = reflow{}
	}
	for _, s := range r.sources {
		s.closed = true
	}
	r.sources = nil
	r.held = 0
}

// transportHeader reads a WireGuard data packet's key index and counter.
func transportHeader(pkt []byte) (uint32, uint64, bool) {
	if len(pkt) < wgTransportMin || binary.LittleEndian.Uint32(pkt) != wgTransport {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint32(pkt[4:]), binary.LittleEndian.Uint64(pkt[8:]), true
}

// flow finds the slot of the flow for a key index, starting one if needed.
func (r *Resequencer) flow(idx uint32, ctr uint64) int {
	r.clock++
	free, oldest := -1, -1
	for i := range r.flows {
		f := &r.flows[i]
		switch {
		case f.used && f.index == idx:
			f.seen = r.clock
			return i
		case !f.used:
			if free < 0 {
				free = i
			}
		case oldest < 0 || f.seen < r.flows[oldest].seen:
			oldest = i
		}
	}
	i := free
	if i < 0 {
		i = oldest
		r.flush(&r.flows[i])
	}
	f := &r.flows[i]
	*f = reflow{used: true, index: idx, seen: r.clock, q: f.q[:0]}
	if ctr >= startWindow {
		f.next = ctr
	}
	for _, s := range r.sources {
		s.past[i] = horizon{}
	}
	return i
}

// settle gives up on the gaps in a flow that no lane can still fill: every
// lane has already delivered something beyond them.
func (r *Resequencer) settle(fi int) {
	f := &r.flows[fi]
	for f.used && f.len() > 0 {
		// The lowest counter any lane might still deliver.
		low := uint64(math.MaxUint64)
		for _, s := range r.sources {
			h := s.past[fi]
			if !h.ok {
				return // a lane that has shown nothing yet could hold anything
			}
			low = min(low, h.next)
		}
		if low <= f.next {
			return
		}
		to := min(low, f.q[f.head].ctr)
		r.stats.Skipped += to - f.next
		f.next = to
		if to != f.q[f.head].ctr {
			return
		}
		r.drain(f)
	}
}

func (f *reflow) len() int { return len(f.q) - f.head }

// find returns where ctr belongs in the flow's queue, and whether it is
// already there. Packets mostly arrive in order, so it searches from the
// end.
func (f *reflow) find(ctr uint64) (int, bool) {
	i := len(f.q)
	for i > f.head && f.q[i-1].ctr >= ctr {
		if f.q[i-1].ctr == ctr {
			return i - 1, true
		}
		i--
	}
	return i, false
}

func (f *reflow) insert(i int, h heldPkt) {
	f.q = append(f.q, heldPkt{})
	copy(f.q[i+1:], f.q[i:])
	f.q[i] = h
}

// release hands on a held packet, if it wasn't handed on already.
func (r *Resequencer) release(h heldPkt) {
	if h.buf != nil {
		r.deliver(h.buf)
		r.bufs.Put(h.buf[:0])
	}
}

// drain hands on the packets that are now in order.
func (r *Resequencer) drain(f *reflow) {
	k := 0
	for f.head+k < len(f.q) && f.q[f.head+k].ctr == f.next {
		r.release(f.q[f.head+k])
		f.next++
		k++
	}
	r.dropFront(f, k)
}

// skipTo gives up on every gap before the flow's n-th waiting packet and
// hands on the packets up to and including it.
func (r *Resequencer) skipTo(f *reflow, n int) {
	for k := 0; k <= n; k++ {
		h := f.q[f.head+k]
		r.stats.Skipped += h.ctr - f.next
		r.release(h)
		f.next = h.ctr + 1
	}
	r.dropFront(f, n+1)
}

// flush hands on everything the flow holds, giving up on its gaps.
func (r *Resequencer) flush(f *reflow) {
	if f.len() > 0 {
		r.skipTo(f, f.len()-1)
	}
}

func (r *Resequencer) dropFront(f *reflow, k int) {
	if k == 0 {
		return
	}
	clear(f.q[f.head : f.head+k])
	f.head += k
	r.held -= k
	switch {
	case f.head == len(f.q):
		f.q, f.head = f.q[:0], 0
	case f.head >= 256 && f.head >= len(f.q)/2:
		n := copy(f.q, f.q[f.head:])
		clear(f.q[n:])
		f.q, f.head = f.q[:n], 0
	}
}

// schedule makes sure the timer fires by due.
func (r *Resequencer) schedule(due time.Time) {
	if !r.timerAt.IsZero() && !due.Before(r.timerAt) {
		return
	}
	r.timerAt = due
	d := time.Until(due)
	if r.timer == nil {
		r.timer = time.AfterFunc(d, r.expire)
	} else {
		r.timer.Reset(d)
	}
}

// expire hands on every packet whose hold has run out, with the packets
// before it, and gives up on the gaps between them.
func (r *Resequencer) expire() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.timerAt = time.Time{}
	if r.closed {
		return
	}
	now := time.Now()
	var next time.Time
	for i := range r.flows {
		f := &r.flows[i]
		if !f.used || f.len() == 0 {
			continue
		}
		last := -1
		for k, h := range f.q[f.head:] {
			if !h.due.After(now) {
				last = k
			}
		}
		if last >= 0 {
			r.skipTo(f, last)
			r.drain(f)
		}
		for _, h := range f.q[f.head:] {
			if next.IsZero() || h.due.Before(next) {
				next = h.due
			}
		}
	}
	if !next.IsZero() {
		r.schedule(next)
	}
}
