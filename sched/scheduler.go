// Package sched spreads WireGuard datagrams across lanes (design §7).
//
// The Scheduler, used by both client and server, sends each packet on the
// most preferred lane that would deliver it about as early as any other,
// and duplicates small urgent packets while a lane is retransmitting. The
// Resequencer, also used by both, merges the packets arriving on the lanes
// back into order. The Pool, used by the client, owns the lanes: it opens
// and replaces them on a browser-like schedule, grows the pool while
// per-connection throttling makes extra lanes pay off, shrinks it when the
// tunnel goes idle, and rejoins the session after a network change.
package sched

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/pangeavpn/tectonic/wire"
)

// Lane is what the scheduler needs from a lane. *lane.Lane implements it.
type Lane interface {
	// Send queues a datagram, copying it, and reports whether the lane
	// took it.
	Send(pkt []byte) bool
	// ETA estimates when n more queued bytes would be delivered.
	ETA(n int) time.Duration
	// Retransmitting reports whether the lane is recovering from loss.
	Retransmitting() bool
	// RTT is the smoothed round-trip estimate.
	RTT() time.Duration
	// Lost tells the peer that datagrams were dropped and will never be
	// sent, and reports whether the lane took the notice.
	Lost(wire.Lost) bool
}

const (
	// DupMaxSize is the largest packet that is duplicated: WireGuard
	// handshakes and keepalives, and most TCP ACKs inside the tunnel.
	DupMaxSize = 128
	// DupShare caps duplicates at 5% of the bytes sent.
	DupShare = 0.05
	// dupBurst is the most duplication budget that can be saved up.
	dupBurst = 16 << 10
	maxLanes = 16

	// SpillMin and SpillMax bound how much later than the best lane's a
	// preferred lane's estimate may be before traffic spills past it.
	// Within them the margin is a sixteenth of the preferred lane's srtt.
	// The receiver delivers in order, so whatever the margin is, the whole
	// stream arrives that much later while traffic is spilling.
	SpillMin = time.Millisecond
	SpillMax = 12 * time.Millisecond

	// maxLostPending is how many separate runs of dropped datagrams wait
	// to be reported at once. Drops come in runs, so it is rarely reached;
	// past it the oldest goes unreported, and the receiver waits out its
	// hold for those as it would have for all of them.
	maxLostPending = 16
	// maxLostRun is the longest run one notice reports.
	maxLostRun = 1 << 16
)

// SpillAfter returns the margin for a lane with this srtt.
func SpillAfter(srtt time.Duration) time.Duration {
	return min(max(srtt/16, SpillMin), SpillMax)
}

// Scheduler picks a lane for every outgoing datagram. It is safe for
// concurrent use; Send is lock-free apart from the duplication budget.
type Scheduler struct {
	lanes atomic.Pointer[[]Lane]

	mu     sync.Mutex
	tokens float64
	// flows is how far each WireGuard key's counter has got, and lost the
	// datagrams found missing or dropped that the peer has yet to be told
	// about (see report).
	flows   [maxFlows]sendFlow
	clock   uint64
	lost    []wire.Lost
	pending atomic.Bool // lost is not empty

	sent       atomic.Uint64
	dropped    atomic.Uint64
	duplicated atomic.Uint64
	reported   atomic.Uint64
}

// sendFlow is one WireGuard key as the sender sees it.
type sendFlow struct {
	used  bool
	index uint32
	next  uint64 // the counter expected next
	seen  uint64 // orders flows by last use
}

// SetLanes replaces the set of lanes packets may be sent on, most preferred
// first. Client and server both put the newest lane first, so a lane takes
// over the traffic as soon as it joins and its predecessor only carries
// what the newcomer cannot yet.
func (s *Scheduler) SetLanes(lanes []Lane) {
	cp := append([]Lane(nil), lanes...)
	s.lanes.Store(&cp)
}

// Len returns how many lanes the scheduler is using.
func (s *Scheduler) Len() int {
	if p := s.lanes.Load(); p != nil {
		return len(*p)
	}
	return 0
}

// Send sends pkt on a lane chosen by delivery estimate:
//
//	eta(lane) = queued_bytes(lane) / rate(lane) + srtt(lane) / 2
//
// It takes the most preferred lane whose estimate is within SpillAfter of
// the earliest. Traffic that one lane can carry therefore stays on one
// lane, in order. Once that lane falls behind, the overflow spills to the
// next, and each packet still goes where it will arrive about as early as
// anywhere, so the lanes deliver nearly in step and the receiver's
// Resequencer has little to wait for. If the chosen lane's queue is full
// it tries the others, earliest first. While any lane is retransmitting, a
// packet of DupMaxSize bytes or less is also copied onto the next-best
// lane, within the DupShare budget; WireGuard's anti-replay window drops
// whichever copy arrives second. Send reports whether any lane took the
// packet.
//
// The receiver puts the lanes' packets back in WireGuard's order and waits
// for one that is missing, since on a lane it can only be late. A packet
// that no lane took, or that never reached the scheduler, is not late: it
// is gone, and only this end knows. So the scheduler follows WireGuard's
// counters as the receiver does, and reports what it finds missing or has
// to drop on the lane that takes the next packet (a LOST frame).
func (s *Scheduler) Send(pkt []byte) bool {
	p := s.lanes.Load()
	if p == nil || len(*p) == 0 {
		return false
	}
	lanes := *p
	n := wire.HeaderLen + len(pkt)
	idx, ctr, counted := transportHeader(pkt)
	if counted {
		s.follow(idx, ctr)
	}

	// order lists the lanes by estimate, earliest first; lanes with equal
	// estimates keep their order of preference.
	var order [maxLanes]int
	var eta, sorted [maxLanes]time.Duration
	k := min(len(lanes), maxLanes)
	for i := range k {
		e := lanes[i].ETA(n)
		eta[i] = e
		j := i
		for j > 0 && sorted[j-1] > e {
			sorted[j], order[j] = sorted[j-1], order[j-1]
			j--
		}
		sorted[j], order[j] = e, i
	}

	used, tried := -1, -1
	for i := range k {
		if eta[i]-sorted[0] <= SpillAfter(lanes[i].RTT()) {
			tried = i
			if lanes[i].Send(pkt) {
				used = i
			}
			break
		}
	}
	if used < 0 {
		for _, i := range order[:k] {
			if i != tried && lanes[i].Send(pkt) {
				used = i
				break
			}
		}
	}
	if used < 0 {
		s.dropped.Add(1)
		if counted {
			s.mu.Lock()
			s.missing(idx, ctr, 1)
			s.mu.Unlock()
		}
		return false
	}
	s.sent.Add(1)
	s.earn(n)
	if s.pending.Load() {
		s.report(lanes[used])
	}

	if len(pkt) <= DupMaxSize && k > 1 && anyRetransmitting(lanes) {
		for _, i := range order[:k] {
			if i == used {
				continue
			}
			// The next-best lane other than the one just used.
			if s.spend(n) && lanes[i].Send(pkt) {
				s.duplicated.Add(1)
			}
			break
		}
	}
	return true
}

// follow notes that the datagram with this key index and counter has
// reached the scheduler. Counters rise by one, so any it skipped never
// will.
func (s *Scheduler) follow(idx uint32, ctr uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clock++
	free, oldest := -1, -1
	for i := range s.flows {
		f := &s.flows[i]
		switch {
		case f.used && f.index == idx:
			f.seen = s.clock
			if ctr < f.next {
				return // out of turn; it was reported missing, and goes anyway
			}
			if gap := ctr - f.next; gap > 0 && gap <= maxJump {
				s.missing(idx, f.next, gap)
			}
			f.next = ctr + 1
			return
		case !f.used:
			if free < 0 {
				free = i
			}
		case oldest < 0 || f.seen < s.flows[oldest].seen:
			oldest = i
		}
	}
	i := free
	if i < 0 {
		i = oldest
	}
	s.flows[i] = sendFlow{used: true, index: idx, next: ctr + 1, seen: s.clock}
}

// missing queues a notice that n datagrams from ctr on will never be sent.
// Called with mu held.
func (s *Scheduler) missing(idx uint32, ctr, n uint64) {
	if k := len(s.lost); k > 0 {
		if l := &s.lost[k-1]; l.Index == idx && l.Counter+uint64(l.Count) == ctr && uint64(l.Count)+n <= maxLostRun {
			l.Count += uint32(n)
			return
		}
	}
	if len(s.lost) == maxLostPending {
		s.lost = s.lost[:copy(s.lost, s.lost[1:])]
	}
	s.lost = append(s.lost, wire.Lost{Index: idx, Counter: ctr, Count: uint32(min(n, maxLostRun))})
	s.pending.Store(true)
}

// report sends the queued notices on l, the lane that has just taken a
// packet. They arrive no later than the packet does, which is when the
// receiver would start to wait for what came before it.
func (s *Scheduler) report(l Lane) {
	s.mu.Lock()
	k := 0
	for k < len(s.lost) && l.Lost(s.lost[k]) {
		s.reported.Add(uint64(s.lost[k].Count))
		k++
	}
	s.lost = s.lost[:copy(s.lost, s.lost[k:])]
	s.pending.Store(len(s.lost) > 0)
	s.mu.Unlock()
}

func anyRetransmitting(lanes []Lane) bool {
	for _, l := range lanes {
		if l.Retransmitting() {
			return true
		}
	}
	return false
}

func (s *Scheduler) earn(n int) {
	s.mu.Lock()
	s.tokens = min(s.tokens+DupShare*float64(n), dupBurst)
	s.mu.Unlock()
}

func (s *Scheduler) spend(n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokens < float64(n) {
		return false
	}
	s.tokens -= float64(n)
	return true
}

// SchedulerStats counts what the scheduler has done.
type SchedulerStats struct {
	Sent       uint64 // packets sent on some lane
	Dropped    uint64 // packets no lane would take
	Duplicated uint64 // extra copies of small urgent packets
	// Reported is how many datagrams the peer was told not to wait for:
	// those dropped here, and those that never arrived from WireGuard.
	Reported uint64
}

// Stats returns the scheduler's counters.
func (s *Scheduler) Stats() SchedulerStats {
	return SchedulerStats{
		Sent: s.sent.Load(), Dropped: s.dropped.Load(), Duplicated: s.duplicated.Load(),
		Reported: s.reported.Load(),
	}
}
