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

	sent       atomic.Uint64
	dropped    atomic.Uint64
	duplicated atomic.Uint64
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
func (s *Scheduler) Send(pkt []byte) bool {
	p := s.lanes.Load()
	if p == nil || len(*p) == 0 {
		return false
	}
	lanes := *p
	n := wire.HeaderLen + len(pkt)

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
		return false
	}
	s.sent.Add(1)
	s.earn(n)

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
}

// Stats returns the scheduler's counters.
func (s *Scheduler) Stats() SchedulerStats {
	return SchedulerStats{Sent: s.sent.Load(), Dropped: s.dropped.Load(), Duplicated: s.duplicated.Load()}
}
