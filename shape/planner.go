package shape

import (
	crand "crypto/rand"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/pangeavpn/tectonic/wire"
)

// Mode is the traffic state a record is planned for.
type Mode int

const (
	// Bulk packs frames into records of up to MaxRecord with no padding.
	Bulk Mode = iota
	// Interactive rounds the record up to the next bucket.
	Interactive
	// Idle pads a keepalive-only record to one of the idle sizes.
	Idle
)

func (m Mode) String() string {
	switch m {
	case Bulk:
		return "bulk"
	case Interactive:
		return "interactive"
	case Idle:
		return "idle"
	}
	return "unknown"
}

// Planner decides record sizes and idle timings for one profile. It is safe
// for concurrent use.
type Planner struct {
	p   *Profile
	mu  sync.Mutex
	rng *rand.Rand
}

// NewPlanner returns a planner for p, or for the default profile if p is nil.
func NewPlanner(p *Profile) *Planner {
	if p == nil {
		p = Default()
	}
	var seed [32]byte
	if _, err := crand.Read(seed[:]); err != nil {
		panic(err)
	}
	return &Planner{p: p, rng: rand.New(rand.NewChaCha8(seed))}
}

// Profile returns the planner's profile.
func (pl *Planner) Profile() *Profile { return pl.p }

// Mode picks the record mode for a lane that has queued bytes waiting to be
// sent. idle is whether the tunnel is idle and the record carries nothing but
// keepalives.
func (pl *Planner) Mode(queued int, idle bool) Mode {
	switch {
	case idle:
		return Idle
	case queued >= pl.p.BulkThreshold:
		return Bulk
	default:
		return Interactive
	}
}

// Padding returns how many bytes of PAD frames to add to a record that holds
// size bytes of frames. The result is always 0 or at least wire.HeaderLen.
func (pl *Planner) Padding(mode Mode, size int) int {
	switch mode {
	case Interactive:
		for _, b := range pl.p.Buckets {
			if gap := b - size; gap >= 0 && wire.CanPad(gap) {
				return gap
			}
		}
	case Idle:
		pl.mu.Lock()
		defer pl.mu.Unlock()
		// Draw among the idle sizes that fit, so absorbed keepalives don't
		// all come out the same size.
		var fit []int
		for _, s := range pl.p.IdleSizes {
			if gap := s - size; gap >= 0 && wire.CanPad(gap) {
				fit = append(fit, gap)
			}
		}
		if len(fit) > 0 {
			return fit[pl.rng.IntN(len(fit))]
		}
	}
	return 0
}

const (
	// splitCost is what one more record costs on the wire beyond the frames
	// in it: its TLS framing, and most of the time a TCP header, since a
	// record that ends before a segment is full sends that segment short.
	splitCost = 64
	// MaxSplit is the most frames Split weighs. More than that make a
	// record large enough that its padding is a small part of it.
	MaxSplit = 16
)

// Split reports how many of the frames waiting to be sent, of the given
// sizes and in that order, should go in the next record, which already
// holds base bytes. It is for interactive records, each of which is padded
// up to a bucket: how the frames are divided between records then decides
// how much padding they take. Three full-size packets in one record pad
// from 4.4 KB to 6.1 KB; as two and then one they pad by 250 bytes in all,
// and every record still comes out at a bucket's size.
//
// Split picks the division that puts the fewest bytes on the wire,
// counting splitCost for each record after the first, and returns how many
// frames the first record takes. That is all of them when one record is
// best, or when there are more than MaxSplit.
func (pl *Planner) Split(base int, sizes []int) int {
	n := len(sizes)
	if n <= 1 || n > MaxSplit {
		return n
	}
	// rest[i] is the least it costs to send frames i onwards in records of
	// their own.
	var rest [MaxSplit + 1]int
	for i := n - 1; i >= 0; i-- {
		best, sum := -1, 0
		for j := i; j < n; j++ {
			sum += sizes[j]
			if c := splitCost + pl.Padding(Interactive, sum) + rest[j+1]; best < 0 || c < best {
				best = c
			}
		}
		rest[i] = best
	}
	best, take, sum := -1, n, base
	for j := range n {
		sum += sizes[j]
		// On a tie the later division wins: fewer records.
		if c := pl.Padding(Interactive, sum) + rest[j+1]; best < 0 || c <= best {
			best, take = c, j+1
		}
	}
	return take
}

// FirstFlightPadding returns the padding that brings a lane's first flight
// of size bytes up to a size drawn from the profile's range for that
// direction. A flight already at or above the drawn size gets none.
func (pl *Planner) FirstFlightPadding(fromClient bool, size int) int {
	r := pl.p.ServerFirstFlight
	if fromClient {
		r = pl.p.ClientFirstFlight
	}
	gap := pl.intIn(r) - size
	if gap <= 0 {
		return 0
	}
	if !wire.CanPad(gap) {
		gap += wire.HeaderLen // overshoot by a few bytes rather than undershoot
	}
	return gap
}

// KeepaliveDelay draws the delay for a keepalive on an idle lane.
func (pl *Planner) KeepaliveDelay() time.Duration { return pl.durationIn(pl.p.KeepaliveDelay) }

// IdleAfter is how long without real traffic before the tunnel is idle.
func (pl *Planner) IdleAfter() time.Duration { return time.Duration(pl.p.IdleAfter) }

// IdleClose draws how long an idle tunnel keeps its last lane open.
func (pl *Planner) IdleClose() time.Duration { return pl.durationIn(pl.p.IdleClose) }

// IdleReopen draws how long held keepalives wait for a fresh lane.
func (pl *Planner) IdleReopen() time.Duration { return pl.durationIn(pl.p.IdleReopen) }

func (pl *Planner) intIn(r IntRange) int {
	if r.Max <= r.Min {
		return r.Min
	}
	pl.mu.Lock()
	defer pl.mu.Unlock()
	return r.Min + pl.rng.IntN(r.Max-r.Min+1)
}

func (pl *Planner) durationIn(r DurationRange) time.Duration {
	if r.Max <= r.Min {
		return time.Duration(r.Min)
	}
	pl.mu.Lock()
	defer pl.mu.Unlock()
	return time.Duration(r.Min) + time.Duration(pl.rng.Int64N(int64(r.Max-r.Min)+1))
}

// WireGuard message sizes (design §8). A keepalive is a transport-data
// message (type 4) with an empty payload: 16-byte header plus 16-byte tag.
const (
	keepaliveLen   = 32
	typeTransport  = 4
	typeInitiation = 1
	initiationLen  = 148
	typeResponse   = 2
	responseLen    = 92
	typeCookie     = 3
	cookieLen      = 64
)

// IsKeepalive reports whether pkt is a WireGuard keepalive. Keepalives don't
// count as tunnel activity, so they never keep an idle tunnel's lanes open.
func IsKeepalive(pkt []byte) bool {
	return len(pkt) == keepaliveLen && pkt[0] == typeTransport && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0
}

// IsHandshake reports whether pkt is a WireGuard handshake initiation,
// response or cookie reply.
func IsHandshake(pkt []byte) bool {
	if len(pkt) < 4 || pkt[1] != 0 || pkt[2] != 0 || pkt[3] != 0 {
		return false
	}
	switch pkt[0] {
	case typeInitiation:
		return len(pkt) == initiationLen
	case typeResponse:
		return len(pkt) == responseLen
	case typeCookie:
		return len(pkt) == cookieLen
	}
	return false
}
