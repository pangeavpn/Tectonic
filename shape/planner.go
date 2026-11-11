package shape

import (
	crand "crypto/rand"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/pangeavpn/tectonic/wire"
)

// Mode is the traffic state a record is planned for.
type Mode int

const (
	// Bulk fills records up to MaxRecord. One that is not full is padded
	// by a few bytes, so that its length is not a whole number of packets.
	Bulk Mode = iota
	// Interactive pads the record to a length drawn from the band above
	// the one its content falls in.
	Interactive
	// Idle pads a keepalive-only record to a length drawn from the idle
	// sizes.
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
// size bytes of frames. The result is 0 or at least wire.HeaderLen, and
// never takes the record past MaxRecord.
//
// An interactive record is padded to a length drawn evenly from the band
// above its own (see Profile.Buckets). An idle one is padded to a length
// drawn from the idle sizes (see Profile.IdleSizes), or as an interactive
// one if it is larger than all of them.
//
// A bulk record is whole full-size packets, whose sizes are no secret; its
// padding only has to take its length off the multiples of a packet's
// size, and every byte of it is one the transfer has to wait for. So it is
// not brought up to a bucket first: it takes a PAD frame with a body of
// less than the width of the band above, drawn evenly.
//
// Whatever the mode, the record ends up holding at least MinRecord bytes.
func (pl *Planner) Padding(mode Mode, size int) int {
	switch mode {
	case Bulk:
		lo, n := pl.band(size)
		if n > 1 {
			lo = max(size+wire.HeaderLen, MinRecord)
		}
		return pl.padTo(size, lo, n)
	case Interactive:
		lo, n := pl.band(size)
		return pl.padTo(size, lo, n)
	case Idle:
		// The record with the header of its PAD frame, as in band.
		s := pl.p.IdleSizes
		i := sort.SearchInts(s, size+wire.HeaderLen)
		if i == len(s) {
			return pl.Padding(Interactive, size)
		}
		// One of the ranges that start at or above it, then a length
		// within that range.
		lo, n := s[i], 1
		if ranges := len(s) - 1 - i; ranges > 0 {
			i += pl.intn(ranges)
			lo, n = s[i], s[i+1]-s[i]
		}
		return pl.padTo(size, lo, n)
	}
	return 0
}

// band returns the lengths an interactive record that holds size bytes of
// frames may be padded to: the n lengths from lo up.
//
// Padding is a PAD frame, which is at least its 3-byte header. The band a
// record falls in is the one that holds it with that header, and it is
// padded into the band above. So every size in a band is padded the same
// way, by 3 bytes or more, and a padded length says which band the record
// was in and nothing closer.
func (pl *Planner) band(size int) (lo, n int) {
	b := pl.p.Buckets
	i := sort.SearchInts(b, size+wire.HeaderLen) // the bucket that ends its band
	switch {
	case i == len(b):
		// Larger than every bucket: left as it is, unless it is smaller
		// than any record should be.
		if size >= MinRecord {
			return size, 1
		}
		return max(size+wire.HeaderLen, MinRecord), 1
	case i == len(b)-1:
		lo, n = b[i], 1
	default:
		lo, n = b[i], b[i+1]-b[i]
	}
	if lo < MinRecord {
		lo, n = MinRecord, max(lo+n-MinRecord, 1)
	}
	return lo, n
}

// padTo returns the padding that takes a record of size bytes to one of the
// n lengths from lo up, each as likely as another.
func (pl *Planner) padTo(size, lo, n int) int {
	gap := lo - size
	if n > 1 {
		gap += pl.intn(n)
	}
	if !wire.CanPad(gap) || gap < 0 || size+gap > MaxRecord {
		return 0
	}
	return gap
}

// cost is twice the padding an interactive record of size bytes takes on
// average: what brings it up to its bucket, and half the band above.
func (pl *Planner) cost(size int) int {
	lo, n := pl.band(size)
	return 2*(lo-size) + n - 1
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
// up to its bucket and into the band above: how the frames are divided
// between records then decides how much padding they take. Where the
// buckets are far apart, a few frames that fall just past one together
// may fall just short of others apart.
//
// Split picks the division that puts the fewest bytes on the wire on
// average, counting splitCost for each record after the first, and returns
// how many frames the first record takes. That is all of them when one
// record is best, or when there are more than MaxSplit.
func (pl *Planner) Split(base int, sizes []int) int {
	n := len(sizes)
	if n <= 1 || n > MaxSplit {
		return n
	}
	// rest[i] is the least it costs to send frames i onwards in records of
	// their own. Costs are doubled throughout, as cost's are.
	var rest [MaxSplit + 1]int
	for i := n - 1; i >= 0; i-- {
		best, sum := -1, 0
		for j := i; j < n; j++ {
			sum += sizes[j]
			if c := 2*splitCost + pl.cost(sum) + rest[j+1]; best < 0 || c < best {
				best = c
			}
		}
		rest[i] = best
	}
	best, take, sum := -1, n, base
	for j := range n {
		sum += sizes[j]
		// On a tie the later division wins: fewer records.
		if c := pl.cost(sum) + rest[j+1]; best < 0 || c <= best {
			best, take = c, j+1
		}
	}
	return take
}

// KeepaliveDelay draws the delay for a keepalive on an idle lane.
func (pl *Planner) KeepaliveDelay() time.Duration { return pl.durationIn(pl.p.KeepaliveDelay) }

// IdleAfter is how long without real traffic before the tunnel is idle.
func (pl *Planner) IdleAfter() time.Duration { return time.Duration(pl.p.IdleAfter) }

// IdleClose draws how long an idle tunnel keeps its last lane open.
func (pl *Planner) IdleClose() time.Duration { return pl.durationIn(pl.p.IdleClose) }

// IdleReopen draws how long held keepalives wait for a fresh lane.
func (pl *Planner) IdleReopen() time.Duration { return pl.durationIn(pl.p.IdleReopen) }

func (pl *Planner) intn(n int) int {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	return pl.rng.IntN(n)
}

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
