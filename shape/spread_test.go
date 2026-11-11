package shape

import (
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/pangeavpn/tectonic/wire"
)

// The DATA frames of WireGuard's fixed-size messages: a keepalive, a
// handshake response and a handshake initiation, each with its 3-byte
// frame header.
const (
	keepaliveFrame  = wire.HeaderLen + keepaliveLen
	responseFrame   = wire.HeaderLen + responseLen
	initiationFrame = wire.HeaderLen + initiationLen
)

// lengths pads a record of size bytes n times and returns how often each
// length came up.
func lengths(pl *Planner, mode Mode, size, n int) map[int]int {
	seen := map[int]int{}
	for range n {
		seen[size+pl.Padding(mode, size)]++
	}
	return seen
}

// bucketed is what a record of size bytes was padded to when padding
// rounded up to the next of sixteen buckets.
func bucketed(size int) int {
	for _, b := range coarse().Buckets {
		if gap := b - size; gap >= 0 && wire.CanPad(gap) {
			return b
		}
	}
	return size
}

func TestPaddedLengthsAreSpread(t *testing.T) {
	pl := NewPlanner(nil)
	const n = 4000
	for _, size := range []int{keepaliveFrame, responseFrame, initiationFrame, 99, 1455, 2910} {
		seen := lengths(pl, Interactive, size, n)
		if len(seen) < 14 {
			t.Errorf("a record of %d bytes came out at only %d lengths", size, len(seen))
		}
		for length, k := range seen {
			if k > n/8 {
				t.Errorf("a record of %d bytes came out at %d bytes %d times in %d", size, length, k, n)
			}
		}
	}
	// Records of every size together sit on no lattice: no length holds
	// more than a sliver of them, and none of the lengths' remainders by
	// the bands' own steps stands out.
	rng := rand.New(rand.NewPCG(3, 4))
	const records = 400000
	count := map[int]int{}
	var by16 [16]int
	var by64 [64]int
	for range records {
		size := 1 + rng.IntN(2048)
		length := size + pl.Padding(Interactive, size)
		count[length]++
		by16[length%16]++
		by64[length%64]++
	}
	for length, k := range count {
		if k > records/500 {
			t.Errorf("%d of %d records are %d bytes long", k, records, length)
		}
	}
	for r, k := range by16 {
		if k < records/16*9/10 || k > records/16*11/10 {
			t.Errorf("%d of %d record lengths leave %d when divided by 16", k, records, r)
		}
	}
	for r, k := range by64 {
		if k < records/64*8/10 || k > records/64*12/10 {
			t.Errorf("%d of %d record lengths leave %d when divided by 64", k, records, r)
		}
	}
}

func TestPaddedLengthDoesNotTrackThePacket(t *testing.T) {
	pl := NewPlanner(nil)
	set := func(size int) []int {
		var out []int
		for length := range lengths(pl, Interactive, size, 4000) {
			out = append(out, length)
		}
		slices.Sort(out)
		return out
	}
	// A lone handshake message comes out at the lengths the data packet
	// next to it in size does: an initiation at those of a packet four
	// bytes smaller, a response at those of a TCP ACK with timestamps.
	// Neither is ever left at its own size.
	for _, tc := range []struct {
		name      string
		size, kin int
	}{
		{"initiation", initiationFrame, wire.HeaderLen + 144},
		{"response", responseFrame, wire.HeaderLen + 96},
	} {
		got, want := set(tc.size), set(tc.kin)
		if !slices.Equal(got, want) {
			t.Errorf("a lone %s comes out at %v, a data packet of %d bytes at %v", tc.name, got, tc.kin, want)
		}
		if got[0] <= tc.size {
			t.Errorf("a lone %s can be left at %d bytes, its own size", tc.name, got[0])
		}
	}
	// A keepalive has no data packet near it in size, so it shares its
	// lengths with records of control frames: here a PONG and a notice of
	// dropped packets together.
	ka, ctrl := set(keepaliveFrame), set(2*wire.HeaderLen+wire.PingLen+wire.LostLen)
	if !slices.Equal(ka, ctrl) || ka[0] <= keepaliveFrame {
		t.Errorf("a lone keepalive comes out at %v, control frames in the same band at %v", ka, ctrl)
	}
	// The lengths are not the packet's own plus a fixed spread: where
	// they start depends on the band, not on the packet.
	offset := func(size int) int { return set(size)[0] - size }
	if a, b, c := offset(keepaliveFrame), offset(responseFrame), offset(initiationFrame); a == b || b == c || a == c {
		t.Errorf("padded lengths start %d, %d and %d bytes above the three messages", a, b, c)
	}
}

func TestPaddingCostsNoMoreThanBucketsDid(t *testing.T) {
	pl := NewPlanner(nil)
	// What a record takes on average now, against rounding up to the next
	// of the sixteen buckets the built-in profile had.
	now := func(size int) float64 { return float64(pl.cost(size)) / 2 }
	for _, tc := range []struct {
		name string
		size int
	}{
		{"a keepalive", keepaliveFrame},
		{"a handshake response", responseFrame},
		{"a handshake initiation", initiationFrame},
		{"a PONG", wire.HeaderLen + wire.PingLen},
		{"a bare TCP ACK", wire.HeaderLen + 80},
		{"a TCP ACK with timestamps", wire.HeaderLen + 96},
		{"one full-size packet", 1455},
		{"two full-size packets", 2 * 1455},
		{"four full-size packets", 4 * 1455},
	} {
		if was := float64(bucketed(tc.size) - tc.size); now(tc.size) > was {
			t.Errorf("%s takes %.1f bytes of padding on average, and took %.0f", tc.name, now(tc.size), was)
		}
	}
	// Over all sizes it is about half.
	var sumNow, sumWas float64
	for size := 1; size < pl.Profile().BulkThreshold; size++ {
		sumNow += now(size)
		sumWas += float64(bucketed(size) - size)
	}
	if sumNow > sumWas*0.6 {
		t.Errorf("padding over all sizes is %.0f%% of what the buckets took", 100*sumNow/sumWas)
	}
	// And what Split weighs is what Padding does.
	for _, size := range []int{keepaliveFrame, initiationFrame, 1455, 5000} {
		const n = 20000
		sum := 0
		for range n {
			sum += pl.Padding(Interactive, size)
		}
		if mean := float64(sum) / n; mean < now(size)-1.5 || mean > now(size)+1.5 {
			t.Errorf("a record of %d bytes took %.1f bytes of padding on average, Split counts %.1f", size, mean, now(size))
		}
	}
}

func TestBulkPaddingIsAFewBytes(t *testing.T) {
	pl := NewPlanner(nil)
	// A record of whole packets that is not full takes a PAD frame of 3
	// to 34 bytes: never none, which would leave its length a multiple of
	// the packet size, and never the distance to a bucket.
	for _, packets := range []int{1, 2, 5, 8, 11} {
		size := packets * 1455
		seen := lengths(pl, Bulk, size, 4000)
		if len(seen) != 32 {
			t.Errorf("%d packets came out at %d lengths, want 32", packets, len(seen))
		}
		for length, k := range seen {
			if pad := length - size; pad < wire.HeaderLen || pad >= wire.HeaderLen+32 {
				t.Errorf("%d packets took %d bytes of padding", packets, pad)
			}
			if k > 4000/16 {
				t.Errorf("%d packets came out at %d bytes %d times in 4000", packets, length, k)
			}
		}
	}
	// It costs less than padding into the band above does, at every size.
	for size := 1; size <= MaxRecord; size++ {
		pad := pl.Padding(Bulk, size)
		if !wire.CanPad(pad) || size+pad > MaxRecord || size+pad < MinRecord {
			t.Fatalf("a bulk record of %d bytes padded by %d", size, pad)
		}
		lo, n := pl.band(size)
		if size+pad >= lo+n && pad != 0 {
			t.Fatalf("a bulk record of %d bytes padded to %d, past the band above it", size, size+pad)
		}
		if pad == 0 && size+wire.HeaderLen <= MaxRecord {
			t.Fatalf("a bulk record of %d bytes left bare", size)
		}
	}
}

func TestPaddedRecordIsNeverSmallerThanAnHTTP2Frame(t *testing.T) {
	// Whatever the profile's buckets, a record of one small control frame
	// is not left shorter than HTTP/2 could make it.
	for _, buckets := range [][]int{Default().Buckets, {2, 4, 6}, {4}, {MaxRecord}} {
		p := Default()
		p.Buckets = buckets
		pl := NewPlanner(p)
		for size := 1; size <= 2*MinRecord; size++ {
			for range 50 {
				for _, mode := range []Mode{Interactive, Bulk, Idle} {
					pad := pl.Padding(mode, size)
					if !wire.CanPad(pad) || size+pad < MinRecord {
						t.Fatalf("buckets %v: a %v record of %d bytes padded by %d", buckets[:min(len(buckets), 4)], mode, size, pad)
					}
				}
			}
		}
	}
}

func TestLastBandIsPaddedToTheLastBucket(t *testing.T) {
	pl := NewPlanner(nil)
	for _, size := range []int{MaxRecord - 30, MaxRecord - 3} {
		if got := size + pl.Padding(Interactive, size); got != MaxRecord {
			t.Errorf("a record of %d bytes padded to %d, want a full record", size, got)
		}
	}
	// One or two bytes short of full can't be padded at all.
	if pl.Padding(Interactive, MaxRecord-1) != 0 || pl.Padding(Interactive, MaxRecord) != 0 {
		t.Error("padded a record with no room for a PAD frame")
	}
	// A profile whose buckets stop short leaves larger records alone.
	p := Default()
	p.Buckets = []int{64, 128}
	short := NewPlanner(p)
	if got := 100 + short.Padding(Interactive, 100); got != 128 {
		t.Errorf("a record in the last band padded to %d, want the last bucket", got)
	}
	if short.Padding(Interactive, 500) != 0 {
		t.Error("padded a record larger than every bucket")
	}
}
