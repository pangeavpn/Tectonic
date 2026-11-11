package shape

import (
	"encoding/json"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/wire"
)

func TestDefaultValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	p := Default()
	p.ID = 7
	p.Name = "recorded"
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	q, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if q.ID != 7 || q.IdleAfter != p.IdleAfter || q.IdleClose != p.IdleClose || len(q.Buckets) != len(p.Buckets) {
		t.Fatalf("round trip changed the profile: %+v", q)
	}
	if _, err := Parse([]byte(`{"idle_after": 5}`)); err == nil {
		t.Fatal("numeric duration accepted")
	}
}

func TestValidateRejects(t *testing.T) {
	for name, mod := range map[string]func(*Profile){
		"empty buckets":      func(p *Profile) { p.Buckets = nil },
		"unsorted buckets":   func(p *Profile) { p.Buckets = []int{512, 256} },
		"duplicate buckets":  func(p *Profile) { p.Buckets = []int{256, 256} },
		"oversized bucket":   func(p *Profile) { p.Buckets = []int{MaxRecord + 1} },
		"bad flight range":   func(p *Profile) { p.ClientFirstFlight = []IntRange{{Min: 10, Max: 5}} },
		"zero bulk":          func(p *Profile) { p.BulkThreshold = 0 },
		"zero idle after":    func(p *Profile) { p.IdleAfter = 0 },
		"zero idle close":    func(p *Profile) { p.IdleClose = DurationRange{} },
		"bad keepalive":      func(p *Profile) { p.KeepaliveDelay = DurationRange{Min: 5, Max: 1} },
		"no idle sizes":      func(p *Profile) { p.IdleSizes = nil },
		"zero idle size":     func(p *Profile) { p.IdleSizes = []int{0, 64} },
		"negative flight":    func(p *Profile) { p.ServerFirstFlight = []IntRange{{Min: -1, Max: 5}} },
		"zero idle reopen":   func(p *Profile) { p.IdleReopen = DurationRange{} },
		"flight too big":     func(p *Profile) { p.ServerFirstFlight = []IntRange{{Min: 3, Max: MaxRecord + 1}} },
		"descending buckets": func(p *Profile) { p.Buckets = []int{64, 32} },
	} {
		p := Default()
		mod(p)
		if p.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSet(t *testing.T) {
	custom := Default()
	custom.ID = 3
	custom.BulkThreshold = 1
	s, err := NewSet(custom)
	if err != nil {
		t.Fatal(err)
	}
	if s.Get(3).BulkThreshold != 1 {
		t.Fatal("Get(3) did not return the custom profile")
	}
	if s.Get(99).ID != DefaultID || s.Has(99) || !s.Has(DefaultID) {
		t.Fatal("unknown IDs must fall back to the default")
	}
	var nilSet *Set
	if nilSet.Get(5).ID != DefaultID {
		t.Fatal("nil set")
	}
	bad := Default()
	bad.Buckets = nil
	if _, err := NewSet(bad); err == nil {
		t.Fatal("NewSet accepted an invalid profile")
	}
}

func TestInteractivePadding(t *testing.T) {
	pl := NewPlanner(nil)
	buckets := pl.Profile().Buckets
	for size := 1; size <= MaxRecord; size++ {
		pad := pl.Padding(Interactive, size)
		if !wire.CanPad(pad) {
			t.Fatalf("size %d: padding %d can't be expressed", size, pad)
		}
		total := size + pad
		if total < MinRecord || total > MaxRecord {
			t.Fatalf("size %d padded to %d", size, total)
		}
		// With the header of its PAD frame the record falls in one band,
		// and it ends up in the band above: at least the bucket that ends
		// its own, and less than the next.
		i, _ := slices.BinarySearch(buckets, size+wire.HeaderLen)
		if i == len(buckets) {
			if pad != 0 {
				t.Fatalf("size %d, with no room for a PAD frame, padded by %d", size, pad)
			}
			continue
		}
		lo, hi := buckets[i], MaxRecord+1
		if i+1 < len(buckets) {
			hi = buckets[i+1]
		}
		if total < lo || total >= hi {
			t.Fatalf("size %d padded to %d, outside [%d, %d)", size, total, lo, hi)
		}
	}
	// A WireGuard keepalive frame (35 bytes) lands in [48, 64), a
	// handshake initiation (151) in [160, 176).
	for range 200 {
		if got := 35 + pl.Padding(Interactive, 35); got < 48 || got >= 64 {
			t.Fatalf("keepalive record = %d", got)
		}
		if got := 151 + pl.Padding(Interactive, 151); got < 160 || got >= 176 {
			t.Fatalf("initiation record = %d", got)
		}
	}
	// A size just short of a bucket has no room for a PAD frame under it,
	// and is padded as the band above is.
	for range 200 {
		if got := 62 + pl.Padding(Interactive, 62); got < 80 || got >= 96 {
			t.Fatalf("a record of 62 bytes padded to %d, want [80, 96)", got)
		}
	}
}

// coarse is a profile whose buckets are far apart, as the built-in ones
// used to be, so that how frames are divided between records matters.
func coarse() *Profile {
	p := Default()
	p.Buckets = []int{
		64, 128, 192, 256, 384, 512, 768, 1024, 1536,
		2048, 3072, 4096, 6144, 8192, 12288, MaxRecord,
	}
	return p
}

func TestSplitDividesFramesToFitBuckets(t *testing.T) {
	const pkt = 1455 // a full-size WireGuard packet in its DATA frame
	full := func(n int) []int {
		s := make([]int, n)
		for i := range s {
			s[i] = pkt
		}
		return s
	}
	// divide sends frames the way a lane would, and returns how many go
	// in each record and twice the padding they take on average.
	divide := func(pl *Planner, base int, sizes []int) (out []int, cost int) {
		for len(sizes) > 0 {
			k := pl.Split(base, sizes)
			if k < 1 || k > len(sizes) {
				t.Fatalf("Split(%d, %v) = %d", base, sizes, k)
			}
			size := base
			for _, s := range sizes[:k] {
				size += s
			}
			out, cost = append(out, k), cost+pl.cost(size)
			sizes, base = sizes[k:], 0
		}
		return out, cost
	}
	pl := NewPlanner(coarse())
	for _, tc := range []struct {
		n    int
		want []int
	}{
		{1, []int{1}},
		{2, []int{2}},
		// Three in one record come up to 6144 and into the band above
		// it, 2.8 KB of padding on average; as two and one they take 1 KB.
		{3, []int{2, 1}},
		{4, []int{4}},
		{5, []int{4, 1}},
	} {
		got, _ := divide(pl, 0, full(tc.n))
		if !slices.Equal(got, tc.want) {
			t.Errorf("%d full packets go out as %v to a record, want %v", tc.n, got, tc.want)
		}
	}
	// However the frames fall, dividing them never costs more than sending
	// them in one record: with buckets far apart, and with the built-in
	// ones, which are close enough that one record is nearly always best.
	rng := rand.New(rand.NewPCG(1, 2))
	for _, pl := range []*Planner{pl, NewPlanner(nil)} {
		divided := 0
		for range 2000 {
			n := 1 + rng.IntN(MaxSplit)
			sizes := make([]int, n)
			sum := 0
			for i := range sizes {
				sizes[i] = 35 + rng.IntN(1421)
				if sum+sizes[i] >= pl.Profile().BulkThreshold {
					sizes = sizes[:i]
					break
				}
				sum += sizes[i]
			}
			if len(sizes) == 0 {
				continue
			}
			base := rng.IntN(2) * 11 // sometimes a PONG goes first
			got, cost := divide(pl, base, sizes)
			if len(got) > 1 {
				divided++
			}
			if one := pl.cost(base + sum); cost+2*splitCost*(len(got)-1) > one {
				t.Fatalf("%v after %d: divided as %v costing %d, but one record costs %d", sizes, base, got, cost/2, one/2)
			}
		}
		if far := len(pl.Profile().Buckets) < 100; far && divided == 0 {
			t.Error("with buckets far apart, no run of frames was divided")
		}
	}
	// Too many frames to weigh, or just one: all in one record.
	if got := pl.Split(0, make([]int, MaxSplit+1)); got != MaxSplit+1 {
		t.Fatalf("Split of %d frames = %d", MaxSplit+1, got)
	}
	if got := pl.Split(0, nil); got != 0 {
		t.Fatalf("Split of nothing = %d", got)
	}
}

func TestIdlePadding(t *testing.T) {
	pl := NewPlanner(nil)
	sizes := pl.Profile().IdleSizes
	seen := map[int]bool{}
	for range 2000 {
		pad := pl.Padding(Idle, 35)
		if !wire.CanPad(pad) {
			t.Fatalf("idle padding %d", pad)
		}
		seen[35+pad] = true
	}
	for s := range seen {
		if s < sizes[0] || s >= sizes[len(sizes)-1] {
			t.Fatalf("idle record size %d outside the idle sizes %v", s, sizes)
		}
	}
	if len(seen) < 40 {
		t.Fatalf("idle sizes don't vary: %d of them", len(seen))
	}
	// Two keepalives together start no lower than the next idle size up.
	for range 200 {
		if got := 70 + pl.Padding(Idle, 70); got < 80 || got >= 128 {
			t.Fatalf("two keepalives padded to %d", got)
		}
	}
	// One that only the largest idle size holds is padded to that.
	if got := 100 + pl.Padding(Idle, 100); got != 128 {
		t.Fatalf("a record of 100 bytes padded to %d, want the largest idle size", got)
	}
	// A record bigger than every idle size is padded as an interactive one.
	if got := 5000 + pl.Padding(Idle, 5000); got < 5024 || got >= 5056 {
		t.Fatalf("a record bigger than every idle size padded to %d", got)
	}
}

func TestMode(t *testing.T) {
	pl := NewPlanner(nil)
	if pl.Mode(100, true) != Idle || pl.Mode(100, false) != Interactive || pl.Mode(1<<20, false) != Bulk {
		t.Fatal("Mode")
	}
}

func TestDurations(t *testing.T) {
	pl := NewPlanner(nil)
	p := pl.Profile()
	for range 200 {
		if d := pl.IdleClose(); d < time.Duration(p.IdleClose.Min) || d > time.Duration(p.IdleClose.Max) {
			t.Fatalf("IdleClose %v", d)
		}
		if d := pl.IdleReopen(); d < time.Duration(p.IdleReopen.Min) || d > time.Duration(p.IdleReopen.Max) {
			t.Fatalf("IdleReopen %v", d)
		}
		if d := pl.KeepaliveDelay(); d < 0 || d > time.Duration(p.KeepaliveDelay.Max) {
			t.Fatalf("KeepaliveDelay %v", d)
		}
	}
	if pl.IdleAfter() != time.Duration(p.IdleAfter) {
		t.Fatal("IdleAfter")
	}
}

func TestWireGuardClassifiers(t *testing.T) {
	ka := make([]byte, 32)
	ka[0] = 4
	if !IsKeepalive(ka) {
		t.Fatal("keepalive not recognised")
	}
	data := make([]byte, 48)
	data[0] = 4
	if IsKeepalive(data) {
		t.Fatal("data packet taken for a keepalive")
	}
	init := make([]byte, 148)
	init[0] = 1
	resp := make([]byte, 92)
	resp[0] = 2
	cookie := make([]byte, 64)
	cookie[0] = 3
	if !IsHandshake(init) || !IsHandshake(resp) || !IsHandshake(cookie) {
		t.Fatal("handshake not recognised")
	}
	if IsHandshake(ka) || IsHandshake(init[:100]) || IsKeepalive(init) {
		t.Fatal("misclassified")
	}
}
