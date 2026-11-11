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
	for size := 1; size <= MaxRecord; size++ {
		pad := pl.Padding(Interactive, size)
		if !wire.CanPad(pad) {
			t.Fatalf("size %d: padding %d can't be expressed", size, pad)
		}
		total := size + pad
		found := false
		for _, b := range pl.Profile().Buckets {
			if b == total {
				found = true
			}
		}
		if !found && pad != 0 {
			t.Fatalf("size %d padded to %d, not a bucket", size, total)
		}
		if found {
			// It must be the smallest usable bucket.
			for _, b := range pl.Profile().Buckets {
				if b >= size && b < total && wire.CanPad(b-size) {
					t.Fatalf("size %d padded to %d but bucket %d fits", size, total, b)
				}
			}
		}
	}
	// A WireGuard keepalive frame (35 bytes) lands in the 64 bucket, a
	// handshake initiation (151) in 192.
	if got := 35 + pl.Padding(Interactive, 35); got != 64 {
		t.Fatalf("keepalive record = %d", got)
	}
	if got := 151 + pl.Padding(Interactive, 151); got != 192 {
		t.Fatalf("initiation record = %d", got)
	}
	// Sizes 1 and 2 short of a bucket skip to the next one.
	if got := 62 + pl.Padding(Interactive, 62); got != 128 {
		t.Fatalf("62 → %d, want 128", got)
	}
	if pl.Padding(Bulk, 100) != 0 {
		t.Fatal("bulk records must not be padded")
	}
}

func TestSplitDividesFramesToFitBuckets(t *testing.T) {
	pl := NewPlanner(nil)
	const pkt = 1455 // a full-size WireGuard packet in its DATA frame
	full := func(n int) []int {
		s := make([]int, n)
		for i := range s {
			s[i] = pkt
		}
		return s
	}
	// records sends frames the way a lane would, and returns each record's
	// size on the wire and the padding in all.
	records := func(base int, sizes []int) (out []int, pad int) {
		for len(sizes) > 0 {
			k := pl.Split(base, sizes)
			if k < 1 || k > len(sizes) {
				t.Fatalf("Split(%d, %v) = %d", base, sizes, k)
			}
			size := base
			for _, s := range sizes[:k] {
				size += s
			}
			p := pl.Padding(Interactive, size)
			out, pad = append(out, size+p), pad+p
			sizes, base = sizes[k:], 0
		}
		return out, pad
	}
	for _, tc := range []struct {
		n    int
		want []int
	}{
		{1, []int{1536}},
		{2, []int{3072}},
		// Three in one record would pad to 6144, wasting 1779 bytes.
		{3, []int{3072, 1536}},
		{4, []int{6144}},
		// Five in one would pad to 8192, wasting 917.
		{5, []int{6144, 1536}},
	} {
		got, _ := records(0, full(tc.n))
		if !slices.Equal(got, tc.want) {
			t.Errorf("%d full packets go out as %v, want %v", tc.n, got, tc.want)
		}
	}
	// However the frames fall, dividing them never costs more than sending
	// them in one record, and every record is a bucket's size.
	rng := rand.New(rand.NewPCG(1, 2))
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
		got, pad := records(base, sizes)
		one := pl.Padding(Interactive, base+sum)
		if cost := pad + (len(got)-1)*splitCost; cost > one {
			t.Fatalf("%v after %d: divided as %v costing %d, but one record costs %d", sizes, base, got, cost, one)
		}
		for _, r := range got {
			if !slices.Contains(pl.Profile().Buckets, r) {
				t.Fatalf("%v after %d: record of %d bytes is not a bucket", sizes, base, r)
			}
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
	seen := map[int]bool{}
	for range 500 {
		pad := pl.Padding(Idle, 35)
		if !wire.CanPad(pad) {
			t.Fatalf("idle padding %d", pad)
		}
		seen[35+pad] = true
	}
	for s := range seen {
		ok := false
		for _, want := range pl.Profile().IdleSizes {
			ok = ok || s == want
		}
		if !ok {
			t.Fatalf("idle record size %d not in idle_sizes", s)
		}
	}
	if len(seen) < 3 {
		t.Fatalf("idle sizes don't vary: %v", seen)
	}
	if pl.Padding(Idle, 5000) != 0 {
		t.Fatal("a record bigger than every idle size gets no padding")
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
