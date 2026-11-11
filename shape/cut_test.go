package shape

import "testing"

func TestCutIsEvenAndKeepsBothPartsOfSize(t *testing.T) {
	pl := NewPlanner(nil)
	const n = 1455 // a full-size WireGuard packet's DATA frame
	counts := make([]int, n+1)
	const draws = 200_000
	for range draws {
		k := pl.Cut(n)
		if k < CutMin || n-k < CutMin {
			t.Fatalf("Cut(%d) = %d: leaves under %d bytes on one side", n, k, CutMin)
		}
		counts[k]++
	}
	// Every point allowed is drawn about as often as any other: split the
	// range in eight and compare.
	span := n - 2*CutMin + 1
	var eighths [8]int
	for k := CutMin; k <= n-CutMin; k++ {
		eighths[(k-CutMin)*8/span] += counts[k]
	}
	for i, c := range eighths {
		if want := draws / 8; c < want*9/10 || c > want*11/10 {
			t.Fatalf("eighth %d of the range drawn %d times, want about %d", i, c, want)
		}
	}
}

func TestCutLeavesSmallFramesWhole(t *testing.T) {
	pl := NewPlanner(nil)
	for _, n := range []int{0, 35, 92 + 3, CutFrom - 1} {
		if k := pl.Cut(n); k != 0 {
			t.Fatalf("Cut(%d) = %d, want 0", n, k)
		}
	}
	if k := pl.Cut(CutFrom); k < CutMin || k > CutFrom-CutMin {
		t.Fatalf("Cut(%d) = %d", CutFrom, k)
	}
}
