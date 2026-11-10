package sched

import (
	"encoding/binary"
	"slices"
	"sync"
	"testing"
	"time"
)

// wgData builds a WireGuard data packet of size bytes for key idx.
func wgData(idx uint32, ctr uint64, size int) []byte {
	p := make([]byte, size)
	binary.LittleEndian.PutUint32(p, wgTransport)
	binary.LittleEndian.PutUint32(p[4:], idx)
	binary.LittleEndian.PutUint64(p[8:], ctr)
	return p
}

// sink records what a Resequencer delivers.
type sink struct {
	mu  sync.Mutex
	got []uint64 // counters, or ^0 for packets that aren't WireGuard data
}

func (s *sink) deliver(pkt []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ctr, ok := transportHeader(pkt); ok {
		s.got = append(s.got, ctr)
	} else {
		s.got = append(s.got, ^uint64(0))
	}
}

func (s *sink) list() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.got)
}

// waitFor polls until the sink holds want.
func (s *sink) waitFor(t *testing.T, want []uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if slices.Equal(s.list(), want) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("delivered %v, want %v", s.list(), want)
}

const big = 1400

const rtt = 50 * time.Millisecond

func TestResequencerMergesLanesInOrder(t *testing.T) {
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a, b := r.Source(), r.Source()
	a.Push(wgData(7, 0, big), rtt)
	a.Push(wgData(7, 1, big), rtt)
	b.Push(wgData(7, 3, big), rtt) // 2 is still on its way on lane a
	b.Push(wgData(7, 4, big), rtt)
	if got := s.list(); !slices.Equal(got, []uint64{0, 1}) {
		t.Fatalf("delivered %v ahead of a packet still in flight", got)
	}
	a.Push(wgData(7, 2, big), rtt)
	a.Push(wgData(7, 5, big), rtt)
	if got := s.list(); !slices.Equal(got, []uint64{0, 1, 2, 3, 4, 5}) {
		t.Fatalf("delivered %v", got)
	}
	if st := r.Stats(); st.Held != 2 || st.Skipped != 0 || st.Late != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestResequencerOneLaneNeverWaits(t *testing.T) {
	// One lane delivers in the order it was sent, so a gap in it is a loss.
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a := r.Source()
	for _, c := range []uint64{0, 2, 3, 7} {
		a.Push(wgData(7, c, big), rtt)
	}
	if got := s.list(); !slices.Equal(got, []uint64{0, 2, 3, 7}) {
		t.Fatalf("delivered %v: a single lane's gaps should not be waited for", got)
	}
	if st := r.Stats(); st.Skipped != 4 {
		t.Fatalf("stats %+v", st)
	}
}

func TestResequencerSkipsALossOnceEveryLaneHasPassedIt(t *testing.T) {
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a, b := r.Source(), r.Source()
	a.Push(wgData(7, 0, big), rtt)
	b.Push(wgData(7, 2, big), rtt) // 1 was dropped before it reached a lane
	if got := s.list(); !slices.Equal(got, []uint64{0}) {
		t.Fatalf("delivered %v while lane a might still hold 1", got)
	}
	// Lane a moves past the gap: 1 can no longer arrive on either lane.
	a.Push(wgData(7, 3, big), rtt)
	if got := s.list(); !slices.Equal(got, []uint64{0, 2, 3}) {
		t.Fatalf("delivered %v; the loss should be given up on at once", got)
	}
	if st := r.Stats(); st.Held != 2 || st.Skipped != 1 || st.Late != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestResequencerGivesUpOnASilentLaneAfterTheHold(t *testing.T) {
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a, b := r.Source(), r.Source()
	start := time.Now()
	a.Push(wgData(7, 0, big), 0)
	b.Push(wgData(7, 2, big), 0) // lane a goes quiet with 1 unaccounted for
	b.Push(wgData(7, 3, big), 0)
	if got := s.list(); !slices.Equal(got, []uint64{0}) {
		t.Fatalf("delivered %v before the hold ran out", got)
	}
	s.waitFor(t, []uint64{0, 2, 3})
	if held := time.Since(start); held < HoldMin {
		t.Fatalf("released after %v, before HoldMin", held)
	}
	// The missing packet turns up after all: it goes straight through, and
	// WireGuard's replay window decides what to do with it.
	a.Push(wgData(7, 1, big), 0)
	a.Push(wgData(7, 4, big), 0)
	s.waitFor(t, []uint64{0, 2, 3, 1, 4})
	if st := r.Stats(); st.Held != 2 || st.Skipped != 1 || st.Late != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestResequencerWaitsForALaneThatHasShownNothing(t *testing.T) {
	// A lane that has just joined may be carrying the missing packets.
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a, b := r.Source(), r.Source()
	a.Push(wgData(7, 0, big), 0)
	a.Push(wgData(7, 2, big), 0)
	if got := s.list(); !slices.Equal(got, []uint64{0}) {
		t.Fatalf("delivered %v without waiting for the new lane", got)
	}
	b.Push(wgData(7, 1, big), 0)
	if got := s.list(); !slices.Equal(got, []uint64{0, 1, 2}) {
		t.Fatalf("delivered %v", got)
	}
}

func TestResequencerStopsWaitingForAClosedLane(t *testing.T) {
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a, b := r.Source(), r.Source()
	a.Push(wgData(7, 0, big), time.Second)
	b.Push(wgData(7, 2, big), time.Second)
	b.Push(wgData(7, 3, big), time.Second)
	// Lane a ends (reset, say) with 1 still on it: nothing can fill the gap.
	a.Close()
	a.Close() // closing twice is harmless
	if got := s.list(); !slices.Equal(got, []uint64{0, 2, 3}) {
		t.Fatalf("delivered %v; a closed lane should not be waited for", got)
	}
	b.Close()
	if st := r.Stats(); st.Skipped != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestResequencerHoldScalesWithRTT(t *testing.T) {
	if HoldFor(0) != HoldMin || HoldFor(time.Second) != HoldMax {
		t.Fatal("hold not clamped")
	}
	if got := HoldFor(80 * time.Millisecond); got != 120*time.Millisecond {
		t.Fatalf("HoldFor(80ms) = %v, want one and a half round trips", got)
	}
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a, b := r.Source(), r.Source()
	a.Push(wgData(7, 0, big), 0)
	b.Push(wgData(7, 2, big), 40*time.Millisecond) // waits 60 ms
	time.Sleep(HoldMin + 10*time.Millisecond)
	if got := s.list(); !slices.Equal(got, []uint64{0}) {
		t.Fatalf("delivered %v long before the hold for this RTT", got)
	}
	s.waitFor(t, []uint64{0, 2})
}

func TestResequencerPassesSmallPacketsStraightThrough(t *testing.T) {
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a, b := r.Source(), r.Source()
	a.Push(wgData(7, 0, big), rtt)
	b.Push(wgData(7, 2, 96), rtt) // an ACK inside the tunnel
	b.Push(wgData(7, 3, big), rtt)
	if got := s.list(); !slices.Equal(got, []uint64{0, 2}) {
		t.Fatalf("delivered %v: the small packet should not wait", got)
	}
	// Filling the gap releases 3 without repeating 2.
	a.Push(wgData(7, 1, big), rtt)
	if got := s.list(); !slices.Equal(got, []uint64{0, 2, 1, 3}) {
		t.Fatalf("delivered %v", got)
	}
}

func TestResequencerSmallPacketsDoNotMoveALaneOn(t *testing.T) {
	// A small packet may be sent out of turn, or copied onto a second lane,
	// so it is no proof the lane has nothing earlier to deliver.
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a, b := r.Source(), r.Source()
	a.Push(wgData(7, 0, big), rtt)
	a.Push(wgData(7, 5, 96), rtt)
	b.Push(wgData(7, 6, big), rtt)
	if got := s.list(); !slices.Equal(got, []uint64{0, 5}) {
		t.Fatalf("delivered %v: lane a still owes 1 to 4", got)
	}
	for c := uint64(1); c <= 4; c++ {
		a.Push(wgData(7, c, big), rtt)
	}
	if got := s.list(); !slices.Equal(got, []uint64{0, 5, 1, 2, 3, 4, 6}) {
		t.Fatalf("delivered %v", got)
	}
	if st := r.Stats(); st.Skipped != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestResequencerPassesOtherMessagesThrough(t *testing.T) {
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a, b := r.Source(), r.Source()
	a.Push(wgData(7, 0, big), 0)
	b.Push(wgData(7, 2, big), rtt)
	init := make([]byte, 148)
	init[0] = 1 // handshake initiation
	b.Push(init, 0)
	b.Push([]byte("not wireguard"), 0)
	if got := s.list(); !slices.Equal(got, []uint64{0, ^uint64(0), ^uint64(0)}) {
		t.Fatalf("delivered %v", got)
	}
}

func TestResequencerKeepsKeysApart(t *testing.T) {
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a, b := r.Source(), r.Source()
	a.Push(wgData(1, 0, big), rtt)
	b.Push(wgData(1, 2, big), rtt) // waits for 1
	// A different key (after a rekey) has its own counters and isn't held
	// up by the gap in key 1.
	b.Push(wgData(2, 0, big), rtt)
	b.Push(wgData(2, 1, big), rtt)
	if got := s.list(); !slices.Equal(got, []uint64{0, 0, 1}) {
		t.Fatalf("delivered %v", got)
	}
}

func TestResequencerDropsDuplicatesOfHeldPackets(t *testing.T) {
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a, b := r.Source(), r.Source()
	a.Push(wgData(7, 0, big), rtt)
	b.Push(wgData(7, 2, big), rtt)
	b.Push(wgData(7, 2, big), rtt)
	a.Push(wgData(7, 1, big), rtt)
	if got := s.list(); !slices.Equal(got, []uint64{0, 1, 2}) {
		t.Fatalf("delivered %v", got)
	}
}

func TestResequencerStartsAKeyWhereItIsFirstSeen(t *testing.T) {
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a, b := r.Source(), r.Source()
	// A key first seen mid-stream (the tunnel outlived a session) starts
	// where it is.
	a.Push(wgData(7, 5000, big), rtt)
	a.Push(wgData(7, 5001, big), rtt)
	// A new key's packets wait for counter 0.
	a.Push(wgData(8, 1, big), rtt)
	b.Push(wgData(8, 0, big), rtt)
	if got := s.list(); !slices.Equal(got, []uint64{5000, 5001, 0, 1}) {
		t.Fatalf("delivered %v", got)
	}
}

func TestResequencerBoundsWhatItHolds(t *testing.T) {
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a, b := r.Source(), r.Source()
	b.Push(wgData(7, 0, big), time.Second)
	for c := uint64(2); c < 2+maxHeld+10; c++ {
		a.Push(wgData(7, c, big), time.Second)
	}
	got := s.list()
	if len(got) != 1+maxHeld+10 || !slices.IsSorted(got) {
		t.Fatalf("delivered %d packets (sorted %v); want everything once the cap is passed", len(got), slices.IsSorted(got))
	}
	if st := r.Stats(); st.Skipped != 1 {
		t.Fatalf("stats %+v", st)
	}
	// A counter far beyond the flow restarts it rather than waiting.
	a.Push(wgData(7, 1<<40, big), time.Second)
	if got := s.list(); got[len(got)-1] != 1<<40 {
		t.Fatal("a far jump was held")
	}
}

func TestResequencerCloseStopsDelivery(t *testing.T) {
	var s sink
	r := NewResequencer(s.deliver)
	a, b := r.Source(), r.Source()
	a.Push(wgData(7, 0, big), 0)
	b.Push(wgData(7, 2, big), 0)
	r.Close()
	time.Sleep(2 * HoldMin)
	a.Push(wgData(7, 1, big), 0)
	r.Source().Push(wgData(7, 3, big), 0)
	b.Close()
	if got := s.list(); !slices.Equal(got, []uint64{0}) {
		t.Fatalf("delivered %v after Close", got)
	}
}

func TestResequencerConcurrentLanes(t *testing.T) {
	// Three lanes deliver interleaved thirds of a stream concurrently, each
	// in its own order; the output must be the whole stream, in order, with
	// nothing given up on along the way.
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	const n, lanes, batch = 6000, 3, 300 // batches keep the lanes within maxHeld of each other
	src := [lanes]*Source{r.Source(), r.Source(), r.Source()}
	for b := uint64(0); b < n; b += batch {
		var wg sync.WaitGroup
		for lane := range uint64(lanes) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for c := b + lane; c < b+batch; c += lanes {
					src[lane].Push(wgData(7, c, big), time.Second)
				}
			}()
		}
		wg.Wait()
	}
	want := make([]uint64, n)
	for i := range want {
		want[i] = uint64(i)
	}
	if got := s.list(); !slices.Equal(got, want) {
		t.Fatalf("delivered %d packets, in order: %v", len(got), slices.IsSorted(got))
	}
	if st := r.Stats(); st.Skipped != 0 || st.Late != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestResequencerSurvivesALaneThatBreaksItsOrder(t *testing.T) {
	// If packets were reordered before they reached the lane, the merge
	// passes them on as they come rather than stalling or losing any.
	var s sink
	r := NewResequencer(s.deliver)
	defer r.Close()
	a := r.Source()
	for _, c := range []uint64{0, 2, 1, 3} {
		a.Push(wgData(7, c, big), rtt)
	}
	if got := s.list(); !slices.Equal(got, []uint64{0, 2, 1, 3}) {
		t.Fatalf("delivered %v", got)
	}
}
