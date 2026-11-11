package shape

import (
	"fmt"

	"github.com/pangeavpn/tectonic/wire"
)

// MaxFirstFlight is the most records a profile may open a lane with in one
// direction.
const MaxFirstFlight = 8

// MinClientFirstRecord is the least a client's first record may hold. The
// node tells a login from the first record it reads: that record begins
// with HELLO and must hold its frame header, every field and the first 16
// bytes of its tag. The rest of HELLO may follow in the next record.
const MinClientFirstRecord = wire.HeaderLen + wire.HelloLen - wire.TagLen + 16 // 65

// validateFirstFlight checks the records a lane opens with.
func (p *Profile) validateFirstFlight() error {
	// A record that happens to hold nothing but padding holds at least one
	// PAD frame, which is at least a frame header.
	ok := func(r IntRange) bool {
		return r.Min >= wire.HeaderLen && r.Max >= r.Min && r.Max <= MaxRecord
	}
	for _, f := range []struct {
		name    string
		records []IntRange
	}{{"client_first_flight", p.ClientFirstFlight}, {"server_first_flight", p.ServerFirstFlight}} {
		if len(f.records) == 0 || len(f.records) > MaxFirstFlight {
			return fmt.Errorf("shape: %s must list between 1 and %d records", f.name, MaxFirstFlight)
		}
		for i, r := range f.records {
			if !ok(r) {
				return fmt.Errorf("shape: %s record %d range [%d, %d] invalid", f.name, i+1, r.Min, r.Max)
			}
		}
	}
	if r := p.ClientFirstFlight[0]; r.Min < MinClientFirstRecord {
		return fmt.Errorf("shape: client_first_flight record 1 range [%d, %d] is under the %d bytes of HELLO the node needs in one record",
			r.Min, r.Max, MinClientFirstRecord)
	}
	if r := p.ClientAck; r != (IntRange{}) && !ok(r) {
		return fmt.Errorf("shape: client_ack range [%d, %d] invalid", r.Min, r.Max)
	}
	return nil
}

// FirstFlight draws the sizes of the records that open a lane in one
// direction, for an opening of size bytes of frames. The frames and the
// padding after them fill the records as one stream, cut where each record
// ends, so the sizes add up to size plus an amount that PAD frames can make
// up exactly (see wire.CanPad).
//
// Every record but the last is the size drawn for it. The last one gives:
// it grows to hold whatever the others leave over, unpadded, and moves a
// byte or two (a frame header, if that would take it under its range) when
// the frames end where no PAD frame fits behind them. No record is ever
// smaller than the least its range allows, so a client's first always holds
// MinClientFirstRecord bytes.
func (pl *Planner) FirstFlight(fromClient bool, size int) []int {
	ranges := pl.p.ServerFirstFlight
	if fromClient {
		ranges = pl.p.ClientFirstFlight
	}
	if len(ranges) == 0 { // not a profile Validate accepts
		if size == 0 {
			return nil
		}
		return []int{size}
	}
	sizes := make([]int, len(ranges))
	total := 0
	for i, r := range ranges {
		sizes[i] = pl.intIn(r)
		total += sizes[i]
	}
	last := len(sizes) - 1
	switch gap := total - size; {
	case gap < 0:
		sizes[last] -= gap
	case !wire.CanPad(gap):
		if sizes[last]-gap >= ranges[last].Min {
			sizes[last] -= gap
		} else {
			sizes[last] += wire.HeaderLen
		}
	}
	return sizes
}

// FirstFlightAck draws the size of the record a client lane sends when the
// server's first bytes arrive, or 0 if the profile has none.
func (pl *Planner) FirstFlightAck() int {
	n := pl.intIn(pl.p.ClientAck)
	if n <= 0 {
		return 0
	}
	return max(n, wire.HeaderLen)
}
