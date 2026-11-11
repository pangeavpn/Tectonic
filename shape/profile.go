// Package shape holds Tectonic's shaping profiles and record-size planning.
//
// TLS hides what is inside the traffic, but WireGuard still has a shape:
// 148- and 92-byte handshakes, a 32-byte keepalive on a timer, and MTU-sized
// data. Shaping changes only what an observer can measure from outside: TLS
// record sizes and their timing (design §8).
//
//	Bulk transfer  records filled to 16 KB, a frame running on into the next;
//	               one that is not full padded by a few bytes
//	Interactive    each record padded to a length drawn from the band above
//	               the one its content falls in, between the profile's buckets
//	Lane start     the first records each way sized like Chrome loading a page over HTTP/2
//	Idle           keepalives delayed and padded to a length drawn from the
//	               profile's idle sizes; the lane closes after a while and a
//	               fresh one opens later
//
// Profiles are data, not code. WELCOME names the profile the session uses by
// ID, so new profiles can be rolled out from the hub without a protocol
// change.
package shape

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// MaxRecord is the largest TLS record payload (2^14 bytes), which is also the
// most the shaper puts in one record.
const MaxRecord = 16384

// MinRecord is the least a padded record holds: an HTTP/2 frame header, the
// smallest thing a browser's connection ever sends in a record.
const MinRecord = 9

// DefaultID is the ID of the built-in profile. A client that doesn't know the
// profile a WELCOME names falls back to it.
const DefaultID = 0

// Profile describes how a session's traffic should look.
type Profile struct {
	ID   uint16 `json:"id"`
	Name string `json:"name"`

	// Lane start: the records that open a lane in each direction, in
	// order, each of a size drawn uniformly from its range. They are the
	// records Chrome and an HTTP/2 server exchange when a page is loaded:
	//
	//	client  the connection preface with SETTINGS and WINDOW_UPDATE,
	//	        then the HEADERS of the first GET
	//	server  SETTINGS ACK with WINDOW_UPDATE, the response HEADERS,
	//	        then the start of the page
	//
	// (A server's own SETTINGS goes out before the client has said
	// anything, so it is no part of what answers a login.) The lane's
	// opening frames, HELLO and the first WireGuard packet or WELCOME, fill
	// these records as one stream with padding after them, so a frame may
	// begin in one record and end in the next. A flight has between 1 and
	// MaxFirstFlight records of at least 3 bytes, and a client's first
	// record holds at least MinClientFirstRecord: the node must find
	// enough of HELLO in it to know a login. Sizes are what goes inside
	// the TLS record, as everywhere in a profile; the record is 17 bytes
	// longer on the wire.
	ClientFirstFlight []IntRange `json:"client_first_flight"`
	ServerFirstFlight []IntRange `json:"server_first_flight"`
	// ClientAck is the record a client sends by itself when the server's
	// first bytes arrive, as Chrome acknowledges the server's SETTINGS. A
	// zero range means none.
	ClientAck IntRange `json:"client_ack"`

	// Interactive: the buckets divide record sizes into bands, each
	// running from just above one bucket up to the next. A record is padded
	// with a PAD frame, whose header is 3 bytes. With that header it falls
	// in one band, and the PAD frame's body brings it to a length drawn
	// evenly from the band above: at least the next bucket and less than
	// the one after. Its length then says which band the record was in and
	// nothing closer, and no length is more likely than its neighbours. A
	// record in the last band is padded to the last bucket; one larger
	// than that is not padded. Ascending, each at most MaxRecord.
	Buckets []int `json:"buckets"`

	// Bulk: when at least this many bytes are waiting, the lane is carrying
	// a transfer. Its records are filled, one that is not full is padded
	// by a few bytes and not up to a bucket, and the packets waiting are
	// not weighed for dividing between records (see Planner.Split).
	BulkThreshold int `json:"bulk_threshold"`

	// Idle: the tunnel is idle once nothing but WireGuard keepalives has
	// moved for IdleAfter. The last lane closes IdleClose after that, and
	// the pool shrinks to one lane at a moment drawn between the two. With
	// no lane open, held keepalives wait IdleReopen before a fresh lane
	// carries them; any other traffic opens a lane at once.
	IdleAfter  Duration      `json:"idle_after"`
	IdleClose  DurationRange `json:"idle_close"`
	IdleReopen DurationRange `json:"idle_reopen"`

	// KeepaliveDelay is the random delay added to keepalives on an idle
	// lane, so they don't tick on WireGuard's fixed timer.
	KeepaliveDelay DurationRange `json:"keepalive_delay"`
	// IdleSizes shape the keepalive-only records of an idle lane. Each
	// size and the next bound a range; a record is padded to a length
	// drawn evenly from one of the ranges that start at or above it, each
	// range as likely as another. Ascending, each at most MaxRecord.
	IdleSizes []int `json:"idle_sizes"`
}

// IntRange is an inclusive range of sizes in bytes.
type IntRange struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// DurationRange is an inclusive range of durations.
type DurationRange struct {
	Min Duration `json:"min"`
	Max Duration `json:"max"`
}

// Duration is a time.Duration written in JSON as a Go duration string, such
// as "90s".
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("shape: duration must be a string like \"90s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Default returns the built-in profile.
//
// Its numbers are hand-picked placeholders shaped like Chrome browsing over
// HTTP/2. Milestone M5 replaces them with profiles recorded from real Chrome
// sessions; until then this is the profile every node announces.
func Default() *Profile {
	return &Profile{
		ID:   DefaultID,
		Name: "default",
		// Chrome's first HTTP/2 flight: the connection preface with
		// SETTINGS and WINDOW_UPDATE, 70 bytes every time, then the HEADERS
		// of the first GET. Its SETTINGS ACK follows the server's SETTINGS.
		ClientFirstFlight: []IntRange{{Min: 70, Max: 70}, {Min: 443, Max: 453}},
		ClientAck:         IntRange{Min: 9, Max: 9},
		// A server's reply: SETTINGS ACK with WINDOW_UPDATE, the response
		// HEADERS, and the start of the page.
		ServerFirstFlight: []IntRange{{Min: 22, Max: 22}, {Min: 91, Max: 92}, {Min: 1090, Max: 4090}},

		Buckets:        defaultBuckets(),
		BulkThreshold:  8192,
		IdleAfter:      Duration(20 * time.Second),
		IdleClose:      DurationRange{Min: Duration(45 * time.Second), Max: Duration(120 * time.Second)},
		IdleReopen:     DurationRange{Min: Duration(20 * time.Second), Max: Duration(50 * time.Second)},
		KeepaliveDelay: DurationRange{Min: 0, Max: Duration(2 * time.Second)},
		IdleSizes:      []int{48, 64, 80, 96, 128},
	}
}

// defaultBuckets are the built-in profile's buckets: 16 bytes apart up to
// 256, and 32 apart from there to a full record.
//
// WireGuard's packets come in sizes 16 bytes apart, with its handshake
// messages in between, so a band 16 bytes wide that holds a handshake also
// holds a data packet. Larger records are full-size packets, alone or
// several together, whose sizes need no hiding. There the band has only to
// be wide enough that record lengths do not fall on multiples of a
// packet's size, and narrow enough to cost little: a record takes about a
// band's width of padding on average, which is 2% of one full-size packet
// and 0.3% of a record of eight.
func defaultBuckets() []int {
	var b []int
	size := 0
	for _, s := range []struct{ upTo, step int }{{256, 16}, {MaxRecord, 32}} {
		for size < s.upTo {
			size += s.step
			b = append(b, size)
		}
	}
	return b
}

// Parse decodes and validates a JSON profile.
func Parse(data []byte) (*Profile, error) {
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks that the profile can be used.
func (p *Profile) Validate() error {
	if err := p.validateFirstFlight(); err != nil {
		return err
	}
	if len(p.Buckets) == 0 {
		return errors.New("shape: buckets must not be empty")
	}
	if !ascending(p.Buckets) {
		return errors.New("shape: buckets must be ascending, positive and at most 16384")
	}
	if len(p.IdleSizes) == 0 || !ascending(p.IdleSizes) {
		return errors.New("shape: idle_sizes must be ascending, positive and at most 16384")
	}
	if p.BulkThreshold <= 0 {
		return errors.New("shape: bulk_threshold must be positive")
	}
	if p.IdleAfter <= 0 {
		return errors.New("shape: idle_after must be positive")
	}
	for name, r := range map[string]DurationRange{
		"idle_close": p.IdleClose, "idle_reopen": p.IdleReopen, "keepalive_delay": p.KeepaliveDelay,
	} {
		if r.Min < 0 || r.Max < r.Min {
			return fmt.Errorf("shape: %s range invalid", name)
		}
	}
	if p.IdleClose.Min <= 0 || p.IdleReopen.Min <= 0 {
		return errors.New("shape: idle_close and idle_reopen must be positive")
	}
	return nil
}

func ascending(s []int) bool {
	return slices.IsSorted(s) && s[0] > 0 && s[len(s)-1] <= MaxRecord &&
		len(slices.Compact(slices.Clone(s))) == len(s)
}

// Set is a collection of profiles indexed by ID. The built-in default is
// always present unless replaced by a profile with the same ID.
type Set struct {
	m map[uint16]*Profile
}

// NewSet validates profiles and returns a Set holding them and the default.
func NewSet(profiles ...*Profile) (*Set, error) {
	s := &Set{m: map[uint16]*Profile{DefaultID: Default()}}
	for _, p := range profiles {
		if p == nil {
			continue
		}
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("profile %d: %w", p.ID, err)
		}
		s.m[p.ID] = p
	}
	return s, nil
}

// Get returns the profile with the given ID, or the default profile if the
// set doesn't have it.
func (s *Set) Get(id uint16) *Profile {
	if s != nil {
		if p, ok := s.m[id]; ok {
			return p
		}
		if p, ok := s.m[DefaultID]; ok {
			return p
		}
	}
	return Default()
}

// Has reports whether the set holds a profile with the given ID.
func (s *Set) Has(id uint16) bool {
	if s == nil {
		return id == DefaultID
	}
	_, ok := s.m[id]
	return ok
}
