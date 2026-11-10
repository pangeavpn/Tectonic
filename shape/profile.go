// Package shape holds Tectonic's shaping profiles and record-size planning.
//
// TLS hides what is inside the traffic, but WireGuard still has a shape:
// 148- and 92-byte handshakes, a 32-byte keepalive on a timer, and MTU-sized
// data. Shaping changes only what an observer can measure from outside: TLS
// record sizes and their timing (design §8).
//
//	Bulk transfer  records packed up to 16 KB, no padding
//	Interactive    record sizes rounded up to the profile's buckets
//	Lane start     first flight padded to look like Chrome loading a page over HTTP/2
//	Idle           keepalives delayed and padded like browser idle traffic; the
//	               lane closes after a while and a fresh one opens later
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

// DefaultID is the ID of the built-in profile. A client that doesn't know the
// profile a WELCOME names falls back to it.
const DefaultID = 0

// Profile describes how a session's traffic should look.
type Profile struct {
	ID   uint16 `json:"id"`
	Name string `json:"name"`

	// Lane start: the first flight in each direction (all frames in the
	// first record) is padded to a size drawn uniformly from these ranges.
	ClientFirstFlight IntRange `json:"client_first_flight"`
	ServerFirstFlight IntRange `json:"server_first_flight"`

	// Interactive: a record's size is rounded up to the next bucket.
	// Ascending, each at most MaxRecord.
	Buckets []int `json:"buckets"`

	// Bulk: when at least this many bytes are waiting, records are packed
	// up to MaxRecord and not padded, because a download already looks like
	// a download.
	BulkThreshold int `json:"bulk_threshold"`

	// Idle: the tunnel is idle once nothing but WireGuard keepalives has
	// moved for IdleAfter. The pool then shrinks to one lane, which closes
	// after IdleClose more. With no lane open, held keepalives wait
	// IdleReopen before a fresh lane carries them; any other traffic opens a
	// lane at once.
	IdleAfter  Duration      `json:"idle_after"`
	IdleClose  DurationRange `json:"idle_close"`
	IdleReopen DurationRange `json:"idle_reopen"`

	// KeepaliveDelay is the random delay added to keepalives on an idle
	// lane, so they don't tick on WireGuard's fixed timer.
	KeepaliveDelay DurationRange `json:"keepalive_delay"`
	// IdleSizes are the record sizes for keepalive-only records on an idle
	// lane; one at least as large as the content is drawn at random.
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
		// Chrome's first HTTP/2 flight: connection preface, SETTINGS,
		// WINDOW_UPDATE and the HEADERS of the first GET.
		ClientFirstFlight: IntRange{Min: 380, Max: 620},
		// A server's reply: SETTINGS, WINDOW_UPDATE, response HEADERS and
		// the start of the page.
		ServerFirstFlight: IntRange{Min: 1200, Max: 4200},
		Buckets: []int{
			64, 128, 192, 256, 384, 512, 768, 1024, 1536,
			2048, 3072, 4096, 6144, 8192, 12288, MaxRecord,
		},
		BulkThreshold:  8192,
		IdleAfter:      Duration(20 * time.Second),
		IdleClose:      DurationRange{Min: Duration(45 * time.Second), Max: Duration(120 * time.Second)},
		IdleReopen:     DurationRange{Min: Duration(20 * time.Second), Max: Duration(50 * time.Second)},
		KeepaliveDelay: DurationRange{Min: 0, Max: Duration(2 * time.Second)},
		IdleSizes:      []int{48, 64, 80, 96, 128},
	}
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
	check := func(name string, r IntRange) error {
		if r.Min < 0 || r.Max < r.Min || r.Max > MaxRecord {
			return fmt.Errorf("shape: %s range [%d, %d] invalid", name, r.Min, r.Max)
		}
		return nil
	}
	if err := check("client_first_flight", p.ClientFirstFlight); err != nil {
		return err
	}
	if err := check("server_first_flight", p.ServerFirstFlight); err != nil {
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
