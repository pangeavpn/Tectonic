package shape

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pangeavpn/tectonic/wire"
)

// recordOverhead is what TLS 1.3 adds to a record's length on the wire: the
// content-type byte and the tag.
const recordOverhead = 17

// What a lane's opening holds: HELLO, the DATA frame of a WireGuard
// handshake initiation, a PING, WELCOME.
const (
	helloFrame   = wire.HeaderLen + wire.HelloLen
	initFrame    = wire.HeaderLen + 148
	pingFrame    = wire.HeaderLen + wire.PingLen
	welcomeFrame = wire.HeaderLen + wire.WelcomeLen
)

func sum(sizes []int) int {
	n := 0
	for _, s := range sizes {
		n += s
	}
	return n
}

// The default profile's opening is the one measured from a Chromium browser
// loading a page over HTTP/2, in record lengths on the wire: the client's
// 87, then 460 to 470, then 26 once the server has spoken; the server's 39,
// then 108 to 109, then the page.
func TestDefaultFirstFlightIsTheMeasuredOne(t *testing.T) {
	pl := NewPlanner(nil)
	for range 500 {
		c := pl.FirstFlight(true, helloFrame+initFrame)
		if len(c) != 2 || c[0]+recordOverhead != 87 || c[1]+recordOverhead < 460 || c[1]+recordOverhead > 470 {
			t.Fatalf("client first flight %v", c)
		}
		if ack := pl.FirstFlightAck(); ack+recordOverhead != 26 {
			t.Fatalf("client ack %d", ack)
		}
		s := pl.FirstFlight(false, welcomeFrame)
		if len(s) != 3 || s[0]+recordOverhead != 39 || s[1]+recordOverhead < 108 || s[1]+recordOverhead > 109 {
			t.Fatalf("server first flight %v", s)
		}
		if s[2] < 1090 || s[2] > 4090+wire.HeaderLen {
			t.Fatalf("server first flight %v", s)
		}
	}
}

// What a lane pays once to open stays about where it was when each side
// padded a single record: 380 to 620 bytes from the client and 1200 to 4200
// from the server, 500 and 2700 on average. The size of the page is what
// sets it.
func TestDefaultFirstFlightCostsWhatItDid(t *testing.T) {
	mean := func(ranges ...IntRange) (m float64) {
		for _, r := range ranges {
			m += float64(r.Min+r.Max) / 2
		}
		return m
	}
	p := Default()
	if got := mean(p.ClientFirstFlight...) + mean(p.ClientAck); got < 450 || got > 550 {
		t.Errorf("a client's opening averages %.0f bytes, want about 500", got)
	}
	if got := mean(p.ServerFirstFlight...); got < 2430 || got > 2970 {
		t.Errorf("a server's opening averages %.0f bytes, want about 2700", got)
	}
}

// Whatever the opening's frames add up to, the records hold them and an
// amount of padding that PAD frames can make exactly, and only the last
// record moves to make that so.
func TestFirstFlightHoldsTheFrames(t *testing.T) {
	pl := NewPlanner(nil)
	p := pl.Profile()
	for _, tc := range []struct {
		client bool
		ranges []IntRange
	}{{true, p.ClientFirstFlight}, {false, p.ServerFirstFlight}} {
		last := len(tc.ranges) - 1
		room := 0 // what the flight holds at the least
		for _, r := range tc.ranges {
			room += r.Min
		}
		for size := 0; size <= 6000; size++ {
			sizes := pl.FirstFlight(tc.client, size)
			if len(sizes) != len(tc.ranges) {
				t.Fatalf("size %d: %d records, want %d", size, len(sizes), len(tc.ranges))
			}
			pad := sum(sizes) - size
			if pad < 0 || !wire.CanPad(pad) {
				t.Fatalf("size %d: records %v leave %d bytes to pad", size, sizes, pad)
			}
			for i, r := range tc.ranges[:last] {
				if sizes[i] < r.Min || sizes[i] > r.Max {
					t.Fatalf("size %d: record %d is %d bytes, outside [%d, %d]", size, i+1, sizes[i], r.Min, r.Max)
				}
			}
			r := tc.ranges[last]
			switch got := sizes[last]; {
			case size <= room:
				// It fits: the last record is in its range too, give or
				// take the frame header no smaller padding can be.
				if got < r.Min || got > r.Max+wire.HeaderLen {
					t.Fatalf("size %d: last record is %d bytes, outside [%d, %d]", size, got, r.Min, r.Max)
				}
			case got > r.Max+wire.HeaderLen && pad != 0:
				t.Fatalf("size %d: last record grew to %d bytes and was padded by %d", size, got, pad)
			}
		}
	}
}

// A WireGuard packet too large for the record drawn for it still leaves in
// the opening: the last record takes it whole.
func TestFirstFlightGrowsForALargeFirstPacket(t *testing.T) {
	pl := NewPlanner(nil)
	size := helloFrame + wire.HeaderLen + 1452 + pingFrame
	sizes := pl.FirstFlight(true, size)
	if len(sizes) != 2 || sizes[0] != 70 || sum(sizes) != size {
		t.Fatalf("records %v for an opening of %d bytes", sizes, size)
	}
}

func TestFirstFlightOfOneFixedRecord(t *testing.T) {
	p := Default()
	p.ServerFirstFlight = []IntRange{{Min: 2000, Max: 2000}}
	pl := NewPlanner(p)
	if got := pl.FirstFlight(false, welcomeFrame+pingFrame); len(got) != 1 || got[0] != 2000 {
		t.Fatalf("records %v, want [2000]", got)
	}
	// One and two bytes short of full can't be padded. A record with no
	// smaller size in its range runs a frame header over.
	if got := pl.FirstFlight(false, 1999); len(got) != 1 || got[0] != 2003 {
		t.Fatalf("records %v, want [2003]", got)
	}
	if got := pl.FirstFlight(false, 1998); len(got) != 1 || got[0] != 2003 {
		t.Fatalf("records %v, want [2003]", got)
	}
	// One that has holds exactly the frames, whatever size was drawn.
	p.ServerFirstFlight = []IntRange{{Min: 1990, Max: 2000}}
	for range 200 {
		if got := pl.FirstFlight(false, 1999); len(got) != 1 || got[0] != 1999 {
			t.Fatalf("records %v, want [1999]", got)
		}
	}
}

func TestFirstFlightAck(t *testing.T) {
	p := Default()
	p.ClientAck = IntRange{}
	if err := p.Validate(); err != nil {
		t.Fatalf("a profile without a client ack: %v", err)
	}
	if got := NewPlanner(p).FirstFlightAck(); got != 0 {
		t.Fatalf("ack of %d bytes from a profile with none", got)
	}
	p.ClientAck = IntRange{Min: 9, Max: 30}
	pl := NewPlanner(p)
	seen := map[int]bool{}
	for range 500 {
		n := pl.FirstFlightAck()
		if n < 9 || n > 30 {
			t.Fatalf("ack of %d bytes outside [9, 30]", n)
		}
		seen[n] = true
	}
	if len(seen) < 5 {
		t.Fatalf("ack sizes don't vary: %v", seen)
	}
}

func TestFirstFlightValidation(t *testing.T) {
	many := make([]IntRange, MaxFirstFlight+1)
	for i := range many {
		many[i] = IntRange{Min: 100, Max: 100}
	}
	for name, mod := range map[string]func(*Profile){
		"no client records":         func(p *Profile) { p.ClientFirstFlight = nil },
		"no server records":         func(p *Profile) { p.ServerFirstFlight = []IntRange{} },
		"too many records":          func(p *Profile) { p.ServerFirstFlight = many },
		"record under a frame":      func(p *Profile) { p.ClientFirstFlight = []IntRange{{Min: 70, Max: 70}, {Min: 2, Max: 9}} },
		"record range backwards":    func(p *Profile) { p.ServerFirstFlight = []IntRange{{Min: 22, Max: 22}, {Min: 92, Max: 91}} },
		"record over a TLS record":  func(p *Profile) { p.ServerFirstFlight = []IntRange{{Min: 22, Max: MaxRecord + 1}} },
		"ack under a frame":         func(p *Profile) { p.ClientAck = IntRange{Min: 1, Max: 9} },
		"ack range backwards":       func(p *Profile) { p.ClientAck = IntRange{Min: 9, Max: 8} },
		"ack with only a maximum":   func(p *Profile) { p.ClientAck = IntRange{Min: 0, Max: 9} },
		"ack over a TLS record":     func(p *Profile) { p.ClientAck = IntRange{Min: 9, Max: MaxRecord + 1} },
		"negative ack":              func(p *Profile) { p.ClientAck = IntRange{Min: -9, Max: -9} },
		"negative record":           func(p *Profile) { p.ClientFirstFlight = []IntRange{{Min: -70, Max: 70}} },
		"zero record among records": func(p *Profile) { p.ServerFirstFlight = []IntRange{{Min: 22, Max: 22}, {}, {Min: 91, Max: 92}} },
		"first record cuts HELLO too short": func(p *Profile) {
			p.ClientFirstFlight = []IntRange{{Min: MinClientFirstRecord - 1, Max: 70}, {Min: 443, Max: 453}}
		},
		"only record cuts HELLO too short": func(p *Profile) {
			p.ClientFirstFlight = []IntRange{{Min: MinClientFirstRecord - 1, Max: 620}}
		},
	} {
		p := Default()
		mod(p)
		if p.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := Default()
	p.ServerFirstFlight = many[:MaxFirstFlight]
	p.ClientFirstFlight = []IntRange{{Min: MinClientFirstRecord, Max: MaxRecord}}
	if err := p.Validate(); err != nil {
		t.Fatalf("a flight at the limits: %v", err)
	}
	// The server's records hold no login and may be as small as a frame.
	p.ServerFirstFlight = []IntRange{{Min: wire.HeaderLen, Max: wire.HeaderLen}}
	if err := p.Validate(); err != nil {
		t.Fatalf("a server record of one frame header: %v", err)
	}
}

// The node tells a login from the first record it reads, which must hold
// HELLO's frame header, its fields and 16 bytes of its tag: 65 bytes. No
// profile that validates, and nothing the opening has to carry, makes a
// client's first record smaller.
func TestClientFirstRecordHoldsTheLogin(t *testing.T) {
	if MinClientFirstRecord != 65 {
		t.Fatalf("MinClientFirstRecord = %d, want 3 + 46 + 16", MinClientFirstRecord)
	}
	for name, flight := range map[string][]IntRange{
		"default":           Default().ClientFirstFlight,
		"smallest":          {{Min: MinClientFirstRecord, Max: MinClientFirstRecord}, {Min: 443, Max: 453}},
		"one record":        {{Min: MinClientFirstRecord, Max: MinClientFirstRecord + 2}},
		"one wide record":   {{Min: 380, Max: 620}},
		"three small ones":  {{Min: 65, Max: 66}, {Min: 3, Max: 4}, {Min: 3, Max: 5}},
		"the largest first": {{Min: 65, Max: MaxRecord}, {Min: 3, Max: 3}},
	} {
		p := Default()
		p.ClientFirstFlight = flight
		if err := p.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pl := NewPlanner(p)
		for size := 0; size <= 2000; size++ {
			sizes := pl.FirstFlight(true, size)
			if sizes[0] < MinClientFirstRecord {
				t.Fatalf("%s: for %d bytes of frames the first record is %d bytes: %v", name, size, sizes[0], sizes)
			}
			if pad := sum(sizes) - size; pad < 0 || !wire.CanPad(pad) {
				t.Fatalf("%s: for %d bytes of frames the records %v leave %d to pad", name, size, sizes, pad)
			}
		}
	}
}

func TestFirstFlightJSON(t *testing.T) {
	b, err := json.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"client_first_flight":[{"min":70,"max":70},{"min":443,"max":453}]`,
		`"client_ack":{"min":9,"max":9}`,
		`"server_first_flight":[{"min":22,"max":22},{"min":91,"max":92},{"min":1090,"max":4090}]`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the default profile's JSON lacks %s:\n%s", want, b)
		}
	}
	q, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.ClientFirstFlight) != 2 || q.ClientFirstFlight[1] != (IntRange{Min: 443, Max: 453}) ||
		len(q.ServerFirstFlight) != 3 || q.ServerFirstFlight[2] != (IntRange{Min: 1090, Max: 4090}) ||
		q.ClientAck != (IntRange{Min: 9, Max: 9}) {
		t.Fatalf("round trip changed the opening: %+v", q)
	}

	// A profile from before the opening was a list of records described
	// one padded record each way. It must be refused, not read as an
	// opening of no records.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	raw["client_first_flight"] = json.RawMessage(`{"min":380,"max":620}`)
	old, _ := json.Marshal(raw)
	if _, err := Parse(old); err == nil {
		t.Fatal("a single range accepted as a first flight")
	}
	delete(raw, "client_first_flight")
	none, _ := json.Marshal(raw)
	if _, err := Parse(none); err == nil {
		t.Fatal("a profile with no client first flight accepted")
	}
}

// A planner made from a profile that was never validated must still give
// the lane something it can write.
func TestFirstFlightWithoutRecords(t *testing.T) {
	pl := NewPlanner(&Profile{})
	if got := pl.FirstFlight(true, 232); len(got) != 1 || got[0] != 232 {
		t.Fatalf("records %v, want [232]", got)
	}
	if got := pl.FirstFlight(false, 0); len(got) != 0 {
		t.Fatalf("records %v for nothing to send", got)
	}
	if got := pl.FirstFlightAck(); got != 0 {
		t.Fatalf("ack of %d bytes", got)
	}
}
