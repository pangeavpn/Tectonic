package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/pangeavpn/tectonic/shape"
)

// A lane's opening from the server is the records the cover web server opens
// an HTTP/2 connection with for Chrome loading its front page: after its
// SETTINGS, a WINDOW_UPDATE, the acknowledgement of Chrome's SETTINGS, the
// response's HEADERS and its DATA. Those records are the server's whole
// first flight to anyone who loads the site, and a lane that opened with
// records of other sizes would be told apart from a visitor by them alone.
// So the node asks its own web server for the page, the way Chrome would,
// and copies the sizes of what comes back (learnOpening). It does that at
// start and again now and then, since the page can change.

// relearnOpening is how often the node asks its web server again.
const relearnOpening = 10 * time.Minute

// maxOpening is the most a learned opening may send. A cover page larger
// than this would cost every lane as much again; lanes then open with the
// profile's records instead.
const maxOpening = 64 << 10

var errNoOpening = errors.New("server: the cover web server did not answer a rehearsed page load")

// chromeOpening is what Chrome sends first on an HTTP/2 connection when it
// loads https://authority/, in the two TLS records it sends it in: the
// preface with its SETTINGS and WINDOW_UPDATE, then the request.
func chromeOpening(authority string) [2][]byte {
	b := []byte(h2Preface)
	frame := func(typ, flags byte, stream uint32, payload []byte) {
		var h [9]byte
		h[0], h[1], h[2] = byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload))
		h[3], h[4] = typ, flags
		binary.BigEndian.PutUint32(h[5:], stream)
		b = append(append(b, h[:]...), payload...)
	}
	var settings []byte
	for _, s := range [][2]uint32{{0x1, 65536}, {0x2, 0}, {0x4, 6291456}, {0x6, 262144}} {
		settings = binary.BigEndian.AppendUint16(settings, uint16(s[0]))
		settings = binary.BigEndian.AppendUint32(settings, s[1])
	}
	frame(0x4, 0, 0, settings)
	frame(0x8, 0, 0, binary.BigEndian.AppendUint32(nil, 15663105))
	first := b
	b = nil

	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{
		{":method", "GET"}, {":authority", authority}, {":scheme", "https"}, {":path", "/"},
		{"sec-ch-ua", `"Chromium";v="157", "Not?A_Brand";v="8"`},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", `"Windows"`},
		{"upgrade-insecure-requests", "1"},
		{"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"sec-fetch-dest", "document"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", "en-US,en;q=0.9"},
		{"priority", "u=0, i"},
	} {
		enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	// END_STREAM, END_HEADERS and PRIORITY: exclusive on stream 0, weight 256.
	payload := append([]byte{0x80, 0, 0, 0, 255}, hb.Bytes()...)
	frame(0x1, 0x1|0x4|0x20, 1, payload)
	return [2][]byte{first, b}
}

// learned is one rehearsed page load: a profile whose server_first_flight
// is that load's records, and what a lane opening like it must adjust.
type learned struct {
	p *shape.Profile
	// headers is the index of the record holding the response's HEADERS,
	// or -1, and date the length its Date header was coded to there. Date
	// is Huffman-coded, so its length moves with the time of day (22 or 23
	// bytes): a lane opening in another second than the rehearsal gets the
	// length a visitor in its own second would.
	headers, date int
	// merged is whether the web server sent its WINDOW_UPDATE and its
	// acknowledgement of Chrome's SETTINGS in one record.
	merged bool
}

// at returns the profile for a lane opening at now: l.p, with the HEADERS
// record the size it has in a response written now.
func (l *learned) at(now time.Time) *shape.Profile {
	if l.headers < 0 {
		return l.p
	}
	d := dateLen(now) - l.date
	if d == 0 {
		return l.p
	}
	p := *l.p
	p.ServerFirstFlight = slices.Clone(l.p.ServerFirstFlight)
	r := &p.ServerFirstFlight[l.headers]
	r.Min, r.Max = r.Min+d, r.Max+d
	return &p
}

// dateLen is how long HPACK codes the Date header net/http writes at t:
// Huffman-coded when that is shorter, as Go's encoder does.
func dateLen(t time.Time) int {
	return hpackLen(t.UTC().Format(http.TimeFormat))
}

func hpackLen(s string) int {
	return int(min(hpack.HuffmanEncodeLength(s), uint64(len(s))))
}

// rehearseOpening asks the web server for its front page as Chrome would
// and returns the sizes of the records it writes after its SETTINGS frame,
// as a profile's server_first_flight, with the HEADERS record's place.
func (c *cover) rehearseOpening(authority string) (*learned, error) {
	if !c.direct {
		return nil, errors.New("server: built with Go before 1.27, the opening cannot be copied")
	}
	open := chromeOpening(authority)
	rc := &rehearsal{chunks: open[:], wrote: make(chan []byte, 64), done: make(chan struct{})}
	defer rc.Close()
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	select {
	case c.in[0].ch <- rc:
	case <-t.C:
		return nil, errNoOpening
	}
	l := &learned{headers: -1}
	var out []shape.IntRange
	total := 0
	first := true
	for {
		var w []byte
		select {
		case w = <-rc.wrote:
		case <-t.C:
			return nil, errNoOpening
		}
		if first {
			first = false
			if !isSettings(w) {
				return nil, errOpening
			}
			continue
		}
		f, err := scanFrames(w)
		if err != nil {
			return nil, err
		}
		if f.headers && f.date >= 0 && len(w) <= shape.MaxRecord {
			l.headers, l.date = len(out), f.date
		}
		l.merged = l.merged || f.windowUpdate && f.settingsAck
		for rest := len(w); rest > 0; {
			n := min(rest, shape.MaxRecord)
			out = append(out, shape.IntRange{Min: n, Max: n})
			rest -= n
		}
		total += len(w)
		if len(out) > shape.MaxFirstFlight || total > maxOpening {
			return nil, fmt.Errorf("server: the cover page opens with more than %d records or %d bytes", shape.MaxFirstFlight, maxOpening)
		}
		if f.end {
			p := *c.s.profile
			p.ServerFirstFlight = out
			l.p = &p
			return l, nil
		}
	}
}

// frames is what one write of the web server's holds.
type frames struct {
	headers      bool // a HEADERS frame
	end          bool // the end of the response on stream 1
	windowUpdate bool // a WINDOW_UPDATE for the connection
	settingsAck  bool // the acknowledgement of the client's SETTINGS
	// date is how long the Date header in the HEADERS frame was coded to,
	// or -1.
	date int
}

// scanFrames reads the frames in b, one write of the web server's.
func scanFrames(b []byte) (frames, error) {
	f := frames{date: -1}
	for len(b) > 0 {
		if len(b) < 9 {
			return f, errors.New("server: the web server wrote part of a frame")
		}
		n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		typ, flags, stream := b[3], b[4], binary.BigEndian.Uint32(b[5:])&0x7fffffff
		if len(b) < 9+n {
			return f, errors.New("server: the web server wrote part of a frame")
		}
		switch {
		case typ == 0x1:
			f.headers = true
			if d, ok := headerDate(flags, b[9:9+n]); ok {
				f.date = d
			}
		case typ == 0x8 && stream == 0:
			f.windowUpdate = true
		case typ == 0x4 && flags&0x1 != 0:
			f.settingsAck = true
		}
		if stream == 1 && (typ == 0x0 || typ == 0x1) && flags&0x1 != 0 {
			f.end = true
		}
		b = b[9+n:]
	}
	return f, nil
}

// headerDate returns how long the Date header in a HEADERS frame's payload
// was coded to. The rehearsal is the first response on its connection, so
// the block decodes with a fresh table.
func headerDate(flags byte, payload []byte) (int, bool) {
	const padded, endHeaders, priority = 0x8, 0x4, 0x20
	if flags&endHeaders == 0 {
		return 0, false // the block goes on in a CONTINUATION frame
	}
	if flags&padded != 0 {
		if len(payload) < 1 || int(payload[0]) > len(payload)-1 {
			return 0, false
		}
		payload = payload[1 : len(payload)-int(payload[0])]
	}
	if flags&priority != 0 {
		if len(payload) < 5 {
			return 0, false
		}
		payload = payload[5:]
	}
	fields, err := hpack.NewDecoder(4096, nil).DecodeFull(payload)
	if err != nil {
		return 0, false
	}
	for _, hf := range fields {
		if hf.Name == "date" {
			return hpackLen(hf.Value), true
		}
	}
	return 0, false
}

// rehearsals is how many times learnOpening asks the web server. How it
// groups its frames into records depends on how its goroutines happen to
// run, so one page load comes out as four records, another as two; each
// lane opens like one of these loads, drawn at random, so lanes vary as
// much as visitors do.
const rehearsals = 16

// learnOpening sets the profiles lanes open with to the server's own, each
// with the records of one rehearsed page load. When it can't learn them,
// lanes keep the profile's.
//
// Loads whose WINDOW_UPDATE and SETTINGS acknowledgement share a record are
// left out while any other load is left. The rehearsal hands the web
// server Chrome's records the moment it reads, so it sometimes answers
// both in one write, but Chrome loading the page over a real network got
// them in two records every time (19 of 19 loads at 80 ms), and lanes
// carrying that merged record stood out (48% of them).
func (s *Server) learnOpening() {
	authority := strings.TrimPrefix(s.cfg.CoverDomain, "*.")
	if authority == "" {
		authority = "localhost"
	}
	var all []*learned
	var err error
	for range rehearsals {
		var l *learned
		if l, err = s.cover.rehearseOpening(authority); err != nil {
			break
		}
		if err = l.p.Validate(); err != nil {
			break
		}
		all = append(all, l)
	}
	if err != nil {
		if s.laneProfiles.Load() == nil {
			s.log.Warn("lanes open with the shaping profile's records, not the cover web server's", "err", err)
		}
		return
	}
	ls := chooseOpenings(all)
	seen := map[string]bool{}
	for _, l := range ls {
		seen[fmt.Sprint(l.p.ServerFirstFlight)] = true
	}
	variants := make([]string, 0, len(seen))
	for v := range seen {
		variants = append(variants, v)
	}
	sort.Strings(variants)
	msg := "lanes open with the records the cover web server opens with"
	args := []any{"variants", strings.Join(variants, " "), "loads", len(ls), "of", len(all)}
	if old := s.laneProfiles.Swap(&ls); old == nil {
		s.log.Info(msg, args...)
	} else {
		s.log.Debug(msg, args...)
	}
}

// chooseOpenings returns the loads lanes open like: those that sent the
// WINDOW_UPDATE and the SETTINGS acknowledgement in records of their own,
// or all of them if none did.
func chooseOpenings(all []*learned) []*learned {
	var split []*learned
	for _, l := range all {
		if !l.merged {
			split = append(split, l)
		}
	}
	if len(split) == 0 {
		return all
	}
	return split
}

// lanePlannerProfile is the profile a new server lane is shaped with.
func (s *Server) lanePlannerProfile() *shape.Profile {
	if ls := s.laneProfiles.Load(); ls != nil && len(*ls) > 0 {
		return (*ls)[rand.IntN(len(*ls))].at(time.Now())
	}
	return s.profile
}
