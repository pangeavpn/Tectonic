package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
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

// rehearseOpening asks the web server for its front page as Chrome would
// and returns the sizes of the records it writes after its SETTINGS frame,
// as a profile's server_first_flight. A record holding HEADERS may be a
// byte longer or shorter: the Date header it carries is Huffman-coded, and
// its length moves with the time of day.
func (c *cover) rehearseOpening(authority string) ([]shape.IntRange, error) {
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
		headers, end, err := scanFrames(w)
		if err != nil {
			return nil, err
		}
		for rest := len(w); rest > 0; {
			n := min(rest, shape.MaxRecord)
			r := shape.IntRange{Min: n, Max: n}
			if headers && n == len(w) {
				r = shape.IntRange{Min: max(n-1, 3), Max: min(n+1, shape.MaxRecord)}
			}
			out = append(out, r)
			rest -= n
		}
		total += len(w)
		if len(out) > shape.MaxFirstFlight || total > maxOpening {
			return nil, fmt.Errorf("server: the cover page opens with more than %d records or %d bytes", shape.MaxFirstFlight, maxOpening)
		}
		if end {
			return out, nil
		}
	}
}

// scanFrames reports whether b, one write of the web server's, holds a
// HEADERS frame, and whether it ends the response on stream 1.
func scanFrames(b []byte) (headers, end bool, err error) {
	for len(b) > 0 {
		if len(b) < 9 {
			return false, false, errors.New("server: the web server wrote part of a frame")
		}
		n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		typ, flags, stream := b[3], b[4], binary.BigEndian.Uint32(b[5:])&0x7fffffff
		if len(b) < 9+n {
			return false, false, errors.New("server: the web server wrote part of a frame")
		}
		if typ == 0x1 {
			headers = true
		}
		if stream == 1 && (typ == 0x0 || typ == 0x1) && flags&0x1 != 0 {
			end = true
		}
		b = b[9+n:]
	}
	return headers, end, nil
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
func (s *Server) learnOpening() {
	authority := strings.TrimPrefix(s.cfg.CoverDomain, "*.")
	if authority == "" {
		authority = "localhost"
	}
	var ps []*shape.Profile
	var err error
	seen := map[string]bool{}
	for range rehearsals {
		var ff []shape.IntRange
		if ff, err = s.cover.rehearseOpening(authority); err != nil {
			break
		}
		p := *s.profile
		p.ServerFirstFlight = ff
		if err = p.Validate(); err != nil {
			break
		}
		ps = append(ps, &p)
		seen[fmt.Sprint(ff)] = true
	}
	if err != nil {
		if s.laneProfiles.Load() == nil {
			s.log.Warn("lanes open with the shaping profile's records, not the cover web server's", "err", err)
		}
		return
	}
	variants := make([]string, 0, len(seen))
	for v := range seen {
		variants = append(variants, v)
	}
	sort.Strings(variants)
	msg := "lanes open with the records the cover web server opens with"
	if old := s.laneProfiles.Swap(&ps); old == nil {
		s.log.Info(msg, "variants", strings.Join(variants, " "))
	} else {
		s.log.Debug(msg, "variants", strings.Join(variants, " "))
	}
}

// lanePlannerProfile is the profile a new server lane is shaped with.
func (s *Server) lanePlannerProfile() *shape.Profile {
	if ps := s.laneProfiles.Load(); ps != nil && len(*ps) > 0 {
		return (*ps)[rand.IntN(len(*ps))]
	}
	return s.profile
}
