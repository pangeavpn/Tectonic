package server

import (
	"context"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/shape"
)

// tlsRecords splits a TLS stream into record lengths.
func tlsRecords(b []byte) []int {
	var out []int
	for len(b) >= 5 {
		n := int(b[3])<<8 | int(b[4])
		if len(b) < 5+n {
			break
		}
		out = append(out, n)
		b = b[5+n:]
	}
	return out
}

// afterSettings returns the record lengths that follow the first record of
// length mark, the web server's SETTINGS frame.
func afterSettings(t *testing.T, recs []int, mark int) []int {
	t.Helper()
	for i, n := range recs {
		if n == mark {
			return recs[i+1:]
		}
	}
	t.Fatalf("no SETTINGS record (%d bytes) in %v", mark, recs)
	return nil
}

const tlsOverhead = 1 + 16 // TLS 1.3: content type and AEAD tag

// visit loads the front page the way Chrome opens a connection and returns
// the payload sizes of the records the server sent after its SETTINGS.
func visit(t *testing.T, ts *testServer) []int {
	t.Helper()
	v := probeDial(t, ts.addr, 0, "h2")
	open := chromeOpening(coverDomain)
	v.Write(open[0])
	v.Write(open[1])
	v.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		f, err := readFrame(v)
		if err != nil {
			t.Fatal(err)
		}
		if f[3] == 0x0 && f[4]&0x1 != 0 { // DATA with END_STREAM
			break
		}
	}
	v.tap.mu.Lock()
	defer v.tap.mu.Unlock()
	var out []int
	for _, n := range afterSettings(t, tlsRecords(v.tap.in), len(ts.cover.opening)+tlsOverhead) {
		out = append(out, n-tlsOverhead)
	}
	return out
}

func sum(s []int) int {
	t := 0
	for _, n := range s {
		t += n
	}
	return t
}

func within(sizes []int, ff []shape.IntRange) bool {
	if len(sizes) < len(ff) {
		return false
	}
	for i, r := range ff {
		if sizes[i] < r.Min || sizes[i] > r.Max {
			return false
		}
	}
	return true
}

// A lane opens, from the server, with the records the cover web server
// sends Chrome loading the front page: the same bytes, grouped into records
// the way one of the web server's own page loads groups them.
func TestLaneOpensWithTheCoverPagesRecords(t *testing.T) {
	ts := newServerAs(t, true, nil)
	ls := ts.laneProfiles.Load()
	if ls == nil || len(*ls) == 0 || len(*ls) > rehearsals {
		t.Fatal("no openings learned")
	}
	page := sum(visit(t, ts))
	for _, l := range *ls {
		ff := l.at(time.Now()).ServerFirstFlight
		lo, hi := 0, 0
		for _, r := range ff {
			lo, hi = lo+r.Min, hi+r.Max
		}
		if page < lo || page > hi {
			t.Fatalf("learned opening %v holds %d to %d bytes; a visitor got %d", ff, lo, hi, page)
		}
	}

	for range 8 {
		got := laneOpening(t, ts)
		ok := false
		for _, l := range *ls {
			ok = ok || within(got, l.at(time.Now()).ServerFirstFlight)
		}
		if !ok {
			t.Fatalf("lane opened with %v, none of the learned openings", got)
		}
	}
}

// laneOpening opens a lane and returns the payload sizes of the records the
// server sent it after its SETTINGS.
func laneOpening(t *testing.T, ts *testServer) []int {
	t.Helper()
	var tap *tapConn
	cfg := ts.dialCfg(t)
	cfg.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err == nil {
			tap = &tapConn{Conn: c}
			return tap, nil
		}
		return nil, err
	}
	c := dial(t, cfg)
	c.welcome(t)
	time.Sleep(20 * time.Millisecond)
	tap.mu.Lock()
	var got []int
	for _, n := range afterSettings(t, tlsRecords(tap.in), len(ts.cover.opening)+tlsOverhead) {
		got = append(got, n-tlsOverhead)
	}
	tap.mu.Unlock()
	c.l.Close()
	return got
}

// A lane's opening holds as many bytes as a visitor's page load in the same
// second: its HEADERS record has the length the Date header has then, not
// a byte more or less, which no visitor ever gets.
func TestLaneOpeningIsTheLengthAVisitorGetsNow(t *testing.T) {
	ts := newServerAs(t, true, nil)
	ls := *ts.laneProfiles.Load()
	for _, l := range ls {
		if l.headers < 0 || l.date < 20 || l.date > 29 {
			t.Fatalf("learned opening %v: HEADERS record %d, Date coded to %d bytes", l.p.ServerFirstFlight, l.headers, l.date)
		}
	}
	for i := 0; i < 30; i++ {
		before := dateLen(time.Now())
		page := sum(visit(t, ts))
		got := laneOpening(t, ts)
		if dateLen(time.Now()) != before {
			i-- // the Date header's length changed in between; measure again
			continue
		}
		matched := false
		for _, l := range ls {
			ff := l.at(time.Now()).ServerFirstFlight
			if len(got) < len(ff) {
				continue
			}
			exact := true
			for j, r := range ff {
				exact = exact && r.Min == r.Max && got[j] == r.Min
			}
			if exact {
				matched = true
				if n := sum(got[:len(ff)]); n != page {
					t.Fatalf("lane %d opened with %v (%d bytes); a visitor got %d bytes", i, got[:len(ff)], n, page)
				}
			}
		}
		if !matched {
			t.Fatalf("lane %d opened with %v, none of the learned openings", i, got)
		}
	}
}

// A learned opening moves its HEADERS record with the Date header's length,
// and only that record.
func TestLearnedOpeningFollowsTheDate(t *testing.T) {
	// The length moves by the second, and on some days not at all.
	t0 := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	var t1 time.Time
	for s := range 3 * 86400 {
		if tm := t0.Add(time.Duration(s) * time.Second); dateLen(tm) != dateLen(t0) {
			t1 = tm
			break
		}
	}
	if t1.IsZero() {
		t.Fatal("the Date header codes to one length for three days")
	}
	p := *shape.Default()
	p.ServerFirstFlight = []shape.IntRange{{Min: 13, Max: 13}, {Min: 9, Max: 9}, {Min: 92, Max: 92}, {Min: 638, Max: 638}}
	l := &learned{p: &p, headers: 2, date: dateLen(t0)}
	if got := l.at(t0); got != l.p {
		t.Fatal("a lane in the rehearsal's second got another profile")
	}
	got := l.at(t1).ServerFirstFlight
	d := dateLen(t1) - dateLen(t0)
	want := []shape.IntRange{{Min: 13, Max: 13}, {Min: 9, Max: 9}, {Min: 92 + d, Max: 92 + d}, {Min: 638, Max: 638}}
	if !slices.Equal(got, want) {
		t.Fatalf("at %v: %v, want %v", t1, got, want)
	}
	if p.ServerFirstFlight[2] != (shape.IntRange{Min: 92, Max: 92}) {
		t.Fatal("the learned profile itself was changed")
	}
}

// Loads whose WINDOW_UPDATE and SETTINGS acknowledgement share a record are
// not used while another load is there; when every load merged them, all
// are used.
func TestOpeningsKeepWindowUpdateAndAckApart(t *testing.T) {
	split, merged := &learned{}, &learned{merged: true}
	if got := chooseOpenings([]*learned{merged, split, merged}); !slices.Equal(got, []*learned{split}) {
		t.Fatalf("chose %v", got)
	}
	if got := chooseOpenings([]*learned{merged, merged}); len(got) != 2 {
		t.Fatalf("with every load merged, chose %d", len(got))
	}
	ts := newServerAs(t, true, nil)
	ls := *ts.laneProfiles.Load()
	some := false
	for _, l := range ls {
		some = some || !l.merged
	}
	for _, l := range ls {
		if l.merged && some {
			t.Fatalf("a merged load (%v) is used beside split ones", l.p.ServerFirstFlight)
		}
	}
}

// What Chrome sends is a valid opening the web server answers with the page.
func TestChromeOpeningGetsThePage(t *testing.T) {
	ts := newServerAs(t, true, nil)
	v := probeDial(t, ts.addr, 0, "h2")
	open := chromeOpening(coverDomain)
	v.Write(append(append([]byte(nil), open[0]...), open[1]...))
	v.SetReadDeadline(time.Now().Add(5 * time.Second))
	var body []byte
	for {
		f, err := readFrame(v)
		if err == io.EOF {
			t.Fatal("closed before the page")
		} else if err != nil {
			t.Fatal(err)
		}
		if f[3] == 0x0 {
			body = append(body, f[9:]...)
			if f[4]&0x1 != 0 {
				break
			}
		}
	}
	if string(body) != "cover page HTTP/2.0 tls=true" {
		t.Fatalf("page = %q", body)
	}
}
