package server

import (
	"context"
	"io"
	"net"
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
	ps := ts.laneProfiles.Load()
	if ps == nil || len(*ps) != rehearsals {
		t.Fatal("no openings learned")
	}
	page := sum(visit(t, ts))
	for _, p := range *ps {
		lo, hi := 0, 0
		for _, r := range p.ServerFirstFlight {
			lo, hi = lo+r.Min, hi+r.Max
		}
		if page < lo || page > hi {
			t.Fatalf("learned opening %v holds %d to %d bytes; a visitor got %d", p.ServerFirstFlight, lo, hi, page)
		}
	}

	for range 8 {
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
		ok := false
		for _, p := range *ps {
			ok = ok || within(got, p.ServerFirstFlight)
		}
		if !ok {
			t.Fatalf("lane opened with %v, none of the learned openings", got)
		}
		c.l.Close()
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
