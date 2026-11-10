package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The expected values were computed independently with Python's hmac and
// hashlib (HKDF written out per RFC 5869), so they pin the derivation in
// design §5 rather than whatever this package happens to do.
func TestKnownAnswers(t *testing.T) {
	nodeSecret := make([]byte, 32)
	for i := range nodeSecret {
		nodeSecret[i] = byte(i)
	}
	var id KeyID
	copy(id[:], mustHex(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00004e20"))
	if id.ExpiryDay() != 20000 {
		t.Fatalf("ExpiryDay = %d", id.ExpiryDay())
	}

	dk := DeviceKey(nodeSecret, id)
	if got, want := hex.EncodeToString(dk[:]), "18e289803058e26dbcf5bb2c8ea22d82fb4910e0acca0d3c2e53724563701ef2"; got != want {
		t.Fatalf("device_key = %s, want %s", got, want)
	}

	exporter := bytes.Repeat([]byte{0x55}, 32)
	lk := LaneKey(dk, exporter)
	if got, want := hex.EncodeToString(lk[:]), "e9e328c8176465ce5bde4004bd40d0e23905f9d2a39dcdd474501d72c3019ec2"; got != want {
		t.Fatalf("lane_key = %s, want %s", got, want)
	}

	h := Hello{Version: 1, Flags: FlagJoin, KeyID: id, Timestamp: 1767225600}
	copy(h.SessionID[:], bytes.Repeat([]byte{0x11}, 16))
	h.Sign(lk)
	want := "0101a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00004e2011111111111111111111111111111111000000006955b9004e03c7807a242895451d658a027eeacb4c085e24222533d8d5365311114f7097"
	if got := hex.EncodeToString(h.AppendBody(nil)); got != want {
		t.Fatalf("HELLO = %s\nwant    %s", got, want)
	}
	if !h.Verify(lk) {
		t.Fatal("Verify rejected a correctly signed HELLO")
	}
}

func TestHelloRoundTrip(t *testing.T) {
	id, err := NewKeyID(time.Now().Add(24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	h := Hello{Version: Version, Flags: FlagJoin | FlagCellular, KeyID: id, Timestamp: uint64(time.Now().Unix())}
	h.SessionID[3] = 9
	lk := LaneKey(DeviceKey([]byte("secret"), id), []byte("exporter"))
	h.Sign(lk)

	body := h.AppendBody(nil)
	if len(body) != HelloLen {
		t.Fatalf("len = %d, want %d", len(body), HelloLen)
	}
	got, err := ParseHello(body)
	if err != nil {
		t.Fatal(err)
	}
	if got != h {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, h)
	}
	if !got.Join() || !got.Cellular() {
		t.Fatal("flags lost")
	}
	if !got.Verify(lk) {
		t.Fatal("Verify failed after round trip")
	}

	// Every single-bit change to the signed fields or the tag must fail.
	for i := range body {
		mod := append([]byte(nil), body...)
		mod[i] ^= 0x04
		m, _ := ParseHello(mod)
		if m.Verify(lk) {
			t.Fatalf("Verify accepted a HELLO with byte %d changed", i)
		}
	}
	// A different exporter (another TLS connection) must fail.
	if got.Verify(LaneKey(DeviceKey([]byte("secret"), id), []byte("exporter2"))) {
		t.Fatal("HELLO verified under another connection's exporter")
	}
	if _, err := ParseHello(body[:77]); err != ErrHelloLength {
		t.Fatalf("short body: err = %v", err)
	}
	if _, err := ParseHello(append(body, 0)); err != ErrHelloLength {
		t.Fatalf("long body: err = %v", err)
	}
}

func TestTimestampWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		ts   uint64
		want bool
	}{
		{uint64(now.Unix()), true},
		{uint64(now.Unix() - 120), true},
		{uint64(now.Unix() + 120), true},
		{uint64(now.Unix() - 121), false},
		{uint64(now.Unix() + 121), false},
		{0, false},
		{^uint64(0), false},
		{1 << 63, false},
	} {
		h := Hello{Timestamp: tc.ts}
		if got := h.TimestampOK(now); got != tc.want {
			t.Errorf("TimestampOK(%d) = %v, want %v", tc.ts, got, tc.want)
		}
	}
}

func TestKeyIDExpiry(t *testing.T) {
	day := time.Date(2027, 3, 4, 15, 0, 0, 0, time.UTC)
	id, err := NewKeyID(day)
	if err != nil {
		t.Fatal(err)
	}
	if id.Expired(day) || id.Expired(time.Date(2027, 3, 4, 23, 59, 59, 0, time.UTC)) {
		t.Fatal("expired on its own expiry day")
	}
	if !id.Expired(time.Date(2027, 3, 5, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("not expired the day after")
	}
	back, err := ParseKeyID(id.String())
	if err != nil || back != id {
		t.Fatalf("ParseKeyID(String()) = %v, %v", back, err)
	}
	if _, err := ParseKeyID("abcd"); err == nil {
		t.Fatal("ParseKeyID accepted a short key_id")
	}
}

func TestWelcomeRoundTrip(t *testing.T) {
	w := Welcome{MaxLanes: 6, ResumeWindow: 60 * time.Second, Profile: 0x1234}
	w.SessionID[0] = 0xAB
	body := w.AppendBody(nil)
	if len(body) != WelcomeLen {
		t.Fatalf("len = %d", len(body))
	}
	got, err := ParseWelcome(body)
	if err != nil || got != w {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	// Trailing bytes from a newer server are ignored.
	got, err = ParseWelcome(append(body, 1, 2, 3))
	if err != nil || got != w {
		t.Fatalf("with extension: %+v, %v", got, err)
	}
	if _, err := ParseWelcome(body[:20]); err != ErrWelcomeLength {
		t.Fatalf("short: %v", err)
	}
}

func TestPingPong(t *testing.T) {
	tok := NewPingToken()
	ping := AppendPing(nil, tok)
	gotTok, pong, err := ParsePing(ping)
	if err != nil || pong || gotTok != tok {
		t.Fatalf("ping: %x %v %v", gotTok, pong, err)
	}
	gotTok, pong, err = ParsePing(AppendPong(nil, gotTok))
	if err != nil || !pong || gotTok != tok {
		t.Fatalf("pong: %x %v %v", gotTok, pong, err)
	}
	if _, _, err := ParsePing([]byte{1, 2, 3}); err == nil {
		t.Fatal("short PING accepted")
	}
}

func TestLost(t *testing.T) {
	want := Lost{Index: 0xA1B2C3D4, Counter: 1<<40 + 7, Count: 300}
	frame := AppendLost(nil, want)
	if len(frame) != HeaderLen+LostLen || frame[0] != TypeLost {
		t.Fatalf("LOST frame % x", frame)
	}
	got, err := ParseLost(frame[HeaderLen:])
	if err != nil || got != want {
		t.Fatalf("ParseLost = %+v, %v; want %+v", got, err, want)
	}
	// Fields appended by a later version are ignored.
	if got, err := ParseLost(append(frame[HeaderLen:], 1, 2, 3)); err != nil || got != want {
		t.Fatalf("ParseLost with a longer body = %+v, %v", got, err)
	}
	if _, err := ParseLost(frame[HeaderLen : HeaderLen+LostLen-1]); err == nil {
		t.Fatal("short LOST accepted")
	}
}

func TestFrames(t *testing.T) {
	var buf []byte
	buf = AppendFrame(buf, TypeData, []byte("packet"))
	buf = AppendPadding(buf, 10)
	buf = AppendFrame(buf, 0x7F, []byte("future frame type"))
	buf = AppendFrame(buf, TypeClose, []byte{byte(CloseShutdown)})
	buf = AppendFrame(buf, TypeRetire, nil)

	r := NewReader(bytes.NewReader(buf))
	want := []struct {
		typ  byte
		body string
	}{
		{TypeData, "packet"},
		{TypePad, "\x00\x00\x00\x00\x00\x00\x00"},
		{0x7F, "future frame type"},
		{TypeClose, "\x01"},
		{TypeRetire, ""},
	}
	for i, w := range want {
		typ, body, err := r.Next()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if typ != w.typ || string(body) != w.body {
			t.Fatalf("frame %d = %#x %q, want %#x %q", i, typ, body, w.typ, w.body)
		}
	}
	if _, _, err := r.Next(); err != io.EOF {
		t.Fatalf("end: %v, want EOF", err)
	}

	// Truncated inside a frame.
	r = NewReader(bytes.NewReader(buf[:5]))
	if _, _, err := r.Next(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated: %v", err)
	}
}

func TestPadding(t *testing.T) {
	for _, n := range []int{0, 3, 4, 100, MaxFrameLen, MaxFrameLen + 1, MaxFrameLen + 2, MaxFrameLen + 3, 3 * MaxFrameLen, 200000} {
		buf := AppendPadding(nil, n)
		if len(buf) != n {
			t.Fatalf("AppendPadding(%d) wrote %d bytes", n, len(buf))
		}
		r := NewReader(bytes.NewReader(buf))
		total := 0
		for {
			typ, body, err := r.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("n=%d: %v", n, err)
			}
			if typ != TypePad {
				t.Fatalf("n=%d: type %#x", n, typ)
			}
			total += HeaderLen + len(body)
		}
		if total != n {
			t.Fatalf("n=%d: frames add up to %d", n, total)
		}
	}
	for _, n := range []int{1, 2} {
		if CanPad(n) {
			t.Fatalf("CanPad(%d)", n)
		}
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("AppendPadding(%d) did not panic", n)
				}
			}()
			AppendPadding(nil, n)
		}()
	}
}

func TestCloseReason(t *testing.T) {
	if ParseClose(nil) != CloseNormal || ParseClose([]byte{2}) != CloseCredential {
		t.Fatal("ParseClose")
	}
	if CloseShutdown.String() != "shutdown" || CloseReason(99).String() != "unknown" {
		t.Fatal("String")
	}
}

func FuzzReader(f *testing.F) {
	f.Add(AppendFrame(nil, TypeData, []byte("x")))
	f.Add(AppendPadding(nil, 70000))
	f.Add([]byte{0x01, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReader(bytes.NewReader(data))
		consumed := 0
		for {
			typ, body, err := r.Next()
			if err != nil {
				if err == io.EOF && consumed != len(data) {
					t.Fatalf("EOF after %d of %d bytes", consumed, len(data))
				}
				return
			}
			consumed += HeaderLen + len(body)
			// Re-encoding a frame reproduces its bytes exactly.
			re := AppendFrame(nil, typ, body)
			if !bytes.Equal(re, data[consumed-len(re):consumed]) {
				t.Fatal("re-encoded frame differs")
			}
		}
	})
}

func FuzzParseHello(f *testing.F) {
	h := Hello{Version: 1}
	f.Add(h.AppendBody(nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ParseHello(data)
		if err != nil {
			return
		}
		if !bytes.Equal(h.AppendBody(nil), data) {
			t.Fatal("HELLO does not round-trip")
		}
		h.TimestampOK(time.Now())
	})
}

func FuzzParseWelcome(f *testing.F) {
	w := Welcome{MaxLanes: 3}
	f.Add(w.AppendBody(nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		w, err := ParseWelcome(data)
		if err != nil {
			return
		}
		if !bytes.Equal(w.AppendBody(nil), data[:WelcomeLen]) {
			t.Fatal("WELCOME does not round-trip")
		}
	})
}

func FuzzParsePing(f *testing.F) {
	f.Add(AppendPing(nil, 42))
	f.Fuzz(func(t *testing.T, data []byte) {
		tok, pong, err := ParsePing(data)
		if err != nil {
			return
		}
		var re []byte
		if pong {
			re = AppendPong(nil, tok)
		} else {
			re = AppendPing(nil, tok)
		}
		if !bytes.Equal(re, data) {
			t.Fatal("PING does not round-trip")
		}
	})
}
