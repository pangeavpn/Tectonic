package lane

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/shape"
	"github.com/pangeavpn/tectonic/wire"
)

// The default profile's opening, in bytes inside each record: Chrome's
// connection preface, the HEADERS of its first GET, its SETTINGS ACK; a
// server's SETTINGS ACK with WINDOW_UPDATE, its response HEADERS, the start
// of the page.
const (
	prefaceLen             = 70
	headersMin, headersMax = 443, 453
	ackLen                 = 9
	serverAckLen           = 22
	replyMin, replyMax     = 91, 92
	pageMin, pageMax       = 1090, 4090
)

// openingFrames returns what Dial hands Start for a lane whose first
// WireGuard packet is pkt (or none), and the HELLO frame in it.
func openingFrames(pkt []byte) (first, hello []byte) {
	h := wire.Hello{Version: wire.Version, Timestamp: uint64(time.Now().Unix())}
	hello = wire.AppendFrame(nil, wire.TypeHello, h.AppendBody(nil))
	first = bytes.Clone(hello)
	if len(pkt) > 0 {
		first = wire.AppendFrame(first, wire.TypeData, pkt)
	}
	return first, hello
}

// checkHello reads a client's HELLO the way the node does (server.handle):
// a look at the frame header, then at the whole frame, through a buffered
// reader. net.Pipe hands over one Write at a time, as TLS hands over one
// record at a time, so buffered is what the first record held.
func checkHello(t *testing.T, br *bufio.Reader, hello []byte) (buffered int) {
	t.Helper()
	hdr, err := br.Peek(wire.HeaderLen)
	if err != nil || hdr[0] != wire.TypeHello || binary.BigEndian.Uint16(hdr[1:]) != wire.HelloLen {
		t.Fatalf("the opening does not begin with a HELLO header: % x (%v)", hdr, err)
	}
	buffered = br.Buffered()
	frame, err := br.Peek(wire.HeaderLen + wire.HelloLen)
	if err != nil {
		t.Fatalf("HELLO did not arrive whole: %v", err)
	}
	if !bytes.Equal(frame, hello) {
		t.Fatal("HELLO was corrupted on its way through the opening's records")
	}
	br.Discard(len(frame))
	return buffered
}

func welcomeFrames() ([]byte, wire.Welcome) {
	w := wire.Welcome{MaxLanes: 6, ResumeWindow: time.Minute}
	w.SessionID[0] = 0x42
	return wire.AppendFrame(nil, wire.TypeWelcome, w.AppendBody(nil)), w
}

func total(sizes []int) (n int) {
	for _, s := range sizes {
		n += s
	}
	return n
}

// A lane opens the way Chrome and an HTTP/2 server do. The client writes
// Chrome's 70-byte preface record and then a record the size of the first
// request's HEADERS, without waiting; when the server's first bytes arrive
// it writes a 9-byte record, Chrome's SETTINGS ACK. The server answers with
// a 22-byte record, one the size of response HEADERS, and one the size of
// the start of a page. HELLO is longer than the first record and ends in
// the second, where the first WireGuard packet follows it.
func TestOpeningRecords(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pkt   []byte
		lowat bool
	}{
		{"handshake", wgInitiation(), true},
		{"handshake, pacing on PONGs", wgInitiation(), false},
		{"no first packet", nil, true},
		{"no first packet, pacing on PONGs", nil, false},
		{"full-size first packet", bytes.Repeat([]byte{7}, 1452), true},
		{"full-size first packet, pacing on PONGs", bytes.Repeat([]byte{7}, 1452), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			crc, src := &recordConn{Conn: a}, &recordConn{Conn: b}
			cl := New(crc, nil, Options{Role: Client})
			cl.lowat = tc.lowat
			t.Cleanup(func() { cl.Close(); b.Close() })

			first, hello := openingFrames(tc.pkt)
			frames := len(first)
			started := make(chan error, 1)
			go func() { started <- cl.Start(first) }()
			br := bufio.NewReaderSize(b, 64<<10)
			if got := checkHello(t, br, hello); got != prefaceLen {
				t.Fatalf("the first record held %d bytes, want %d", got, prefaceLen)
			}
			if err := <-started; err != nil {
				t.Fatal(err)
			}

			// The client's flight: two records, and nothing more for as
			// long as the server says nothing.
			time.Sleep(20 * time.Millisecond)
			got := crc.sizes()
			if len(got) != 2 || got[0] != prefaceLen {
				t.Fatalf("client records %v, want %d and one more", got, prefaceLen)
			}
			if !tc.lowat {
				frames += wire.HeaderLen + wire.PingLen
			}
			if rest := frames - prefaceLen; rest > headersMax {
				// Too much for a HEADERS-sized record: it takes what
				// there is, and the packet still leaves with HELLO.
				if got[1] != rest {
					t.Fatalf("second record is %d bytes, want the %d left to send", got[1], rest)
				}
			} else if got[1] < headersMin || got[1] > headersMax {
				t.Fatalf("second record is %d bytes, outside [%d, %d]", got[1], headersMin, headersMax)
			}

			// The node logs the lane in and answers.
			sink := newSink()
			sl := New(src, br, Options{Role: Server, Handler: Handler{Data: sink.handler}})
			sl.lowat = tc.lowat
			t.Cleanup(func() { sl.Close() })
			welcome, want := welcomeFrames()
			if err := sl.Start(welcome); err != nil {
				t.Fatal(err)
			}
			if w := waitWelcome(t, cl); w != want {
				t.Fatalf("WELCOME arrived as %+v, want %+v", w, want)
			}
			if len(tc.pkt) > 0 {
				if pkts := sink.wait(t, 1); !bytes.Equal(pkts[0], tc.pkt) {
					t.Fatal("the first WireGuard packet was corrupted on its way through the opening")
				}
			}
			got = src.sizes()
			if len(got) < 3 || got[0] != serverAckLen || got[1] < replyMin || got[1] > replyMax ||
				got[2] < pageMin || got[2] > pageMax+wire.HeaderLen {
				t.Fatalf("server records %v, want %d, %d-%d, %d-%d", got, serverAckLen, replyMin, replyMax, pageMin, pageMax)
			}

			// The server's first bytes bring the client's last record.
			waitWrites(t, crc, 3)
			if got := crc.sizes()[2]; got != ackLen {
				t.Fatalf("the record after the server's first bytes is %d bytes, want %d", got, ackLen)
			}

			if tc.lowat {
				// Nothing else was written, and all of it is counted.
				time.Sleep(20 * time.Millisecond)
				if got := crc.sizes(); len(got) != 3 || cl.Stats().BytesSent != uint64(total(got)) {
					t.Fatalf("client records %v, %d bytes counted", got, cl.Stats().BytesSent)
				}
				if got := src.sizes(); len(got) != 3 || sl.Stats().BytesSent != uint64(total(got)) {
					t.Fatalf("server records %v, %d bytes counted", got, sl.Stats().BytesSent)
				}
				return
			}
			// Without TCP_NOTSENT_LOWAT each opening ends with a PING, and
			// its PONG answers for every record of it.
			deadline := time.Now().Add(3 * time.Second)
			for _, l := range []*Lane{cl, sl} {
				for !l.ponged.Load() || l.Stats().Unconfirmed != 0 || l.Stats().PingsOut != 0 {
					if time.Now().After(deadline) {
						t.Fatalf("%v: the opening's PING was not answered for all of it: %+v", l, l.Stats())
					}
					time.Sleep(time.Millisecond)
				}
			}
		})
	}
}

// Before the PONG comes back, a lane without TCP_NOTSENT_LOWAT counts every
// record of its opening as on its way.
func TestOpeningIsOutstandingUntilItsPong(t *testing.T) {
	prof := shape.Default()
	l, rc := pipeLane(t, prof) // the far end reads and answers nothing
	welcome, _ := welcomeFrames()
	if err := l.Start(welcome); err != nil {
		t.Fatal(err)
	}
	got := rc.sizes()
	if len(got) != 3 {
		t.Fatalf("records %v, want three", got)
	}
	if st := l.Stats(); st.PingsOut != 1 || st.Unconfirmed != uint64(total(got)) || st.BytesSent != uint64(total(got)) {
		t.Fatalf("after an opening of %d bytes: %+v", total(got), st)
	}
}

// Chrome's SETTINGS ACK is a record of its own whatever else is waiting, so
// the client's 9 bytes never share a record with DATA.
func TestOpeningAckSharesItsRecordWithNothing(t *testing.T) {
	a, b := net.Pipe()
	crc := &recordConn{Conn: a}
	cl := New(crc, nil, Options{Role: Client})
	cl.lowat = true
	t.Cleanup(func() { cl.Close(); b.Close() })
	first, hello := openingFrames(wgInitiation())
	started := make(chan error, 1)
	go func() { started <- cl.Start(first) }()
	br := bufio.NewReaderSize(b, 64<<10)
	checkHello(t, br, hello)
	if err := <-started; err != nil {
		t.Fatal(err)
	}

	// A packet is waiting when the server's first bytes arrive.
	cl.mu.Lock() // hold the writer
	pkt := wgInitiation()
	cl.data = append(cl.data, pkt)
	cl.dataAt = append(cl.dataAt, time.Now().UnixNano())
	cl.queued += wire.HeaderLen + len(pkt)
	sink := newSink()
	sl := New(b, br, Options{Role: Server, Handler: Handler{Data: sink.handler}})
	sl.lowat = true
	t.Cleanup(func() { sl.Close() })
	welcome, _ := welcomeFrames()
	if err := sl.Start(welcome); err != nil {
		cl.mu.Unlock()
		t.Fatal(err)
	}
	waitWelcome(t, cl)
	cl.mu.Unlock()
	cl.signal(cl.wake)

	sink.wait(t, 2)
	waitWrites(t, crc, 4)
	got := crc.sizes()
	if len(got) != 4 || got[2] != ackLen || got[3] < wire.HeaderLen+len(pkt) {
		t.Fatalf("client records %v, want the %d-byte record and then one with the packet", got, ackLen)
	}
}

// The CDN carrier is a WebSocket: HELLO must arrive in its first message,
// and a WebSocket has no HTTP/2 opening to follow. The opening goes in one
// message each way, of the same size in all, and the client sends no ACK.
func TestOpeningOverWebSocketIsOneMessage(t *testing.T) {
	a, b := net.Pipe()
	crc, src := &recordConn{Conn: a}, &recordConn{Conn: b}
	cws := &wsConn{Conn: crc, br: bufio.NewReader(crc), client: true}
	sws := &wsConn{Conn: src, br: bufio.NewReader(src)}
	cl := New(cws, nil, Options{Role: Client})
	cl.lowat = true
	t.Cleanup(func() { cl.Close(); b.Close() })

	first, hello := openingFrames(wgInitiation())
	started := make(chan error, 1)
	go func() { started <- cl.Start(first) }()
	// The node's side of a CDN lane (server.serveCDN).
	br := bufio.NewReaderSize(sws, 64<<10)
	message := checkHello(t, br, hello)
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	const clientFrame, serverFrame = 8, 4 // WebSocket framing: header, length and the client's mask
	if got := crc.sizes(); len(got) != 1 || got[0] != message+clientFrame {
		t.Fatalf("client writes %v, want one message of %d bytes", got, message)
	}
	if message < prefaceLen+headersMin || message > prefaceLen+headersMax {
		t.Fatalf("the first message is %d bytes, want the two records' %d-%d", message, prefaceLen+headersMin, prefaceLen+headersMax)
	}

	sink := newSink()
	sl := New(sws, br, Options{Role: Server, Handler: Handler{Data: sink.handler}})
	sl.lowat = true
	t.Cleanup(func() { sl.Close() })
	welcome, want := welcomeFrames()
	if err := sl.Start(welcome); err != nil {
		t.Fatal(err)
	}
	if w := waitWelcome(t, cl); w != want {
		t.Fatalf("WELCOME arrived as %+v, want %+v", w, want)
	}
	if pkts := sink.wait(t, 1); !bytes.Equal(pkts[0], wgInitiation()) {
		t.Fatal("the first WireGuard packet was corrupted")
	}
	lo, hi := serverAckLen+replyMin+pageMin, serverAckLen+replyMax+pageMax+wire.HeaderLen
	if got := src.sizes(); len(got) != 1 || got[0] < lo+serverFrame || got[0] > hi+serverFrame {
		t.Fatalf("server writes %v, want one message of %d-%d bytes", got, lo, hi)
	}
	time.Sleep(30 * time.Millisecond)
	if got := crc.sizes(); len(got) != 1 {
		t.Fatalf("client writes %v: a WebSocket lane has no ACK to send", got)
	}
}

// A profile decides the opening: other records, and no ACK.
func TestOpeningFollowsTheProfile(t *testing.T) {
	prof := shape.Default()
	prof.ClientFirstFlight = []shape.IntRange{{Min: 100, Max: 100}, {Min: 200, Max: 200}, {Min: 300, Max: 300}}
	prof.ClientAck = shape.IntRange{}
	if err := prof.Validate(); err != nil {
		t.Fatal(err)
	}
	// A real connection: HELLO fits the first record this time, so the
	// records after it are still unread when the node answers, and a pipe
	// would have each end wait for the other to read.
	a, b := tcpPair(t)
	crc := &recordConn{Conn: a}
	cl := New(crc, nil, Options{Role: Client, Planner: shape.NewPlanner(prof)})
	cl.lowat = true
	t.Cleanup(func() { cl.Close() })
	first, hello := openingFrames(wgInitiation())
	if err := cl.Start(first); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReaderSize(b, 64<<10)
	checkHello(t, br, hello)
	sink := newSink()
	sl := New(b, br, Options{Role: Server, Handler: Handler{Data: sink.handler}})
	sl.lowat = true
	t.Cleanup(func() { sl.Close() })
	welcome, _ := welcomeFrames()
	if err := sl.Start(welcome); err != nil {
		t.Fatal(err)
	}
	waitWelcome(t, cl)
	if pkts := sink.wait(t, 1); !bytes.Equal(pkts[0], wgInitiation()) {
		t.Fatal("the first WireGuard packet was corrupted")
	}
	time.Sleep(30 * time.Millisecond)
	if got := crc.sizes(); len(got) != 3 || got[0] != 100 || got[1] != 200 || got[2] != 300 {
		t.Fatalf("client records %v, want [100 200 300]", got)
	}
}

// A lane tells its carrier by its connection: Dial gives a CDN lane the
// WebSocket itself, and a direct lane its TLS connection. If Dial ever wraps
// the WebSocket in something else, the lane would cut the opening into
// records, and HELLO would miss the first message.
func TestDialedLanesKnowTheirCarrier(t *testing.T) {
	cdn := newTestNode(t, func(n *testNode) { n.ws = true })
	cfg := cdn.dialConfig(t, 0)
	cfg.Carrier = CDN
	cfg.ServerName = coverDomain
	cfg.Path = "/ws"
	cl := dial(t, cfg)
	sl := cdn.acceptLane(t)
	waitWelcome(t, cl)
	if _, ws := cl.conn.(*wsConn); !ws || cl.ack != 0 {
		t.Fatalf("a dialed CDN lane runs on a %T and plans a %d-byte ACK: it did not open as a WebSocket", cl.conn, cl.ack)
	}
	if _, ws := sl.conn.(*wsConn); !ws {
		t.Fatalf("the node's end of a CDN lane runs on a %T", sl.conn)
	}

	direct := newTestNode(t, nil)
	cl = dial(t, direct.dialConfig(t, SNIOwn))
	direct.acceptLane(t)
	waitWelcome(t, cl)
	if cl.ack != ackLen {
		t.Fatalf("a dialed direct lane plans a %d-byte ACK, want %d", cl.ack, ackLen)
	}
}

// The node tells a login from the first record it reads, which must begin
// with HELLO and hold its frame header, its fields and 16 bytes of its tag.
// Whatever the profile, and whatever else the opening carries, nothing goes
// ahead of HELLO and the first record is not cut shorter than that.
func TestClientFirstRecordBeginsWithHello(t *testing.T) {
	smallest := shape.Default()
	smallest.ClientFirstFlight = []shape.IntRange{
		{Min: shape.MinClientFirstRecord, Max: shape.MinClientFirstRecord}, {Min: headersMin, Max: headersMax},
	}
	one := shape.Default()
	one.ClientFirstFlight = []shape.IntRange{{Min: 380, Max: 620}}
	for name, prof := range map[string]*shape.Profile{
		"default": shape.Default(), "smallest first record": smallest, "one record": one,
	} {
		if err := prof.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, lowat := range []bool{true, false} {
			for _, pkt := range [][]byte{nil, wgInitiation(), bytes.Repeat([]byte{7}, 1452)} {
				a, b := net.Pipe()
				cl := New(a, nil, Options{Role: Client, Planner: shape.NewPlanner(prof)})
				cl.lowat = lowat
				first, hello := openingFrames(pkt)
				go cl.Start(first)
				// net.Pipe hands a Read one Write, as TLS hands over one
				// record.
				buf := make([]byte, 64<<10)
				n, err := b.Read(buf)
				go io.Copy(io.Discard, b)
				cl.Close()
				b.Close()
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if n < shape.MinClientFirstRecord {
					t.Fatalf("%s, %d-byte first packet: the first record holds %d bytes, under the %d the node needs",
						name, len(pkt), n, shape.MinClientFirstRecord)
				}
				if got := min(n, len(hello)); !bytes.Equal(buf[:got], hello[:got]) {
					t.Fatalf("%s, %d-byte first packet: the first record does not begin with HELLO", name, len(pkt))
				}
			}
		}
	}
}
