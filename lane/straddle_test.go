package lane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/pangeavpn/tectonic/shape"
	"github.com/pangeavpn/tectonic/wire"
)

// fullSize is a full-size WireGuard packet, and fullFrame the DATA frame
// that carries it: 11 of them fit a record, with 379 bytes over.
const (
	fullSize  = 1452
	fullFrame = wire.HeaderLen + fullSize
)

// fastSock is a connection that sends a full record in a moment.
func fastSock() *sockState {
	return &sockState{cwnd: 600 * 1448, rtt: 50 * time.Millisecond, pacing: 12.5e6}
}

// numbered returns n packets of size bytes, no two alike: each starts with
// its number and is random from there.
func numbered(n, size int) [][]byte {
	pkts := make([][]byte, n)
	for i := range pkts {
		p := make([]byte, size)
		rand.Read(p)
		binary.BigEndian.PutUint32(p, 0xD0000000|uint32(i))
		pkts[i] = p
	}
	return pkts
}

// queuePackets puts pkts on the lane at once, so that its writer finds
// them all waiting.
func queuePackets(l *Lane, pkts [][]byte) {
	l.mu.Lock()
	for _, p := range pkts {
		l.data = append(l.data, p)
		l.dataAt = append(l.dataAt, time.Now().UnixNano())
		l.queued += wire.HeaderLen + len(p)
	}
	l.mu.Unlock()
	l.signal(l.wake)
}

func samePackets(t *testing.T, got, want [][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d packets arrived, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("packet %d arrived changed or out of turn", i)
		}
	}
}

func TestBacklogGoesOutInFullRecords(t *testing.T) {
	// 60 packets are 87300 bytes of frames; with the PING that rides in
	// the first record, five records of 16384 bytes and 5391 over. Each
	// full record ends inside a packet, which the next one finishes.
	l, rc, far := recordLane(t, fastSock())
	pkts := numbered(60, fullSize)
	queuePackets(l, pkts)
	samePackets(t, far.packets(60), pkts)
	sizes := rc.sizes()[1:]
	if len(sizes) != 6 {
		t.Fatalf("records %v, want five full and one more", sizes)
	}
	for _, s := range sizes[:5] {
		if s != shape.MaxRecord {
			t.Fatalf("records %v: the first five should be %d bytes", sizes, shape.MaxRecord)
		}
	}
	// The last holds what was left, padded into the band above it.
	if last := sizes[5]; last < 5408 || last >= 5440 {
		t.Fatalf("the last record is %d bytes, want [5408, 5440)", last)
	}
	if st := l.Stats(); st.PacketsSent != 60 || st.DataSent != 60*fullSize {
		t.Fatalf("lane counted %d packets, %d bytes of them", st.PacketsSent, st.DataSent)
	}

	// A lane that paces itself on PONGs keeps whole packets in its
	// records. It stops writing while its window is full, and a packet
	// cut by the last record before that would wait half sent. Eleven
	// packets, a PING and the padding come to less than a full record.
	l, rc, far = recordLane(t, nil)
	queuePackets(l, pkts)
	samePackets(t, far.packets(60), pkts)
	drained(t, l, rc)
	for _, s := range rc.sizes()[1:] {
		if s >= shape.MaxRecord {
			t.Fatalf("records %v: one of %d bytes does not end with a whole packet", rc.sizes()[1:], s)
		}
	}
}

func TestLastRecordOfABacklogFollowsAtOnce(t *testing.T) {
	// 14 packets are one full record and 3986 bytes: the end of the
	// packet the record stopped in, and two more. Nothing else is coming,
	// and that must not wait for a record to fill, which is a millisecond
	// or two. Once the lane has been busy, the last record also ends
	// inside its last packet, and the end of that follows, at once too.
	// The quickest of twenty tries says whether the lane waits.
	l, rc, far := recordLane(t, fastSock())
	quickest := time.Hour
	sent := 0
	for range 20 {
		n := drained(t, l, rc)
		pkts := numbered(14, fullSize)
		queuePackets(l, pkts)
		sent += 14
		samePackets(t, far.packets(sent)[sent-14:], pkts)
		drained(t, l, rc)
		rc.mu.Lock()
		sizes, times := slices.Clone(rc.writes[n:]), slices.Clone(rc.times[n:])
		rc.mu.Unlock()
		if len(sizes) < 2 || len(sizes) > 3 || sizes[0] != shape.MaxRecord {
			t.Fatalf("14 packets left in records %v, want a full one and one or two more", sizes)
		}
		gap := time.Duration(0)
		for i := 1; i < len(times); i++ {
			gap = max(gap, times[i].Sub(times[i-1]))
		}
		quickest = min(quickest, gap)
	}
	if quickest > 300*time.Microsecond {
		t.Fatalf("the record that finishes a packet followed %v after the one that began it", quickest)
	}
}

func TestConnectionLimitBoundsRecords(t *testing.T) {
	// A connection with its window full, sending 4.5 MB/s, sends 4525
	// bytes in the millisecond a record may take: three packets. Its
	// records hold no more than that. Each ends inside its last packet,
	// at a point drawn evenly, and the next opens with the rest, so their
	// lengths say nothing of the packets' size.
	s := &sockState{cwnd: 100 * 1448, inflight: 100 * 1448, rtt: 32 * time.Millisecond}
	if got := s.recordLimit(); got != 4525 {
		t.Fatalf("record limit = %d, want 4525", got)
	}
	l, rc, far := recordLane(t, s)
	pkts := numbered(120, fullSize)
	queuePackets(l, pkts)
	samePackets(t, far.packets(120), pkts)
	drained(t, l, rc)
	sizes := rc.sizes()[1:]
	seen, onLattice := map[int]bool{}, 0
	for _, size := range sizes {
		// No more than the limit, or the last, padded into the band
		// above once the backlog is nearly gone.
		if size > 4525+51 {
			t.Fatalf("records %v: one is over the limit", sizes)
		}
		if size%fullFrame < shape.CutMin {
			onLattice++
		}
		seen[size] = true
	}
	// A record that opens with the end of one packet and ends inside
	// another has a length spread evenly over a packet's size, so one in
	// twenty-odd lands within CutMin of a multiple of it. Holding whole
	// packets, all of them would.
	if onLattice > len(sizes)/5 {
		t.Fatalf("records %v: %d are whole packets and a little", sizes, onLattice)
	}
	if len(seen) < len(sizes)*3/4 {
		t.Fatalf("records %v: lengths barely vary", sizes)
	}
}

func TestPacketLargerThanARecord(t *testing.T) {
	// A frame can carry 64 KB, four records' worth. Each record it fills
	// holds nothing else, on a fast connection and on one whose limit is
	// a fraction of a packet, and what follows it arrives whole.
	for _, sock := range []*sockState{fastSock(), {cwnd: 10 * 1448, inflight: 10 * 1448, rtt: 150 * time.Millisecond}, nil} {
		l, rc, far := recordLane(t, sock)
		pkts := [][]byte{numbered(1, 40000)[0], numbered(1, fullSize)[0], numbered(1, wire.MaxBodyLen)[0], numbered(1, 200)[0]}
		for _, p := range pkts {
			if !l.Send(p) {
				t.Fatalf("lane refused a packet of %d bytes", len(p))
			}
		}
		samePackets(t, far.packets(4), pkts)
		drained(t, l, rc)
		full := 0
		for _, size := range rc.sizes()[1:] {
			if size > shape.MaxRecord {
				t.Fatalf("records %v: one is longer than a TLS record", rc.sizes()[1:])
			}
			if size == shape.MaxRecord {
				full++
			}
		}
		// 40003 bytes fill two records and 65538 fill three or four,
		// depending on where the one before left off.
		if full < 5 {
			t.Fatalf("records %v: %d full ones, want at least 5", rc.sizes()[1:], full)
		}
		if got := l.Queued(); got != 0 {
			t.Fatalf("%d bytes still counted as queued", got)
		}
	}
}

// stepLimiter lets one record of DATA through and then holds the rest
// until it is released.
type stepLimiter struct {
	fakeLimiter
	asked int
}

func (f *stepLimiter) Wait(now time.Time) time.Duration {
	f.mu.Lock()
	f.asked++
	hold := f.hold && f.asked > 1
	f.mu.Unlock()
	if hold {
		return 50 * time.Millisecond
	}
	return 0
}

// heldAfterOneRecord returns a lane that has written the first record of a
// 20-packet backlog and is held by its session's send limit before the
// next: 11 packets, a PING and the first 368 bytes of the twelfth are
// out, and its other 1087 bytes are waiting.
func heldAfterOneRecord(t *testing.T) (*Lane, *recordConn, *farEnd, *stepLimiter, [][]byte) {
	t.Helper()
	a, b := net.Pipe()
	rc := &recordConn{Conn: a}
	lim := &stepLimiter{fakeLimiter: fakeLimiter{hold: true}}
	l := New(rc, nil, Options{Role: Server, Planner: shape.NewPlanner(testProfile()), Limiter: lim})
	l.lowat = true
	l.sock.Store(fastSock())
	far := &farEnd{t: t, conn: b, done: make(chan struct{})}
	go far.read()
	t.Cleanup(func() { l.Close(); b.Close(); <-far.done })
	if err := l.Start(nil); err != nil {
		t.Fatal(err)
	}
	waitWrites(t, rc, 1)
	pkts := numbered(20, fullSize)
	queuePackets(l, pkts)
	samePackets(t, far.packets(11), pkts[:11])
	time.Sleep(20 * time.Millisecond)
	if sizes := rc.sizes()[1:]; len(sizes) != 1 || sizes[0] != shape.MaxRecord {
		t.Fatalf("records %v, want one full one before the limit held", sizes)
	}
	if got := lim.written(); got != shape.MaxRecord {
		t.Fatalf("%d bytes counted against the limit, want the one record", got)
	}
	// What is left of the twelfth packet is still queued, with the eight
	// behind it: the scheduler counts on the lane for all of it.
	const rest = fullFrame - (shape.MaxRecord - 11*fullFrame - wire.HeaderLen - wire.PingLen)
	if got := l.Queued(); got != rest+8*fullFrame {
		t.Fatalf("%d bytes queued, want %d", got, rest+8*fullFrame)
	}
	return l, rc, far, lim, pkts
}

func TestEndOfAPacketGoesWithWhateverIsWritten(t *testing.T) {
	l, rc, far, lim, pkts := heldAfterOneRecord(t)
	const rest = fullFrame - (shape.MaxRecord - 11*fullFrame - wire.HeaderLen - wire.PingLen)
	// A small packet does not wait for the limit. The end of the packet
	// the last record began is ahead of it in the stream, so it goes too,
	// and the packet arrives before the small one.
	small := numbered(1, 100)[0]
	l.Send(small)
	got := far.packets(13)
	samePackets(t, got[:12], pkts[:12])
	if !bytes.Equal(got[12], small) {
		t.Fatal("the small packet arrived changed")
	}
	// That record holds the 1087 bytes and the small packet's 103, padded
	// into the band above. Only the end of the packet counts against the
	// limit, and all of the record counts as DATA written.
	held := rc.sizes()[2]
	if held < 1216 || held >= 1248 {
		t.Fatalf("the held record is %d bytes, want [1216, 1248): the end of one packet and the small one", held)
	}
	if got := lim.written(); got != shape.MaxRecord+rest {
		t.Fatalf("%d bytes counted against the limit, want the first record and the %d that finished its last packet", got, rest)
	}
	if got := l.tracked.Load(); got != uint64(shape.MaxRecord+held) {
		t.Fatalf("%d bytes tracked, want both records' %d", got, shape.MaxRecord+held)
	}
	// Once the limit lets go, the rest follows, and every byte of every
	// record has been counted once.
	lim.set(false)
	samePackets(t, far.packets(21)[13:], pkts[12:])
	drained(t, l, rc)
	total := 0
	for _, s := range rc.sizes()[1:] {
		total += s
	}
	if got := lim.written(); got != total-(held-rest) {
		t.Fatalf("%d bytes counted against the limit, want %d", got, total-(held-rest))
	}
	if st := l.Stats(); st.BytesSent != uint64(opening+total) || l.tracked.Load() != uint64(total) || st.PacketsSent != 21 || st.Queued != 0 {
		t.Fatalf("lane counted %d bytes sent, %d tracked, %d packets, %d bytes still queued; wrote %d after its opening",
			st.BytesSent, l.tracked.Load(), st.PacketsSent, st.Queued, total)
	}
}

func TestCloseFinishesThePacketItInterrupts(t *testing.T) {
	// CLOSE drops what is queued. A packet that is partly sent is not
	// queued any more: the frames after it would be read as its body.
	l, _, far, _, pkts := heldAfterOneRecord(t)
	l.SendClose(wire.CloseNormal)
	samePackets(t, far.packets(12), pkts[:12])
	<-far.done
	far.mu.Lock()
	defer far.mu.Unlock()
	if len(far.pkts) != 12 {
		t.Fatalf("%d packets arrived, want the 12 that had begun", len(far.pkts))
	}
	if !slices.Contains(far.ctrl, wire.TypeClose) {
		t.Fatalf("frames %v after the packets, want a CLOSE", far.ctrl)
	}
	if far.err != io.EOF {
		t.Fatalf("the stream ended with %v, want a clean end between frames", far.err)
	}
}

func TestPingMarksTheEndOfItsRecord(t *testing.T) {
	// A PING in a record that ends inside a packet rides ahead of that
	// packet's beginning, and still stands for every byte of the record:
	// TLS hands the record over whole.
	a, b := net.Pipe()
	rc := &recordConn{Conn: a}
	l := New(rc, nil, Options{Role: Server, Planner: shape.NewPlanner(testProfile())})
	l.lowat = true
	l.sock.Store(fastSock())
	far := &farEnd{t: t, conn: b, done: make(chan struct{}), quiet: true}
	go far.read()
	t.Cleanup(func() { l.Close(); b.Close(); <-far.done })
	if err := l.Start(nil); err != nil {
		t.Fatal(err)
	}
	// The lane has sent no PING yet, so one is due in the first record
	// that carries DATA; with no PONG coming back it stays outstanding
	// and no other follows.
	pkts := numbered(60, fullSize)
	queuePackets(l, pkts)
	samePackets(t, far.packets(60), pkts)
	drained(t, l, rc)
	sizes := rc.sizes()
	if len(sizes) < 3 || sizes[1] != shape.MaxRecord {
		t.Fatalf("records %v: the first after the opening should be full", sizes)
	}
	sum := uint64(0)
	for _, s := range sizes[1:] {
		sum += uint64(s)
	}
	far.mu.Lock()
	pinged := bytes.Count(far.ctrl, []byte{wire.TypePing})
	far.mu.Unlock()
	if pinged != 1 {
		t.Fatalf("%d PINGs arrived, want one", pinged)
	}
	l.pingMu.Lock()
	defer l.pingMu.Unlock()
	if len(l.pings) != 1 || l.pings[0].bytes != shape.MaxRecord {
		t.Fatalf("PINGs outstanding %+v, want one that stands for the %d bytes of its record", l.pings, shape.MaxRecord)
	}
	// A lane with TCP_NOTSENT_LOWAT does not count its opening.
	if got := l.tracked.Load(); got != sum {
		t.Fatalf("%d bytes tracked, %d written after the opening", got, sum)
	}
}

func TestFramesAreReadAcrossAnyRecordBoundary(t *testing.T) {
	var stream []byte
	want := [][]byte{numbered(1, fullSize)[0], wgKeepalive(), numbered(1, 100)[0]}
	stream = wire.AppendFrame(stream, wire.TypeData, want[0])
	stream = wire.AppendHeader(stream, wire.TypePing, wire.PingLen)
	stream = wire.AppendPing(stream, 7)
	stream = wire.AppendFrame(stream, wire.TypeData, want[1])
	stream = wire.AppendPadding(stream, 40)
	stream = wire.AppendFrame(stream, wire.TypeData, want[2])
	read := func(r io.Reader) {
		t.Helper()
		rd := wire.NewReader(r)
		var got [][]byte
		for {
			typ, body, err := rd.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if typ == wire.TypeData {
				got = append(got, append([]byte(nil), body...))
			}
		}
		samePackets(t, got, want)
	}
	// Two records, the first ending at every byte of the stream in turn:
	// inside each header, inside each body, and between frames.
	for cut := range stream {
		read(io.MultiReader(bytes.NewReader(stream[:cut]), bytes.NewReader(stream[cut:])))
	}
	read(iotest.OneByteReader(bytes.NewReader(stream)))
}

// tlsTap is a TCP connection that notes the length of every TLS
// application-data record written to it, as someone watching the
// connection sees them.
type tlsTap struct {
	*net.TCPConn
	mu      sync.Mutex
	pending []byte
	records []int
}

func (c *tlsTap) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.pending = append(c.pending, p...)
	for len(c.pending) >= 5 {
		n := 5 + int(binary.BigEndian.Uint16(c.pending[3:]))
		if len(c.pending) < n {
			break
		}
		if c.pending[0] == 23 {
			c.records = append(c.records, n-5)
		}
		c.pending = c.pending[n:]
	}
	c.mu.Unlock()
	return c.TCPConn.Write(p)
}

func (c *tlsTap) lengths() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.records)
}

func TestFullRecordsOnTheWire(t *testing.T) {
	// Over real TLS, both ways: 80 packets are seven full records and
	// 1712 bytes. Every one arrives whole and in turn, and on the wire the
	// full records are 16401 bytes, as a web server's are.
	serverSink := newSink()
	n := newTestNode(t, func(n *testNode) { n.handler.Data = serverSink.handler })
	clientSink := newSink()
	cfg := n.dialConfig(t, SNIOwn)
	cfg.Lane.Handler.Data = clientSink.handler
	var tap *tlsTap
	cfg.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tap = &tlsTap{TCPConn: c.(*net.TCPConn)}
		return tap, nil
	}
	cl := dial(t, cfg)
	sl := n.acceptLane(t)
	waitWelcome(t, cl)

	up, down := numbered(80, fullSize), numbered(80, fullSize)
	queuePackets(cl, up)
	queuePackets(sl, down)
	samePackets(t, serverSink.wait(t, 80), up)
	samePackets(t, clientSink.wait(t, 80), down)
	if !cl.Stats().NotSentLowat {
		t.Skip("no TCP_NOTSENT_LOWAT here: the lane's window, not the backlog, decides where its records end")
	}
	full, bare := 0, 0
	for _, n := range tap.lengths() {
		switch {
		case n == shape.MaxRecord+17:
			full++
		case n > 1400 && (n-17)%fullFrame == 0:
			bare++
		}
	}
	if full < 6 || bare > 0 {
		t.Fatalf("records on the wire %v: %d of 16401 bytes, want at least 6; %d a whole number of packets, want none", tap.lengths(), full, bare)
	}
}

func TestFullRecordsOverWebSocket(t *testing.T) {
	// The CDN carrier reads the stream out of WebSocket messages, one to
	// a record. Frames cross those too.
	serverSink := newSink()
	n := newTestNode(t, func(n *testNode) {
		n.ws = true
		n.handler.Data = serverSink.handler
	})
	cfg := n.dialConfig(t, 0)
	cfg.Carrier = CDN
	cfg.ServerName = coverDomain
	cfg.Path = "/ws"
	clientSink := newSink()
	cfg.Lane.Handler.Data = clientSink.handler
	cl := dial(t, cfg)
	sl := n.acceptLane(t)
	waitWelcome(t, cl)
	up, down := numbered(80, fullSize), numbered(80, fullSize)
	queuePackets(cl, up)
	queuePackets(sl, down)
	samePackets(t, serverSink.wait(t, 80), up)
	samePackets(t, clientSink.wait(t, 80), down)
}

// ackOnFullRecord is a client lane's connection that has the server's first
// bytes arrive, as far as the lane can tell, just as its first full record
// is written: with the rest of a packet still to send.
type ackOnFullRecord struct {
	*recordConn
	l    *Lane
	once sync.Once
}

func (c *ackOnFullRecord) Write(p []byte) (int, error) {
	if len(p) == shape.MaxRecord {
		c.once.Do(func() { c.l.ackDue.Store(true) })
	}
	return c.recordConn.Write(p)
}

func TestOpeningAckWaitsForThePacketARecordEndedIn(t *testing.T) {
	// The record that ends a client's opening is padding with a record to
	// itself. In a transfer every full record ends inside a packet, and
	// padding between the two parts of a packet would be read as the rest
	// of it. The record waits for that packet to be finished, and no
	// longer: the record that finishes it ends with a whole packet.
	a, b := net.Pipe()
	rc := &recordConn{Conn: a}
	conn := &ackOnFullRecord{recordConn: rc}
	l := New(conn, nil, Options{Role: Client})
	conn.l = l
	l.lowat = true
	l.sock.Store(fastSock())
	far := &farEnd{t: t, conn: b, quiet: true, done: make(chan struct{})}
	go far.read()
	t.Cleanup(func() { l.Close(); b.Close(); <-far.done })
	first, _ := openingFrames(nil)
	if err := l.Start(first); err != nil {
		t.Fatal(err)
	}
	if l.ack != ackLen {
		t.Fatalf("the lane plans a %d-byte ACK, want %d", l.ack, ackLen)
	}

	pkts := numbered(60, fullSize)
	queuePackets(l, pkts)
	samePackets(t, far.packets(60), pkts)
	drained(t, l, rc)
	// Two records of opening, a full record, the one that finishes its
	// last packet, the ACK, and the rest of the transfer.
	sizes := rc.sizes()
	if len(sizes) < 6 || sizes[2] != shape.MaxRecord || sizes[3] >= shape.MaxRecord || sizes[4] != ackLen {
		t.Fatalf("records %v, want a full one, one ending with a whole packet, then %d bytes", sizes, ackLen)
	}
	full := 0
	for _, s := range sizes[5:] {
		if s == ackLen {
			t.Fatalf("records %v: the %d-byte record went twice", sizes, ackLen)
		}
		if s == shape.MaxRecord {
			full++
		}
	}
	if full < 2 {
		t.Fatalf("records %v: the transfer did not go back to full records", sizes)
	}
}
