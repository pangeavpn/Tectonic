package lane

import (
	"bufio"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/shape"
	"github.com/pangeavpn/tectonic/wire"
)

// farEnd is the other end of a lane's connection: it reads the lane's
// frames from the byte stream and answers its PINGs, as a lane does, and
// can send it a PING of its own. A quiet one answers nothing.
type farEnd struct {
	t     *testing.T
	conn  net.Conn
	quiet bool
	wmu   sync.Mutex

	mu   sync.Mutex
	pkts [][]byte // DATA bodies, in the order they arrived
	ctrl []byte   // the types of the other frames, PAD left out
	err  error
	done chan struct{}
}

func (f *farEnd) read() {
	defer close(f.done)
	rd := wire.NewReader(bufio.NewReader(f.conn))
	for {
		typ, body, err := rd.Next()
		f.mu.Lock()
		switch {
		case err != nil:
			f.err = err
		case typ == wire.TypeData:
			f.pkts = append(f.pkts, append([]byte(nil), body...))
		case typ != wire.TypePad:
			f.ctrl = append(f.ctrl, typ)
		}
		f.mu.Unlock()
		if err != nil {
			return
		}
		if typ == wire.TypePing && !f.quiet {
			if tok, pong, err := wire.ParsePing(body); err == nil && !pong {
				b := wire.AppendHeader(nil, wire.TypePing, wire.PingLen)
				f.write(wire.AppendPong(b, tok))
			}
		}
	}
}

func (f *farEnd) write(b []byte) error {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	_, err := f.conn.Write(b)
	return err
}

// packets waits for n DATA frames and returns them.
func (f *farEnd) packets(n int) [][]byte {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		got, err := len(f.pkts), f.err
		if got >= n {
			out := append([][]byte(nil), f.pkts...)
			f.mu.Unlock()
			return out
		}
		f.mu.Unlock()
		if err != nil || time.Now().After(deadline) {
			f.t.Fatalf("the far end read %d packets, want %d (%v)", got, n, err)
		}
		time.Sleep(time.Millisecond)
	}
}

// ping sends the lane a PING, which it answers with a PONG.
func (f *farEnd) ping() {
	f.t.Helper()
	b := wire.AppendHeader(nil, wire.TypePing, wire.PingLen)
	if err := f.write(wire.AppendPing(b, wire.NewPingToken())); err != nil {
		f.t.Fatal(err)
	}
}

// opening is how many bytes a lane with testProfile opens with, in one
// record: what a test sees before the records it is about.
const opening = 2000

// testProfile is the built-in profile with a server lane's opening fixed.
func testProfile() *shape.Profile {
	prof := shape.Default()
	prof.ServerFirstFlight = []shape.IntRange{{Min: opening, Max: opening}}
	return prof
}

// recordLane returns a started lane with the built-in profile, the records
// it writes after its opening, and the far end of its connection. sock, if
// set, is what the lane takes its connection's state from, as a lane with
// TCP_NOTSENT_LOWAT does.
func recordLane(t *testing.T, sock *sockState) (*Lane, *recordConn, *farEnd) {
	t.Helper()
	a, b := net.Pipe()
	rc := &recordConn{Conn: a}
	l := New(rc, nil, Options{Role: Server, Planner: shape.NewPlanner(testProfile())})
	if sock != nil {
		l.lowat = true
		l.sock.Store(sock)
	}
	far := &farEnd{t: t, conn: b, done: make(chan struct{})}
	go far.read()
	t.Cleanup(func() { l.Close(); b.Close(); <-far.done })
	if err := l.Start(nil); err != nil {
		t.Fatal(err)
	}
	waitWrites(t, rc, 1)
	return l, rc, far
}

// drained waits until the lane has written everything queued on it, and
// returns how many records it has written by then.
func drained(t *testing.T, l *Lane, rc *recordConn) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := len(rc.sizes())
		time.Sleep(5 * time.Millisecond)
		if l.Queued() == 0 && len(rc.sizes()) == n {
			return n
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d bytes still queued", l.Queued())
		}
	}
}

// keepBusy has the lane carry a bulk transfer for a few of the windows it
// judges that by, and waits for it to finish.
func keepBusy(t *testing.T, l *Lane, rc *recordConn) int {
	t.Helper()
	for range 6 {
		queue(l, 14)
		time.Sleep(busyWindow / 2)
	}
	return drained(t, l, rc)
}

func TestControlFramesAreNeverSentBare(t *testing.T) {
	// A PONG is 11 bytes and a RETIRE 3. HTTP/2's smallest frame is 9, so
	// nothing a browser sends is as short as a bare RETIRE, and a record
	// that is always 11 bytes is a PONG to anyone counting. In the middle
	// of a bulk transfer, where records are not padded up to a bucket,
	// these are all the same.
	l, rc, far := recordLane(t, nil)
	seen := map[int]bool{}
	for range 40 {
		n := keepBusy(t, l, rc)
		far.ping()
		waitWrites(t, rc, n+1)
		size := rc.sizes()[n]
		if size < 16 || size >= 32 {
			t.Fatalf("a record carrying only a PONG is %d bytes, want [16, 32)", size)
		}
		seen[size] = true
	}
	if len(seen) < 8 {
		t.Errorf("40 records carrying only a PONG came out at %d lengths", len(seen))
	}
	n := keepBusy(t, l, rc)
	l.Retire()
	waitWrites(t, rc, n+1)
	if size := rc.sizes()[n]; size < 16 || size >= 32 {
		t.Fatalf("a record carrying only a RETIRE is %d bytes, want [16, 32)", size)
	}
}

func TestLastRecordOfABurstIsPadded(t *testing.T) {
	// During a bulk transfer, a record that goes out because the queue ran
	// dry holds whole packets. Left as it is, its length is a multiple of
	// the packet size; it takes a few bytes of padding, and no more.
	l, rc, far := recordLane(t, nil)
	const frame = wire.HeaderLen + 1420
	sent := 0
	for range 20 {
		n := keepBusy(t, l, rc)
		sent += 6 * 14
		queue(l, 5)
		sent += 5
		far.packets(sent)
		drained(t, l, rc)
		sizes := rc.sizes()[n:]
		if len(sizes) != 1 {
			t.Fatalf("five packets left in records %v, want one", sizes)
		}
		// Five packets, with or without a PING, and a PAD frame of 3 to
		// 34 bytes.
		if size := sizes[0]; size%frame == 0 || size < 5*frame+3 || size >= 5*frame+11+35 {
			t.Fatalf("five packets left in a record of %d bytes", size)
		}
	}
}
