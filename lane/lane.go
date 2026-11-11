// Package lane implements a single Tectonic lane: one TLS 1.3 connection that
// carries frames after the HELLO login (design §4, §6, §7).
//
// A Lane owns three goroutines: a reader that hands each DATA frame up the
// moment it arrives, a writer that packs queued frames into records sized by
// the shaper, and a monitor that keeps the round-trip time and rate estimates
// the scheduler needs. Dial opens a client lane; the server builds its lanes
// with New after checking HELLO.
package lane

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pangeavpn/tectonic/shape"
	"github.com/pangeavpn/tectonic/wire"
)

// Role says which end of a lane this is.
type Role uint8

const (
	Client Role = iota
	Server
)

func (r Role) String() string {
	if r == Client {
		return "client"
	}
	return "server"
}

// Errors a lane can end with.
var (
	// ErrLoginFailed means the server answered the HELLO with something
	// other than WELCOME: it served its website instead.
	ErrLoginFailed = errors.New("lane: login failed")
	// ErrPingTimeout means a PING went unanswered for the ping timeout.
	ErrPingTimeout = errors.New("lane: no PONG within the timeout")
	// ErrPeerClosed means the peer ended the connection without retiring it.
	ErrPeerClosed = errors.New("lane: closed by peer")
	// ErrClosed means the lane was closed locally.
	ErrClosed = errors.New("lane: closed")
	// ErrSessionClosed means a CLOSE frame ended the session.
	ErrSessionClosed = errors.New("lane: session closed")
)

// Defaults for the Options of the same names.
const (
	// DefaultPingInterval is the least time between PINGs on a lane with
	// TCP_NOTSENT_LOWAT. PINGs only ride along in records that carry DATA,
	// so an idle lane sends none.
	DefaultPingInterval = time.Second
	// DefaultPingTimeout ends a lane whose PING goes unanswered this long.
	DefaultPingTimeout = 15 * time.Second
	// DefaultLinger is how long a retiring lane waits for the peer's
	// close_notify.
	DefaultLinger = 10 * time.Second
)

const (
	// notSentLowat keeps the kernel's unsent data small (design §7), so the
	// queue stays in Tectonic's scheduler where packets can still be steered
	// to the fastest lane.
	notSentLowat = 32 << 10

	defaultRTT    = 100 * time.Millisecond
	defaultRate   = 1 << 20 // bytes/s before any estimate
	minRate       = 16 << 10
	minQueueDelay = 50 * time.Millisecond
	minQueueBytes = 64 << 10
	maxQueueBytes = 4 << 20
	activeWindow  = 2 * time.Second
	// Packets of smallMax bytes or less (pings, TCP ACKs and most of what
	// real-time traffic sends inside the tunnel) go out ahead of the larger
	// ones queued on a lane, up to smallQueueMax of them at a time, so a
	// bulk transfer does not make everything else wait behind it. The
	// receiver hands such packets on as they come, so sending them out of
	// turn costs nothing. WireGuard keepalives stay in the main queue:
	// they are in no hurry, and while the tunnel is idle they are held
	// back on purpose.
	smallMax        = 128
	smallQueueMax   = 512
	monitorInterval = 100 * time.Millisecond
	readBufferSize  = 64 << 10

	// Without TCP_NOTSENT_LOWAT, a lane caps the bytes it has written but
	// not yet seen confirmed by a PONG at a multiple of rate × base RTT,
	// and at least windowMin. The multiple depends on what the PONGs show:
	//
	//   - growthGain while they come back on time and the rate is still
	//     rising. A connection in slow start doubles what it carries every
	//     round trip, the rate is what it carried a round trip ago, and a
	//     tunnel that holds such a connection back delays its own traffic,
	//     which the TCP inside it takes as a sign to stop growing.
	//   - windowGain while they come back on time and the rate is steady:
	//     nothing is waiting below the lane, but nothing says there is
	//     room for much more either.
	//   - lateGain once they come back late: bytes are waiting below the
	//     lane, in the kernel or in a queue on the path. Anything more
	//     waits in the lane's own queue instead. There it can still be
	//     steered or, when the tunnel is offered more than it can carry,
	//     dropped, which the TCP inside reads as it would a full link. A
	//     queue on the path that overflows drops the lane's own segments,
	//     and the lane stalls on the retransmission.
	growthGain     = 3.0
	windowGain     = 2.0
	lateGain       = 1.5
	windowMin      = 64 << 10
	windowMax      = 64 << 20
	minRateSpan    = 20 * time.Millisecond
	baseRTTEpoch   = 10 * time.Second // the base RTT is the least seen over 10-20 s
	maxPings       = 8
	minPingSpacing = 2 * time.Millisecond
	maxPongHist    = 64

	// The scheduler is told how many unconfirmed bytes such a lane carries
	// before any of them waits in the kernel: what it was last seen to
	// deliver in one base RTT, times probeGain while its PONGs come back on
	// time. More than one, so that a lane the scheduler prefers is offered
	// a little more each round trip and takes over as fast as its
	// connection really grows. Not much more, and nothing more once PONGs
	// are late, because next to a busy lane a new connection soon stops
	// doubling, and what it is offered beyond what it can carry arrives
	// late and holds up the packets the other lanes delivered on time.
	probeGain = 1.25
	// A PONG is on time if it comes back within the base RTT plus an eighth
	// (and at least onTimeMin).
	onTimeMin = 4 * time.Millisecond
	// initialWindow is what a new TCP connection may send before any
	// acknowledgement: ten segments. A lane is taken to carry half of that
	// at once until its first rate sample, and again after it has sat
	// idle: whatever a connection that is not yet sending steadily is
	// given beyond its window waits a whole round trip for the first
	// acknowledgements.
	initialWindow = 10 * 1448
	coldWindow    = initialWindow / 2
	// The writer of a lane that is at its capacity (its PONGs are late and
	// its rate has stopped growing) also paces itself: it writes at no
	// more than paceGain times the lane's rate, after a burst of up to
	// paceBurst at that rate (and at least TCP's initial window). When the
	// tunnel's traffic arrives in a burst, as it does after the receiver
	// has held packets back, the burst waits in the lane's queue rather
	// than going out at once and overflowing a queue on the path, which
	// would stall the lane on a retransmission. A lane still growing is
	// not paced: its connection is in slow start, which sets its own pace.
	paceGain  = 1.5
	paceBurst = 4 * time.Millisecond
	// A late lane whose rate sample is under growing times its estimate has
	// stopped growing.
	growing = 1.1
	// After idleRestart without DATA (and at least four round trips), TCP
	// has shrunk its congestion window, so the lane starts over.
	idleRestart = 500 * time.Millisecond
	drainSpan   = 20 * time.Millisecond

	// A lane that wrote at least busyBytes in the last busyWindow is in a
	// bulk transfer: its records are packed up to 16 KB, waiting up to
	// coalesceDelay for one to fill, and one that is not full takes only a
	// few bytes of padding (design §8).
	busyWindow    = 10 * time.Millisecond
	busyBytes     = 16 << 10
	coalesceDelay = 2 * time.Millisecond
	// Outside a bulk transfer a record still waits up to flushDelay (and no
	// more than a sixteenth of the round trip) for more to go with it.
	// Packets inside the tunnel come in trains: a reply's segments, the
	// ACKs that answer them. Written one to a record, each pays for its own
	// TLS framing, its own padding and, being a little over one segment
	// with them, two TCP headers. A millisecond turns a train into one
	// record.
	flushDelay = time.Millisecond
	// limitNap is the longest the writer sleeps at once while the
	// session's send limit holds its DATA, so that a small packet or a
	// control frame that arrives meanwhile goes within that.
	limitNap = 2 * time.Millisecond
)

// Handler receives a lane's events. Every callback runs on the lane's reader
// goroutine, so a slow callback delays that lane's later frames, never
// another lane's.
type Handler struct {
	// Data is called for every DATA frame. pkt is only valid during the call.
	Data func(l *Lane, pkt []byte)
	// Welcome is called on a client lane when WELCOME arrives.
	Welcome func(l *Lane, w wire.Welcome)
	// Lost is called when the peer says it dropped WireGuard datagrams
	// and will never send them.
	Lost func(l *Lane, lost wire.Lost)
	// Retire is called when the peer sends RETIRE.
	Retire func(l *Lane)
	// Close is called when the peer sends CLOSE, which ends the session.
	Close func(l *Lane, reason wire.CloseReason)
	// End is called once, when the lane's reader has stopped: no more
	// frames will arrive on this lane.
	End func(l *Lane)
}

// Limiter is a limit on what a session sends, shared by its lanes (see
// sched.Limiter). A lane reports what its connection does, asks before it
// writes DATA, and says what it wrote.
type Limiter interface {
	// Report takes what the lane's connection has done since the lane
	// last reported.
	Report(now time.Time, p Progress)
	// Wait is how long the lane must hold its next DATA. Control frames
	// and small packets do not wait.
	Wait(now time.Time) time.Duration
	// Wrote notes n bytes of records carrying DATA written.
	Wrote(now time.Time, n int)
}

// Progress is what a lane's connection did over a stretch of time, as the
// kernel counts it.
type Progress struct {
	// Sent is the bytes sent, retransmissions included; Resent the bytes
	// sent again; Delivered the bytes the peer has acknowledged, in order
	// or not.
	Sent, Resent, Delivered uint64
	// RTT is the smoothed round trip, and Queued whether it is well above
	// the least the connection has seen: a queue on the path.
	RTT    time.Duration
	Queued bool
}

// Options configure a lane.
type Options struct {
	Role    Role
	Handler Handler
	// Planner shapes the lane's records. Nil means the default profile.
	Planner *shape.Planner
	// Profiles is where a client lane looks up the profile WELCOME names.
	Profiles *shape.Set
	// Raw is the TCP connection under the lane's TLS, used for TCP_INFO.
	// It may be nil, or a connection without a file descriptor.
	Raw net.Conn
	// InitialRTT seeds the RTT estimate until the first measurement.
	InitialRTT time.Duration
	// Limiter, if set, is the send limit the lane shares with the other
	// lanes of its session.
	Limiter Limiter
	// PingInterval, PingTimeout and Linger override the defaults.
	PingInterval time.Duration
	PingTimeout  time.Duration
	Linger       time.Duration
	Logger       *slog.Logger
}

var laneIDs atomic.Uint64

// Lane is one TLS connection carrying Tectonic frames.
type Lane struct {
	id      uint64
	conn    net.Conn
	rc      syscall.RawConn
	br      *bufio.Reader // what rd reads from
	rd      *wire.Reader
	role    Role
	h       Handler
	log     *slog.Logger
	created time.Time

	profiles *shape.Set
	planner  atomic.Pointer[shape.Planner]

	pingInterval time.Duration
	pingTimeout  time.Duration
	linger       time.Duration

	mu         sync.Mutex
	ctrl       []byte   // encoded control frames, sent before any DATA
	data       [][]byte // queued datagrams
	dataAt     []int64  // when each was queued, unix ns
	small      [][]byte // queued small datagrams, which go out first
	queued     int      // bytes of DATA frames queued, headers included
	keepalives int      // how many queued datagrams are WireGuard keepalives
	kaSince    time.Time
	kaDelay    time.Duration
	lastActive time.Time // last non-keepalive DATA in either direction
	retiring   bool      // no new DATA; drain, then close_notify
	closing    bool      // a CLOSE is queued; stop after sending it
	started    bool

	wake        chan struct{}
	monitorWake chan struct{}
	sleeping    atomic.Bool
	done        chan struct{}
	doneOnce    sync.Once
	err         error

	welcomed chan struct{}
	welcome  wire.Welcome

	// ack is the size of the record that ends a client lane's opening, or
	// 0 if it has none: the one Chrome acknowledges the server's SETTINGS
	// with. The reader sets ackDue when the server's first bytes arrive,
	// and the writer sends the record (see writeAck).
	ack    int
	ackDue atomic.Bool

	queuedA     atomic.Int64
	srtt        atomic.Int64 // ns
	minRTT      atomic.Int64 // ns
	rate        atomic.Uint64
	rttSampled  atomic.Bool
	rateSampled atomic.Bool  // a sample from a busy lane set the rate
	rateSeen    atomic.Bool  // any delivery-rate sample has been taken
	lastRetrans atomic.Int64 // unix ns of the last retransmission seen
	stalled     atomic.Bool  // TCP_INFO reports an unrecovered timeout
	hasTCPInfo  atomic.Bool
	bytesSent   atomic.Uint64
	bytesRecv   atomic.Uint64
	dataSent    atomic.Uint64
	dataRecv    atomic.Uint64
	pktsSent    atomic.Uint64
	pktsRecv    atomic.Uint64
	lastSend    atomic.Int64
	lastRecv    atomic.Int64

	// lowat is whether TCP_NOTSENT_LOWAT is in effect. Without it the
	// writer paces itself on PONGs instead.
	lowat bool
	// sock is what the kernel last said about the connection, which the
	// estimate for a lane with TCP_NOTSENT_LOWAT is made from; sockPoll is
	// when it was last read, or is being read.
	sock     atomic.Pointer[sockState]
	sockPoll atomic.Int64
	// paced counts the signs that the connection spaces its packets out
	// (see paces).
	paced atomic.Int32
	// limit is the session's send limit, if it has one, and the counters
	// below what the connection had done when the lane last looked
	// (guarded by pingMu).
	limit        Limiter
	limSent      uint64
	limResent    uint64
	limDelivered uint32
	limInit      bool
	confirmedA   atomic.Uint64 // mirrors confirmed, for ETA
	// tracked counts the bytes written in records that carry DATA or a
	// PING. It is what PINGs mark positions in and PONGs confirm; records
	// of control frames alone are left out, because on a lane that only
	// answers PINGs nothing would ever confirm them.
	tracked atomic.Uint64
	baseRTT atomic.Int64 // ns: least PONG round trip over the last 10-20 s
	// ponged is set once any PONG has come back. Until then a lane without
	// TCP_NOTSENT_LOWAT has shown nothing: not that its first flight has
	// arrived, nor how long that takes.
	ponged atomic.Bool
	// late is set while the last PONG came back later than on time: bytes
	// are waiting below the lane. full is set while the lane is also at
	// its capacity: the rate has stopped growing.
	late     atomic.Bool
	full     atomic.Bool
	growing  atomic.Bool   // the last rate sample was well above the estimate
	lastPong atomic.Int64  // unix ns of the last PONG
	lastData atomic.Int64  // unix ns of the last DATA written
	drain    atomic.Uint64 // float64 bits: bytes/s written while backlogged

	pingMu        sync.Mutex
	pings         []outPing // outstanding, oldest first
	lastPingSent  time.Time
	lastPingBytes uint64    // bytes written when the last PING went
	rateFrom      time.Time // start of the current delivery-rate sample
	rateFromBytes uint64
	rateLimited   bool   // the lane wasn't kept busy at some point in the sample
	confirmed     uint64 // bytes the peer has confirmed receiving
	baseCur       time.Duration
	basePrev      time.Duration
	baseEpoch     time.Time
	appLimited    bool // the queue ran dry since the last PING
	lastRetransN  uint64
	retransInit   bool
	hist          []pongRec // recent PONGs, oldest first, for rate samples
}

// outPing is a PING waiting for its PONG.
type outPing struct {
	tok     uint64
	at      time.Time
	bytes   uint64 // tracked bytes written up to and including the PING's record
	limited bool   // the lane was not kept busy before this PING
}

// pongRec is what one PONG confirmed.
type pongRec struct {
	at      time.Time
	bytes   uint64
	limited bool
}

// New wraps an established TLS connection as a lane. r is where frames are
// read from; pass nil to read from conn. The server passes the buffered
// reader it used to check HELLO, so nothing it has read is lost. The lane
// does nothing until Start.
func New(conn net.Conn, r io.Reader, opts Options) *Lane {
	if r == nil {
		r = conn
	}
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, readBufferSize)
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	now := time.Now()
	l := &Lane{
		id:          laneIDs.Add(1),
		conn:        conn,
		br:          br,
		rd:          wire.NewReader(br),
		role:        opts.Role,
		h:           opts.Handler,
		created:     now,
		profiles:    opts.Profiles,
		limit:       opts.Limiter,
		lastActive:  now,
		wake:        make(chan struct{}, 1),
		monitorWake: make(chan struct{}, 1),
		done:        make(chan struct{}),
		welcomed:    make(chan struct{}),

		pingInterval: cmp.Or(opts.PingInterval, DefaultPingInterval),
		pingTimeout:  cmp.Or(opts.PingTimeout, DefaultPingTimeout),
		linger:       cmp.Or(opts.Linger, DefaultLinger),
	}
	l.log = log.With("lane", l.id, "role", opts.Role.String())
	pl := opts.Planner
	if pl == nil {
		pl = shape.NewPlanner(nil)
	}
	l.planner.Store(pl)
	rtt := opts.InitialRTT
	if rtt <= 0 {
		rtt = defaultRTT
	}
	l.srtt.Store(int64(rtt))
	l.rate.Store(math.Float64bits(defaultRate))
	if sc, ok := opts.Raw.(syscall.Conn); ok {
		if rc, err := sc.SyscallConn(); err == nil {
			l.rc = rc
			l.lowat = setNotSentLowat(rc, notSentLowat)
			if ti, ok := readTCPInfo(rc); ok {
				l.hasTCPInfo.Store(true)
				if l.lowat {
					if pacedByDesign(rc) {
						l.paced.Store(pacedAfter)
					}
					l.noteTCPInfo(ti, now)
				}
			}
		}
	}
	if !l.lowat {
		l.rate.Store(math.Float64bits(initialWindow / rtt.Seconds()))
	}
	if l.role == Server {
		close(l.welcomed) // only client lanes wait for WELCOME
	}
	return l
}

// ID returns a number that identifies the lane in logs.
func (l *Lane) ID() uint64 { return l.id }

// Role returns which end of the lane this is.
func (l *Lane) Role() Role { return l.role }

// Start writes the lane's opening and starts its goroutines. first holds the
// frames that open the lane: HELLO and the first DATA from a client, WELCOME
// from the server.
//
// They go out as the records the shaping profile lists for a lane's start
// (shape.Profile.ClientFirstFlight and ServerFirstFlight), which are the
// records Chrome and an HTTP/2 server open a connection with. The frames and
// the padding after them are one stream, cut where each record ends: HELLO
// is longer than Chrome's first record, so it begins there and ends in the
// second, ahead of the first DATA. Nothing goes in front of HELLO, and a
// profile cannot make the first record shorter than the part of HELLO the
// node needs in one record to know a login (shape.MinClientFirstRecord).
// Every record is written before Start returns; nothing in first waits for
// the peer. A client's opening has one more record, sent when the server's
// first bytes arrive (see writeAck).
//
// The CDN carrier is a WebSocket. It has no such opening, and HELLO must
// arrive in its first message, so there the same bytes go in one message.
func (l *Lane) Start(first []byte) error {
	l.mu.Lock()
	if l.started {
		l.mu.Unlock()
		return errors.New("lane: already started")
	}
	l.started = true
	l.mu.Unlock()

	now := time.Now()
	pl := l.planner.Load()
	n := len(first)
	if !l.lowat {
		n += wire.HeaderLen + wire.PingLen
	}
	sizes := pl.FirstFlight(l.role == Client, n)
	total := 0
	for _, size := range sizes {
		total += size
	}
	buf := wire.AppendPadding(first, total-n)
	if !l.lowat {
		// The PONG shows the opening has arrived and how long a round
		// trip takes; until it is back the scheduler does not count on
		// the lane. The PING is the last frame, so its PONG answers for
		// every record of the opening.
		p := outPing{tok: wire.NewPingToken(), at: now, bytes: uint64(total), limited: true}
		buf = wire.AppendHeader(buf, wire.TypePing, wire.PingLen)
		buf = wire.AppendPing(buf, p.tok)
		l.pingMu.Lock()
		l.pings = append(l.pings, p)
		l.lastPingSent, l.lastPingBytes = now, uint64(total)
		l.pingMu.Unlock()
	}
	if _, ws := l.conn.(*wsConn); ws {
		sizes = []int{total}
	} else if l.role == Client {
		l.ack = pl.FirstFlightAck()
	}
	for _, size := range sizes {
		if _, err := l.conn.Write(buf[:size]); err != nil {
			l.finish(err)
			return err
		}
		buf = buf[size:]
	}
	l.bytesSent.Add(uint64(total))
	if !l.lowat {
		l.tracked.Add(uint64(total))
	}
	l.lastSend.Store(time.Now().UnixNano())
	go l.run()
	return nil
}

// writeAck writes the record that ends a client lane's opening. Chrome
// acknowledges the server's SETTINGS in a record of its own as soon as it
// arrives, whatever else it is sending, so this one is nothing but padding
// and shares its record with nothing. It runs on the writer's goroutine,
// which is the only one that writes once the lane has started.
func (l *Lane) writeAck() error {
	l.ackDue.Store(false)
	buf := wire.AppendPadding(make([]byte, 0, l.ack), l.ack)
	if _, err := l.conn.Write(buf); err != nil {
		return err
	}
	l.bytesSent.Add(uint64(len(buf)))
	l.lastSend.Store(time.Now().UnixNano())
	return nil
}

// Send queues one WireGuard datagram as a DATA frame. It copies pkt. It
// returns false if the lane is retiring or closed, or if the packets
// already in its queue have been waiting for about a round trip; the
// scheduler then tries another lane.
func (l *Lane) Send(pkt []byte) bool {
	if len(pkt) > wire.MaxBodyLen {
		return false
	}
	n := wire.HeaderLen + len(pkt)
	ka := shape.IsKeepalive(pkt)
	now := time.Now()
	l.mu.Lock()
	if l.retiring || l.closing || l.isDone() {
		l.mu.Unlock()
		return false
	}
	if l.queued >= minQueueBytes && len(l.data) > 0 && (len(pkt) > smallMax || ka || len(l.small) >= smallQueueMax) {
		// The queue is full once its oldest packet has waited about a
		// round trip. Going by how long packets really wait, rather than
		// by the bytes queued over the estimated rate, gives the tunnel's
		// traffic the same room whether the estimate is right or, as while
		// a connection is still in slow start, well behind.
		limit := max(minQueueDelay, time.Duration(l.srtt.Load()))
		if l.queued+n > maxQueueBytes || now.UnixNano()-l.dataAt[0] > int64(limit) {
			l.mu.Unlock()
			return false
		}
	}
	if len(pkt) <= smallMax && !ka && len(l.small) < smallQueueMax {
		l.small = append(l.small, append([]byte(nil), pkt...))
	} else {
		l.data = append(l.data, append([]byte(nil), pkt...))
		l.dataAt = append(l.dataAt, now.UnixNano())
	}
	l.queued += n
	if ka {
		if l.keepalives == 0 {
			l.kaSince = now
			l.kaDelay = l.planner.Load().KeepaliveDelay()
		}
		l.keepalives++
	} else {
		l.lastActive = now
	}
	l.queuedA.Store(int64(l.queued))
	l.mu.Unlock()
	l.signal(l.wake)
	l.kickMonitor()
	return true
}

// Lost tells the peer that datagrams were dropped and will never be sent,
// so that it does not wait for them (see wire.Lost). The notice goes out
// ahead of any DATA queued on the lane. It returns false if the lane is
// retiring or closed.
func (l *Lane) Lost(lost wire.Lost) bool {
	l.mu.Lock()
	if l.retiring || l.closing || l.isDone() {
		l.mu.Unlock()
		return false
	}
	l.ctrl = wire.AppendLost(l.ctrl, lost)
	l.mu.Unlock()
	l.signal(l.wake)
	return true
}

// Retire sends RETIRE: no new DATA goes on this lane. The lane finishes
// sending what is queued, closes with TLS close_notify, and ends once the
// peer has done the same.
func (l *Lane) Retire() {
	l.mu.Lock()
	if !l.retiring && !l.closing {
		l.retiring = true
		l.ctrl = wire.AppendFrame(l.ctrl, wire.TypeRetire, nil)
	}
	l.mu.Unlock()
	l.signal(l.wake)
}

// SendClose ends the whole session: queued DATA is dropped, CLOSE is sent,
// and the lane closes.
func (l *Lane) SendClose(reason wire.CloseReason) {
	l.mu.Lock()
	if !l.closing {
		l.closing = true
		l.retiring = true
		l.data, l.dataAt, l.small = nil, nil, nil
		l.queued, l.keepalives = 0, 0
		l.queuedA.Store(0)
		l.ctrl = wire.AppendFrame(l.ctrl, wire.TypeClose, []byte{byte(reason)})
	}
	started := l.started
	l.mu.Unlock()
	if !started {
		l.finish(ErrSessionClosed)
		return
	}
	l.signal(l.wake)
}

// Close ends the lane at once, without RETIRE.
func (l *Lane) Close() error {
	l.finish(ErrClosed)
	return nil
}

// Done is closed when the lane has ended.
func (l *Lane) Done() <-chan struct{} { return l.done }

// Err returns why the lane ended, or nil while it is open. A lane that
// retired cleanly ends with a nil error.
func (l *Lane) Err() error {
	select {
	case <-l.done:
		return l.err
	default:
		return nil
	}
}

// Welcomed is closed when a client lane receives WELCOME. It is closed from
// the start on server lanes.
func (l *Lane) Welcomed() <-chan struct{} { return l.welcomed }

// Welcome returns the WELCOME a client lane received, if any.
func (l *Lane) Welcome() (wire.Welcome, bool) {
	select {
	case <-l.welcomed:
		return l.welcome, l.role == Client
	default:
		return wire.Welcome{}, false
	}
}

// Retiring reports whether the lane has stopped taking new DATA.
func (l *Lane) Retiring() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.retiring
}

// Age is how long ago the lane was created.
func (l *Lane) Age() time.Duration { return time.Since(l.created) }

// SetPlanner switches the lane's shaping profile.
func (l *Lane) SetPlanner(pl *shape.Planner) {
	if pl != nil {
		l.planner.Store(pl)
	}
}

// RTT is the smoothed round-trip estimate.
func (l *Lane) RTT() time.Duration { return time.Duration(l.srtt.Load()) }

// Rate is the delivery-rate estimate in bytes per second.
func (l *Lane) Rate() float64 {
	r := math.Float64frombits(l.rate.Load())
	if l.lowat {
		// With TCP_NOTSENT_LOWAT the kernel takes bytes only as fast as it
		// sends them, so what a backlogged lane has just been writing is a
		// fresher floor than the last TCP_INFO poll.
		r = max(r, math.Float64frombits(l.drain.Load()))
	}
	return max(r, minRate)
}

// Queued is the number of bytes waiting in the lane's queue.
func (l *Lane) Queued() int { return int(l.queuedA.Load()) }

// ETA estimates when n more bytes queued on this lane would be delivered
// (design §7):
//
//	eta(lane) = queued_bytes(lane) / rate(lane) + srtt(lane) / 2
//
// With TCP_NOTSENT_LOWAT, queued_bytes also counts what the kernel has
// taken and not sent, and the rate is what the connection can send now:
// its window each round trip, or its pacing rate (see sockState).
//
// Without TCP_NOTSENT_LOWAT the queue is not all in the lane: bytes it has
// written may still be waiting in the kernel. They count as queued too, so
// queued_bytes is then everything not yet confirmed by a PONG, less what
// the lane has delivered since and what the connection carries in flight
// without any of it waiting (see clear), and the round trip is the base
// RTT, which that wait does not inflate. Such a lane is also not counted on
// until its first PONG is back, a round trip after it opens: only then is
// its first flight known to have arrived.
func (l *Lane) ETA(n int) time.Duration {
	q := int(l.queuedA.Load()) + n
	if l.lowat {
		// The kernel holds part of the queue too, and says how much the
		// connection can send (see sockState).
		now := time.Now()
		if s := l.kernel(now); s != nil {
			idle := time.Duration(now.UnixNano() - l.lastSend.Load())
			wait := s.wait(float64(q), idle)
			// The lane's own queue leaves no faster than it has been
			// leaving: the session's send limit may be holding it.
			if d := math.Float64frombits(l.drain.Load()); d > 0 {
				wait = max(wait, time.Duration(float64(q)/d*float64(time.Second)))
			}
			return wait + l.RTT()/2
		}
		return l.backlog(q) + l.RTT()/2
	}
	eta := l.backlog(q) + l.base()/2
	if !l.ponged.Load() {
		eta += l.base()
	}
	return eta
}

// backlog estimates how long it takes the lane to start delivering the last
// of q bytes in its queue.
func (l *Lane) backlog(q int) time.Duration {
	over, rate := float64(q), l.Rate()
	if !l.lowat {
		over += l.outstanding(l.tracked.Load(), time.Now()) - l.clear()
		if over <= 0 {
			return 0
		}
	}
	return time.Duration(over / rate * float64(time.Second))
}

// outstanding estimates how many of the first sent bytes a lane without
// TCP_NOTSENT_LOWAT has written have not arrived yet at now: those no PONG
// has confirmed, less what the lane has gone on delivering since the last
// PONG. PONGs come a few to a round trip.
func (l *Lane) outstanding(sent uint64, now time.Time) float64 {
	confirmed := l.confirmedA.Load()
	if sent <= confirmed {
		return 0
	}
	since := time.Duration(now.UnixNano() - l.lastPong.Load())
	return max(float64(sent-confirmed)-l.Rate()*min(since, l.pingSpacing()).Seconds(), 0)
}

// pingSpacing is the least time between PINGs on a lane that paces itself
// on them.
func (l *Lane) pingSpacing() time.Duration {
	return min(l.pingInterval, max(l.RTT()/4, minPingSpacing))
}

// clear is how many unconfirmed bytes a lane without TCP_NOTSENT_LOWAT is
// taken to carry with none of them waiting in the kernel: what it delivers
// in one base RTT, a little more while its PONGs come back on time, and half
// of TCP's initial window while its rate is unknown.
func (l *Lane) clear() float64 {
	if !l.rateSeen.Load() {
		return coldWindow
	}
	bdp := l.Rate() * l.base().Seconds()
	if l.late.Load() {
		return bdp
	}
	return probeGain * bdp
}

// unconfirmed is how many bytes a lane without TCP_NOTSENT_LOWAT has
// written that no PONG has confirmed.
func (l *Lane) unconfirmed() uint64 {
	sent, confirmed := l.tracked.Load(), l.confirmedA.Load()
	if sent < confirmed {
		return 0
	}
	return sent - confirmed
}

// BaseRTT is the lane's round trip without any queueing, as far as it is
// known: what a new lane beside this one can expect.
func (l *Lane) BaseRTT() time.Duration {
	if l.lowat {
		if m := time.Duration(l.minRTT.Load()); m > 0 {
			return m
		}
		return l.RTT()
	}
	return l.base()
}

// base is the lane's round trip without any queueing: the base RTT once a
// PONG has measured it, and the smoothed estimate until then.
func (l *Lane) base() time.Duration {
	if b := time.Duration(l.baseRTT.Load()); b > 0 {
		return b
	}
	return l.RTT()
}

// Retransmitting reports whether the lane is recovering from loss, which is
// when the scheduler duplicates small urgent packets onto another lane.
func (l *Lane) Retransmitting() bool {
	if l.isDone() {
		return false
	}
	if l.stalled.Load() {
		return true
	}
	now := time.Now().UnixNano()
	win := max(2*l.srtt.Load(), int64(200*time.Millisecond))
	if last := l.lastRetrans.Load(); last != 0 && now-last < win {
		return true
	}
	if !l.hasTCPInfo.Load() {
		// Without TCP_INFO, a PING that is long overdue is the best sign
		// that the connection is stuck retransmitting.
		l.pingMu.Lock()
		stuck := len(l.pings) > 0 && time.Since(l.pings[0].at) > 2*l.RTT()+100*time.Millisecond
		l.pingMu.Unlock()
		return stuck
	}
	return false
}

// Stats is a snapshot of a lane's counters and estimates.
type Stats struct {
	Created        time.Time
	SRTT           time.Duration
	MinRTT         time.Duration
	Rate           float64 // bytes/s
	Queued         int
	BytesSent      uint64 // everything written, padding included
	BytesRecv      uint64
	DataSent       uint64 // WireGuard payload bytes
	DataRecv       uint64
	PacketsSent    uint64
	PacketsRecv    uint64
	Retransmitting bool
	TCPInfo        bool // estimates come from TCP_INFO rather than PING/PONG
	NotSentLowat   bool // TCP_NOTSENT_LOWAT is in effect; otherwise the lane paces on PONGs
	Unconfirmed    uint64
	Window         uint64 // the cap on unconfirmed bytes without TCP_NOTSENT_LOWAT
	PingsOut       int
}

// Stats returns a snapshot of the lane's counters.
func (l *Lane) Stats() Stats {
	l.pingMu.Lock()
	pings := len(l.pings)
	l.pingMu.Unlock()
	unconfirmed := l.unconfirmed()
	return Stats{
		NotSentLowat:   l.lowat,
		Unconfirmed:    unconfirmed,
		Window:         uint64(l.windowBytes()),
		PingsOut:       pings,
		Created:        l.created,
		SRTT:           l.RTT(),
		MinRTT:         time.Duration(l.minRTT.Load()),
		Rate:           l.Rate(),
		Queued:         l.Queued(),
		BytesSent:      l.bytesSent.Load(),
		BytesRecv:      l.bytesRecv.Load(),
		DataSent:       l.dataSent.Load(),
		DataRecv:       l.dataRecv.Load(),
		PacketsSent:    l.pktsSent.Load(),
		PacketsRecv:    l.pktsRecv.Load(),
		Retransmitting: l.Retransmitting(),
		TCPInfo:        l.hasTCPInfo.Load(),
	}
}

func (l *Lane) String() string { return fmt.Sprintf("lane %d (%s)", l.id, l.role) }

func (l *Lane) isDone() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

func (l *Lane) signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

func (l *Lane) kickMonitor() {
	if l.sleeping.CompareAndSwap(true, false) {
		l.signal(l.monitorWake)
	}
}

// finish ends the lane once, recording why.
func (l *Lane) finish(err error) {
	l.doneOnce.Do(func() {
		l.err = err
		close(l.done)
		l.conn.Close()
		l.mu.Lock()
		l.data, l.dataAt, l.small, l.ctrl = nil, nil, nil, nil
		l.queued, l.keepalives = 0, 0
		l.queuedA.Store(0)
		l.mu.Unlock()
		if err != nil {
			l.log.Debug("lane ended", "err", err)
		} else {
			l.log.Debug("lane retired")
		}
	})
}

// run supervises the reader, writer and monitor.
func (l *Lane) run() {
	rerr := make(chan error, 1)
	werr := make(chan error, 1)
	go func() {
		err := l.readLoop()
		if l.h.End != nil {
			l.h.End(l)
		}
		rerr <- err
	}()
	go func() { werr <- l.writeLoop() }()
	go l.monitor()

	var rDone, wDone bool
	var linger <-chan time.Time
	for !(rDone && wDone) {
		select {
		case err := <-rerr:
			rDone = true
			if err == nil {
				l.finish(ErrSessionClosed)
				return
			}
			if !errors.Is(err, io.EOF) {
				l.finish(err)
				return
			}
			l.mu.Lock()
			retiring := l.retiring
			l.mu.Unlock()
			if !retiring {
				l.finish(ErrPeerClosed)
				return
			}
		case err := <-werr:
			wDone = true
			if err != nil {
				l.finish(err)
				return
			}
			l.mu.Lock()
			closing := l.closing
			l.mu.Unlock()
			if closing {
				l.finish(ErrSessionClosed)
				return
			}
		case <-linger:
			l.finish(nil)
			return
		case <-l.done:
			return
		}
		if linger == nil {
			linger = time.After(l.linger)
		}
	}
	l.finish(nil)
}

func (l *Lane) readLoop() error {
	first := l.role == Client
	if l.ack > 0 {
		// The server's first bytes are here, or the connection is over.
		if _, err := l.br.Peek(1); err != nil {
			return fmt.Errorf("%w: %v", ErrLoginFailed, err)
		}
		l.ackDue.Store(true)
		l.signal(l.wake)
	}
	for {
		typ, body, err := l.rd.Next()
		if err != nil {
			if first {
				return fmt.Errorf("%w: %v", ErrLoginFailed, err)
			}
			return err
		}
		now := time.Now()
		l.bytesRecv.Add(uint64(wire.HeaderLen + len(body)))
		l.lastRecv.Store(now.UnixNano())
		if first {
			first = false
			if typ != wire.TypeWelcome {
				return ErrLoginFailed
			}
			w, err := wire.ParseWelcome(body)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrLoginFailed, err)
			}
			l.welcome = w
			if l.profiles != nil {
				l.planner.Store(shape.NewPlanner(l.profiles.Get(w.Profile)))
			}
			close(l.welcomed)
			if l.h.Welcome != nil {
				l.h.Welcome(l, w)
			}
			continue
		}
		switch typ {
		case wire.TypeData:
			l.dataRecv.Add(uint64(len(body)))
			l.pktsRecv.Add(1)
			if !shape.IsKeepalive(body) {
				l.mu.Lock()
				l.lastActive = now
				l.mu.Unlock()
				l.kickMonitor()
			}
			if l.h.Data != nil {
				l.h.Data(l, body)
			}
		case wire.TypePing:
			tok, pong, err := wire.ParsePing(body)
			if err != nil {
				continue
			}
			if pong {
				l.onPong(tok, now)
			} else {
				l.mu.Lock()
				if !l.closing {
					l.ctrl = wire.AppendHeader(l.ctrl, wire.TypePing, wire.PingLen)
					l.ctrl = wire.AppendPong(l.ctrl, tok)
				}
				l.mu.Unlock()
				l.signal(l.wake)
			}
		case wire.TypeLost:
			if lost, err := wire.ParseLost(body); err == nil && l.h.Lost != nil {
				l.h.Lost(l, lost)
			}
		case wire.TypeRetire:
			l.mu.Lock()
			already := l.retiring
			l.retiring = true
			l.mu.Unlock()
			l.signal(l.wake)
			if !already && l.h.Retire != nil {
				l.h.Retire(l)
			}
		case wire.TypeClose:
			if l.h.Close != nil {
				l.h.Close(l, wire.ParseClose(body))
			}
			return nil
		default:
			// PAD, a stray HELLO or WELCOME, and frame types from newer
			// peers are skipped.
		}
	}
}

func (l *Lane) writeLoop() error {
	buf := make([]byte, 0, shape.MaxRecord+wire.MaxFrameLen)
	// carry is the rest of a DATA frame that the last record began and
	// had no room to finish. It opens the next record, ahead of everything
	// else, and waits for nothing that would not have held the whole
	// packet back. Until it is written it counts as queued, like the
	// packets behind it, so that the scheduler's estimate for the lane
	// misses nothing.
	var carry []byte
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	// Bulk detection: bytes written in the current busyWindow.
	var winStart, coalesceUntil time.Time
	var winBytes int
	busy := false
	// The drain rate: bytes written since drainFrom with the queue never
	// empty.
	var drainFrom time.Time
	var drainBytes int
	var pace pacer
	// more is set when the last record left packets behind on purpose
	// (see shape.Planner.Split), or stopped part of the way through one:
	// the next record goes out at once.
	more := false
	for {
		// The record that ends a client's opening goes by itself, as soon
		// as the reader has the server's first bytes. It cannot go between
		// the two parts of a packet, so while one is unfinished it waits,
		// and the record that finishes that packet ends with a whole one
		// (see put): in a transfer every full record ends inside a packet,
		// and the opening would wait for the transfer to be over.
		ackWaits := l.ackDue.Load()
		if ackWaits && len(carry) == 0 {
			if err := l.writeAck(); err != nil {
				return err
			}
			ackWaits = false
		}
		l.mu.Lock()
		if len(carry) == 0 && len(l.ctrl) == 0 && len(l.data) == 0 && len(l.small) == 0 {
			retiring := l.retiring
			l.mu.Unlock()
			drainFrom = time.Time{}
			l.drain.Store(0)
			if retiring {
				return l.closeWrite()
			}
			select {
			case <-l.wake:
			case <-l.done:
				return nil
			}
			continue
		}

		now := time.Now()
		pl := l.planner.Load()
		kaOnly := len(carry) == 0 && len(l.ctrl) == 0 && len(l.small) == 0 && l.keepalives == len(l.data)
		idle := kaOnly && now.Sub(l.lastActive) >= pl.IdleAfter()
		if idle && !l.retiring {
			// Absorb keepalives into idle behaviour: hold them a random
			// while instead of ticking on WireGuard's timer.
			if wait := l.kaSince.Add(l.kaDelay).Sub(now); wait > 0 {
				l.mu.Unlock()
				timer.Reset(wait)
				select {
				case <-l.wake:
				case <-timer.C:
				case <-l.done:
					return nil
				}
				timer.Stop()
				continue
			}
		}

		if !l.lowat && len(l.data) > 0 {
			last := time.Unix(0, l.lastData.Load())
			if idle := now.Sub(last); idle > max(idleRestart, 4*l.RTT()) && l.rateSeen.Load() {
				l.restart()
			}
		}
		// Without TCP_NOTSENT_LOWAT, DATA waits while the window of
		// unconfirmed bytes is full; control frames still go.
		gated := !l.lowat && !l.closing && len(l.data) > 0 && !l.windowOpen()
		if gated && len(l.ctrl) == 0 && len(l.small) == 0 && !l.needCoverPing() {
			l.mu.Unlock()
			select {
			case <-l.wake: // a PONG opened the window, or new control frames
			case <-l.done:
				return nil
			}
			continue
		}
		// The session's send limit: DATA waits its turn. Control frames
		// and small packets go regardless.
		held := false
		if l.limit != nil && !l.closing && len(l.data) > 0 {
			if wait := l.limit.Wait(now); wait > 0 {
				if len(l.ctrl) == 0 && len(l.small) == 0 {
					l.mu.Unlock()
					timer.Reset(min(wait, limitNap))
					select {
					case <-timer.C:
					case <-l.done:
						return nil
					}
					timer.Stop()
					continue
				}
				held = true
			}
		}
		if l.full.Load() && !gated && !l.closing && len(l.ctrl) == 0 && len(l.small) == 0 && len(l.data) > 0 {
			if wait := pace.wait(now, paceGain*l.Rate()); wait > 0 {
				l.mu.Unlock()
				timer.Reset(wait)
				select {
				case <-timer.C:
				case <-l.done:
					return nil
				}
				timer.Stop()
				continue
			}
		}
		// Give a record a moment to fill.
		if !more && !gated && !held && !idle && !l.retiring && !l.closing &&
			l.queued+len(l.ctrl) < shape.MaxRecord-wire.MaxFrameLen/32 {
			if coalesceUntil.IsZero() {
				hold := min(flushDelay, l.RTT()/16)
				if busy && len(l.small) == 0 {
					hold = coalesceDelay
				}
				coalesceUntil = now.Add(hold)
			}
			if wait := coalesceUntil.Sub(now); wait > 0 {
				l.mu.Unlock()
				timer.Reset(wait)
				select {
				case <-l.wake:
				case <-timer.C:
				case <-l.done:
					return nil
				}
				timer.Stop()
				continue
			}
		}
		coalesceUntil = time.Time{}

		// The rest of a frame the last record began goes first. Nothing
		// may come between the two parts of a frame, so a record that
		// cannot hold all of what is left holds nothing else.
		carried := min(len(carry), shape.MaxRecord)
		buf = append(buf[:0], carry[:carried]...)
		carry = carry[:copy(carry, carry[carried:])]
		// cut is set when the record ends inside a frame: it is full to
		// the last byte, and what did not fit is in carry.
		cut := len(carry) > 0
		closing, pinged := false, false
		limit, reserve := shape.MaxRecord, 0
		queuedBefore := l.queued
		// A CLOSE may have emptied the queue from under it.
		l.queued = max(l.queued-carried, 0)
		var dataBytes, pkts, real int
		if !cut {
			buf = append(buf, l.ctrl...)
			l.ctrl = l.ctrl[:0]
			closing = l.closing
			// A record is no larger than the connection sends in a moment
			// (see sockState.recordLimit); what is left over follows in
			// the next.
			if l.lowat {
				if s := l.sock.Load(); s != nil {
					limit = s.recordLimit()
				}
			}
			// A PING rides at the end of a record; if one is due, it
			// has a place kept.
			if l.pingDue(now, gated) {
				reserve = wire.HeaderLen + wire.PingLen
			}
			// However small the limit, a record takes one packet: it
			// finishes the one it opens with, or holds as much as the
			// first one waiting.
			first := 0
			switch {
			case len(l.small) > 0:
				first = wire.HeaderLen + len(l.small[0])
			case !gated && !held && len(l.data) > 0:
				first = wire.HeaderLen + len(l.data[0])
			}
			// room is how many more bytes of DATA frames the record
			// takes.
			room := min(max(limit, len(buf)-carried+max(carried, first)+reserve), shape.MaxRecord) - len(buf) - reserve
			// An interactive record is padded past a bucket, so a few
			// queued packets that fit in one record may cost less padding
			// divided between two.
			take := len(l.small) + len(l.data)
			if n := take; n > 1 && n <= shape.MaxSplit && l.queued <= room && !gated && !held && !busy && !idle &&
				pl.Mode(l.queued, false) == shape.Interactive {
				var sizes [shape.MaxSplit]int
				for i, p := range l.small {
					sizes[i] = wire.HeaderLen + len(p)
				}
				for i, p := range l.data {
					sizes[len(l.small)+i] = wire.HeaderLen + len(p)
				}
				take = pl.Split(len(buf), sizes[:n])
			}
			split := take < len(l.small)+len(l.data)
			// put adds p to the record as a DATA frame and reports
			// whether it did. A packet that does not fit in a record
			// that may be full is cut: what there is room for goes in,
			// and the next record opens with the rest. The reader on the
			// other side puts frames together from a stream of bytes and
			// does not see where records end.
			//
			// A record that its connection's limit ends holds whole
			// packets. It is there so that a packet does not wait on
			// more than the connection sends in a moment, and a packet
			// in two records waits on both. So does a record written
			// while the opening's last record waits to follow it.
			put := func(p []byte, keepalive bool) bool {
				n := wire.HeaderLen + len(p)
				if n > room && reserve > 0 && keepalive && real == 0 && !gated {
					room, reserve = room+reserve, 0 // no PING rides with keepalives alone
				}
				switch {
				case n <= room:
					buf = wire.AppendFrame(buf, wire.TypeData, p)
					room -= n
					return true
				case room <= 0, (limit < shape.MaxRecord || ackWaits) && pkts+carried > 0:
					return false
				}
				if reserve > 0 {
					// A PING cannot follow part of a frame, so it goes
					// in ahead of it.
					buf, pinged, reserve = l.ping(buf, now, true), true, 0
				}
				end := len(buf) + room
				buf = wire.AppendFrame(buf, wire.TypeData, p)
				carry = append(carry[:0], buf[end:]...)
				buf, room, cut = buf[:end], 0, true
				l.queued += len(carry)
				return true
			}
			// Small packets first, and even while the window is closed:
			// they add next to nothing to what is outstanding.
			for len(l.small) > 0 && take > 0 && !cut {
				p := l.small[0]
				if !put(p, false) {
					break
				}
				take--
				l.small[0] = nil
				l.small = l.small[1:]
				l.queued -= wire.HeaderLen + len(p)
				real++
				dataBytes += len(p)
				pkts++
			}
			if len(l.small) == 0 {
				l.small = l.small[:0:0]
			}
			for !gated && !held && len(l.data) > 0 && take > 0 && !cut {
				p := l.data[0]
				ka := shape.IsKeepalive(p)
				if !put(p, ka) {
					break
				}
				take--
				l.data[0] = nil
				l.data, l.dataAt = l.data[1:], l.dataAt[1:]
				l.queued -= wire.HeaderLen + len(p)
				if ka {
					l.keepalives--
				} else {
					real++
				}
				dataBytes += len(p)
				pkts++
			}
			if len(l.data) == 0 {
				l.data, l.dataAt = l.data[:0:0], l.dataAt[:0:0]
			}
			// Packets a record on a slow connection had no room for go
			// in the next, without waiting for it to fill.
			left := len(l.small) > 0 || !gated && !held && len(l.data) > 0
			more = split || left && limit < shape.MaxRecord
		}
		more = more || cut
		backlogged := len(carry) > 0 || len(l.data) > 0 || len(l.small) > 0
		l.queuedA.Store(int64(l.queued))
		l.mu.Unlock()

		if reserve > 0 && (real > 0 || gated) {
			// A gated record exists to carry a PING whose PONG will
			// reopen the window.
			buf, pinged = l.ping(buf, now, backlogged), true
		}
		// data is whether the record carries DATA: packets that begin in
		// it, or the end of one that began in the last.
		data := pkts > 0 || carried > 0
		// A record that ends inside a packet is full, and is left as it
		// is. Any other is padded.
		if !cut && len(buf) < shape.MaxRecord {
			mode := pl.Mode(queuedBefore, idle)
			switch {
			case gated, held, !data:
				// Control frames with no DATA to ride with are padded
				// as an interactive record is, whatever the lane is
				// carrying. The few bytes a bulk record takes are for
				// whole packets, whose size is no secret; they would
				// leave a PONG's record or a RETIRE's just longer than
				// the frame, and say which it was.
				mode = shape.Interactive
			case busy && !idle:
				mode = shape.Bulk
			}
			buf = wire.AppendPadding(buf, pl.Padding(mode, len(buf)))
		}
		// Only this goroutine writes, so the totals after the write are
		// known now; record the PING's before a fast PONG can arrive.
		total := l.bytesSent.Load() + uint64(len(buf))
		tracked := l.tracked.Load()
		if data || pinged {
			tracked += uint64(len(buf))
		}
		l.pingMu.Lock()
		if pinged {
			l.pings[len(l.pings)-1].bytes = tracked
		}
		if !backlogged {
			l.appLimited = true
		}
		l.pingMu.Unlock()
		if _, err := l.conn.Write(buf); err != nil {
			return err
		}
		l.bytesSent.Store(total)
		l.tracked.Store(tracked)
		l.dataSent.Add(uint64(dataBytes))
		l.pktsSent.Add(uint64(pkts))
		after := time.Now()
		l.lastSend.Store(after.UnixNano())
		if data {
			l.lastData.Store(after.UnixNano())
			switch {
			case l.limit == nil:
			case !held:
				l.limit.Wrote(after, len(buf))
			case carried > 0:
				// Of what a held record carries, only the end of a
				// packet begun before the limit held is its to count.
				l.limit.Wrote(after, carried)
			}
		}
		if l.lowat {
			// What was just written is in the kernel now; see how much
			// of it the connection could send.
			l.readSock(after)
		}
		switch {
		case !l.full.Load():
			// Not pacing. What was written at the rate of a lane still
			// growing must not count against it once it is full.
			pace = pacer{}
		case data:
			pace.wrote(now, len(buf), paceGain*l.Rate())
		}
		switch {
		case !backlogged:
			drainFrom = time.Time{}
		case drainFrom.IsZero():
			drainFrom, drainBytes = after, 0
		default:
			drainBytes += len(buf)
			if d := after.Sub(drainFrom); d >= drainSpan {
				l.drain.Store(math.Float64bits(float64(drainBytes) / d.Seconds()))
				drainFrom, drainBytes = after, 0
			}
		}
		if after.Sub(winStart) >= busyWindow {
			busy = winBytes >= busyBytes
			winStart, winBytes = after, 0
		}
		winBytes += dataBytes
		if closing {
			l.mu.Lock()
			done := len(l.ctrl) == 0
			l.mu.Unlock()
			if done {
				l.closeWrite()
				return nil
			}
		}
	}
}

// pacer spaces a writer's records out at a rate, after a burst. The zero
// value has nothing to wait for.
type pacer struct {
	// until is when the bytes written so far would all have gone out at the
	// rate they were written at.
	until time.Time
}

// wait is how long the writer must hold its next record at now, pacing at
// rate bytes per second: until it is no more than a burst ahead.
func (p *pacer) wait(now time.Time, rate float64) time.Duration {
	if p.until.IsZero() {
		return 0
	}
	burst := max(paceBurst, time.Duration(initialWindow/rate*float64(time.Second)))
	return max(p.until.Sub(now)-burst, 0)
}

// wrote records n bytes written at now.
func (p *pacer) wrote(now time.Time, n int, rate float64) {
	if p.until.Before(now) {
		p.until = now
	}
	p.until = p.until.Add(time.Duration(float64(n) / rate * float64(time.Second)))
}

// pingDue reports whether a PING should ride in the record being built.
// PINGs only ride in records that carry DATA, so an idle lane sends none.
// With TCP_NOTSENT_LOWAT they go once per ping interval, for liveness and,
// without TCP_INFO, the estimates. Without it they go several times a round
// trip, because their PONGs are what reopen the window; cover forces one
// when none is outstanding.
func (l *Lane) pingDue(now time.Time, cover bool) bool {
	l.pingMu.Lock()
	defer l.pingMu.Unlock()
	if cover && len(l.pings) == 0 {
		return true
	}
	if l.lowat {
		return len(l.pings) == 0 && now.Sub(l.lastPingSent) >= l.pingInterval
	}
	// Spread PINGs through the window, by time and by bytes, so
	// confirmations keep pace with what is in flight.
	every := max(uint64(l.windowBytes()/8), shape.MaxRecord)
	return len(l.pings) < maxPings &&
		(now.Sub(l.lastPingSent) >= l.pingSpacing() || l.tracked.Load()-l.lastPingBytes >= every)
}

// ping adds a PING to a record and notes that it is outstanding. backlogged
// is whether the lane has more to send once the record is written.
func (l *Lane) ping(buf []byte, now time.Time, backlogged bool) []byte {
	l.pingMu.Lock()
	defer l.pingMu.Unlock()
	p := outPing{tok: wire.NewPingToken(), at: now, limited: l.appLimited || !backlogged}
	l.pings = append(l.pings, p)
	l.lastPingSent = now
	l.lastPingBytes = l.tracked.Load()
	l.appLimited = false
	buf = wire.AppendHeader(buf, wire.TypePing, wire.PingLen)
	return wire.AppendPing(buf, p.tok)
}

// windowOpen reports whether a lane pacing itself on PONGs may write more
// DATA: the bytes written but not yet confirmed are under
// windowGain × rate × min RTT + windowMin.
func (l *Lane) windowOpen() bool {
	return float64(l.unconfirmed()) < l.windowBytes()
}

// windowBytes is the cap on unconfirmed bytes for a lane without
// TCP_NOTSENT_LOWAT.
func (l *Lane) windowBytes() float64 {
	if !l.rateSeen.Load() {
		// A new connection is in slow start; until it has shown what it
		// can deliver, offer it no more than a small first window.
		return windowMin
	}
	gain := windowGain
	switch {
	case l.late.Load():
		gain = lateGain
	case l.growing.Load():
		gain = growthGain
	}
	return min(max(gain*l.Rate()*l.base().Seconds(), windowMin), windowMax)
}

// observeBase tracks the base RTT: the least PONG round trip seen in the
// current and previous 10-second epochs, so it follows a path whose delay
// really changed. Called with pingMu held.
func (l *Lane) observeBase(sample time.Duration, now time.Time) {
	if l.baseEpoch.IsZero() || now.Sub(l.baseEpoch) >= baseRTTEpoch {
		l.basePrev, l.baseCur, l.baseEpoch = l.baseCur, 0, now
	}
	if l.baseCur == 0 || sample < l.baseCur {
		l.baseCur = sample
	}
	base := l.baseCur
	if l.basePrev != 0 && l.basePrev < base {
		base = l.basePrev
	}
	l.baseRTT.Store(int64(base))
}

// needCoverPing reports whether a gated lane must send a PING so that a
// PONG will come back and reopen its window.
func (l *Lane) needCoverPing() bool {
	l.pingMu.Lock()
	defer l.pingMu.Unlock()
	return len(l.pings) == 0
}

// onPong updates the estimates from a PONG. Every byte written before the
// PING has been delivered when its PONG arrives, so the bytes between two
// PONGs over the time between them is a delivery-rate sample.
func (l *Lane) onPong(tok uint64, now time.Time) {
	l.pingMu.Lock()
	i := 0
	for i < len(l.pings) && l.pings[i].tok != tok {
		i++
	}
	if i == len(l.pings) {
		l.pingMu.Unlock()
		return
	}
	p := l.pings[i]
	l.pings = l.pings[i+1:]
	if len(l.pings) == 0 {
		l.pings = nil
	}
	l.lastPong.Store(now.UnixNano())
	l.ponged.Store(true)
	confirmed := p.bytes
	if len(l.pings) == 0 && !l.lowat {
		// With no PING left outstanding, everything written has arrived:
		// a record written long enough after the last PING to be still in
		// flight now would have carried a PING of its own.
		confirmed = max(confirmed, l.tracked.Load())
	}
	if confirmed > l.confirmed {
		l.confirmed = confirmed
		l.confirmedA.Store(confirmed)
	}
	sojourn := now.Sub(p.at)
	if !l.lowat {
		l.observeBase(sojourn, now)
	}
	if !l.hasTCPInfo.Load() { // otherwise TCP_INFO supplies RTT and rate
		l.updateRTT(sojourn)
	}
	switch {
	case !l.lowat:
		l.paceOnPong(p, sojourn, now)
	case !l.hasTCPInfo.Load():
		// A delivery-rate sample spans at least one base RTT: PONGs
		// arrive in bunches, and a sample over the gap between two of
		// them says nothing.
		l.rateLimited = l.rateLimited || p.limited
		span := max(l.RTT()/2, minRateSpan)
		switch {
		case l.rateFrom.IsZero():
			l.rateFrom, l.rateFromBytes, l.rateLimited = now, p.bytes, false
		case now.Sub(l.rateFrom) >= span:
			if p.bytes > l.rateFromBytes {
				l.updateRate(float64(p.bytes-l.rateFromBytes)/now.Sub(l.rateFrom).Seconds(), l.rateLimited)
			}
			l.rateFrom, l.rateFromBytes, l.rateLimited = now, p.bytes, false
		}
	}
	l.pingMu.Unlock()
	l.signal(l.wake) // a gated writer may go on
}

// paceOnPong keeps the estimates a lane without TCP_NOTSENT_LOWAT paces
// itself by. Called with pingMu held.
//
// The rate is what PONGs confirmed over the last base RTT, taken afresh on
// every PONG. The estimate follows a sample upwards quickly, because the
// window is a multiple of it and a connection in slow start doubles every
// round trip; it comes down slowly, and only on samples taken while the
// lane was kept busy, since an idle lane's samples say nothing about its
// capacity.
func (l *Lane) paceOnPong(p outPing, sojourn time.Duration, now time.Time) {
	base := l.base()
	late := sojourn > base+max(base/8, onTimeMin)
	l.late.Store(late)
	if !late {
		l.full.Store(false)
	} else {
		l.growing.Store(false)
	}

	span := max(base, minRateSpan)
	l.hist = append(l.hist, pongRec{at: now, bytes: p.bytes, limited: p.limited})
	// The sample runs from the latest PONG at least one span old.
	from := -1
	for i := len(l.hist) - 2; i >= 0; i-- {
		if now.Sub(l.hist[i].at) >= span {
			from = i
			break
		}
	}
	if from < 0 {
		if len(l.hist) > maxPongHist {
			l.hist = l.hist[1:]
		}
		return
	}
	limited := false
	for _, h := range l.hist[from+1:] {
		limited = limited || h.limited
	}
	first := l.hist[from]
	l.hist = l.hist[from:]
	if p.bytes <= first.bytes {
		return
	}
	sample := float64(p.bytes-first.bytes) / now.Sub(first.at).Seconds()
	rate := math.Float64frombits(l.rate.Load())
	rising := !l.rateSeen.Load() || sample >= rate*growing
	l.growing.Store(rising && !late)
	if late {
		// Late, and no faster than before: the lane is at its capacity.
		l.full.Store(!rising)
	}
	// Samples overlap, several to a round trip, so each moves the estimate
	// only part of the way, except upwards while the lane is still
	// growing.
	switch {
	case !l.rateSeen.Swap(true), sample >= rate && !late:
		rate = sample
	case sample >= rate:
		rate += (sample - rate) / 2
	case !limited:
		rate += (sample - rate) / 16
	}
	l.rate.Store(math.Float64bits(rate))
}

// restart puts a lane without TCP_NOTSENT_LOWAT back to how it began, when
// it carries DATA again after sitting idle: TCP has shrunk its congestion
// window meanwhile, so what the lane carried before says little.
func (l *Lane) restart() {
	l.pingMu.Lock()
	l.hist = nil
	l.rate.Store(math.Float64bits(initialWindow / l.base().Seconds()))
	l.rateSeen.Store(false)
	l.late.Store(false)
	l.full.Store(false)
	l.growing.Store(false)
	l.pingMu.Unlock()
}

func (l *Lane) updateRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}
	if m := l.minRTT.Load(); m == 0 || int64(sample) < m {
		l.minRTT.Store(int64(sample))
	}
	if !l.rttSampled.Swap(true) {
		l.srtt.Store(int64(sample))
		return
	}
	old := l.srtt.Load()
	l.srtt.Store(old - old/8 + int64(sample)/8)
}

// updateRate folds a delivery-rate sample into the estimate. A sample taken
// while the lane wasn't kept busy only says the lane can go at least that
// fast, so it can raise the estimate but not lower it.
func (l *Lane) updateRate(sample float64, appLimited bool) {
	if sample <= 0 {
		return
	}
	old := math.Float64frombits(l.rate.Load())
	if !l.rateSeen.Swap(true) && !appLimited {
		old = sample // the default was only a guess
	}
	var next float64
	switch {
	case appLimited:
		next = max(old, sample)
	case !l.rateSampled.Swap(true):
		next = sample
	default:
		next = old*0.75 + sample*0.25
	}
	l.rate.Store(math.Float64bits(next))
}

// monitor polls TCP_INFO and enforces the PING timeout while the lane is
// busy, and sleeps while it is idle so idle lanes cost no wakeups.
func (l *Lane) monitor() {
	t := time.NewTicker(monitorInterval)
	defer t.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-t.C:
		}
		now := time.Now()
		l.pingMu.Lock()
		out := len(l.pings) > 0
		var at time.Time
		if out {
			at = l.pings[0].at
		}
		l.pingMu.Unlock()
		if out && now.Sub(at) > l.pingTimeout {
			l.finish(ErrPingTimeout)
			return
		}
		last := max(l.lastSend.Load(), l.lastRecv.Load())
		if !out && now.UnixNano()-last > int64(activeWindow) && l.Queued() == 0 {
			l.sleeping.Store(true)
			// Re-check so a Send that raced with going to sleep isn't missed.
			if max(l.lastSend.Load(), l.lastRecv.Load()) == last && l.Queued() == 0 {
				select {
				case <-l.done:
					return
				case <-l.monitorWake:
				}
			}
			l.sleeping.Store(false)
			continue
		}
		if l.rc != nil && l.hasTCPInfo.Load() {
			if ti, ok := readTCPInfo(l.rc); ok {
				l.applyTCPInfo(ti, now)
			}
		}
	}
}

// applyTCPInfo takes the monitor's regular reading of the connection: what
// is true of it now, and one more sample for the rate estimate.
func (l *Lane) applyTCPInfo(ti tcpInfo, now time.Time) {
	l.noteTCPInfo(ti, now)
	if ti.rate > 0 {
		l.pingMu.Lock()
		appLimited := l.appLimited
		l.pingMu.Unlock()
		l.updateRate(ti.rate, appLimited || ti.appLimited)
	}
}

// closeWrite sends TLS close_notify (or the carrier's equivalent).
func (l *Lane) closeWrite() error {
	if cw, ok := l.conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// tcpInfo is what the platform's TCP_INFO tells us.
type tcpInfo struct {
	rtt        time.Duration
	minRTT     time.Duration
	rate       float64 // bytes/s
	appLimited bool
	retrans    uint64 // total retransmissions so far
	stalled    bool   // an unrecovered retransmission timeout is in progress
	// The connection's window and what is using it, in bytes, the bytes
	// written to it and not yet sent, its pacing rate in bytes per second
	// and its segment size; cwnd is zero where the platform doesn't say.
	cwnd, inflight, notsent, pacing, mss float64
	rto                                  time.Duration
	// Running totals: bytes and segments of data sent, retransmissions
	// included; bytes sent again; and segments delivered, in order or not.
	bytesSent, bytesResent uint64
	segsSent, delivered    uint32
}
