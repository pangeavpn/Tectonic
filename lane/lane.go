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

	defaultRTT      = 100 * time.Millisecond
	defaultRate     = 1 << 20 // bytes/s before any estimate
	minRate         = 16 << 10
	minQueueDelay   = 50 * time.Millisecond
	minQueueBytes   = 64 << 10
	maxQueueBytes   = 4 << 20
	activeWindow    = 2 * time.Second
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
	// coalesceDelay for one to fill, and never padded (design §8).
	busyWindow    = 10 * time.Millisecond
	busyBytes     = 16 << 10
	coalesceDelay = 2 * time.Millisecond
)

// Handler receives a lane's events. Every callback runs on the lane's reader
// goroutine, so a slow callback delays that lane's later frames, never
// another lane's.
type Handler struct {
	// Data is called for every DATA frame. pkt is only valid during the call.
	Data func(l *Lane, pkt []byte)
	// Welcome is called on a client lane when WELCOME arrives.
	Welcome func(l *Lane, w wire.Welcome)
	// Retire is called when the peer sends RETIRE.
	Retire func(l *Lane)
	// Close is called when the peer sends CLOSE, which ends the session.
	Close func(l *Lane, reason wire.CloseReason)
	// End is called once, when the lane's reader has stopped: no more
	// frames will arrive on this lane.
	End func(l *Lane)
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
	lowat      bool
	confirmedA atomic.Uint64 // mirrors confirmed, for ETA
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
	if _, ok := r.(*bufio.Reader); !ok {
		r = bufio.NewReaderSize(r, readBufferSize)
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	now := time.Now()
	l := &Lane{
		id:          laneIDs.Add(1),
		conn:        conn,
		rd:          wire.NewReader(r),
		role:        opts.Role,
		h:           opts.Handler,
		created:     now,
		profiles:    opts.Profiles,
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
			if _, ok := readTCPInfo(rc); ok {
				l.hasTCPInfo.Store(true)
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

// Start writes the lane's first flight and starts its goroutines. first holds
// the frames that open the lane (HELLO and the first DATA from a client,
// WELCOME from the server); Start pads them to the profile's first-flight
// size and sends them in one record.
func (l *Lane) Start(first []byte) error {
	l.mu.Lock()
	if l.started {
		l.mu.Unlock()
		return errors.New("lane: already started")
	}
	l.started = true
	l.mu.Unlock()

	now := time.Now()
	if !l.lowat {
		// The PONG shows the first flight has arrived and how long a round
		// trip takes; until it is back the scheduler does not count on
		// the lane. It fits inside the first flight's padding.
		p := outPing{tok: wire.NewPingToken(), at: now, limited: true}
		first = wire.AppendHeader(first, wire.TypePing, wire.PingLen)
		first = wire.AppendPing(first, p.tok)
		l.pingMu.Lock()
		l.pings = append(l.pings, p)
		l.pingMu.Unlock()
	}
	pl := l.planner.Load()
	buf := wire.AppendPadding(first, pl.FirstFlightPadding(l.role == Client, len(first)))
	if !l.lowat {
		l.pingMu.Lock()
		l.pings[0].bytes = uint64(len(buf))
		l.lastPingSent, l.lastPingBytes = now, uint64(len(buf))
		l.pingMu.Unlock()
	}
	if _, err := l.conn.Write(buf); err != nil {
		l.finish(err)
		return err
	}
	l.bytesSent.Add(uint64(len(buf)))
	if !l.lowat {
		l.tracked.Add(uint64(len(buf)))
	}
	l.lastSend.Store(time.Now().UnixNano())
	go l.run()
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
	if l.queued >= minQueueBytes {
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
	l.data = append(l.data, append([]byte(nil), pkt...))
	l.dataAt = append(l.dataAt, now.UnixNano())
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
		l.data, l.dataAt = nil, nil
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
		l.data, l.dataAt, l.ctrl = nil, nil, nil
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
	for {
		l.mu.Lock()
		if len(l.ctrl) == 0 && len(l.data) == 0 {
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
		kaOnly := len(l.ctrl) == 0 && l.keepalives == len(l.data)
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
		if gated && len(l.ctrl) == 0 && !l.needCoverPing() {
			l.mu.Unlock()
			select {
			case <-l.wake: // a PONG opened the window, or new control frames
			case <-l.done:
				return nil
			}
			continue
		}
		if l.full.Load() && !gated && !l.closing && len(l.ctrl) == 0 && len(l.data) > 0 {
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
		// In a bulk transfer, give a record a moment to fill.
		if busy && !gated && len(l.ctrl) == 0 && !l.retiring && !l.closing &&
			l.queued < shape.MaxRecord-wire.MaxFrameLen/32 {
			if coalesceUntil.IsZero() {
				coalesceUntil = now.Add(coalesceDelay)
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

		buf = append(buf[:0], l.ctrl...)
		l.ctrl = l.ctrl[:0]
		closing := l.closing
		queuedBefore := l.queued
		var dataBytes, pkts, real int
		for !gated && len(l.data) > 0 {
			p := l.data[0]
			if len(buf) > 0 && len(buf)+wire.HeaderLen+len(p) > shape.MaxRecord {
				break
			}
			buf = wire.AppendFrame(buf, wire.TypeData, p)
			l.data[0] = nil
			l.data, l.dataAt = l.data[1:], l.dataAt[1:]
			l.queued -= wire.HeaderLen + len(p)
			if shape.IsKeepalive(p) {
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
		backlogged := len(l.data) > 0
		l.queuedA.Store(int64(l.queued))
		l.mu.Unlock()

		pinged := false
		if real > 0 || gated {
			// A gated record exists to carry a PING whose PONG will
			// reopen the window.
			buf, pinged = l.maybePing(buf, now, backlogged, gated)
		}
		mode := pl.Mode(queuedBefore, idle)
		switch {
		case gated:
			mode = shape.Interactive
		case busy && !idle:
			mode = shape.Bulk
		}
		if len(buf) < shape.MaxRecord {
			buf = wire.AppendPadding(buf, pl.Padding(mode, len(buf)))
		}
		// Only this goroutine writes, so the totals after the write are
		// known now; record the PING's before a fast PONG can arrive.
		total := l.bytesSent.Load() + uint64(len(buf))
		tracked := l.tracked.Load()
		if pkts > 0 || pinged {
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
		if pkts > 0 {
			l.lastData.Store(after.UnixNano())
		}
		switch {
		case !l.full.Load():
			// Not pacing. What was written at the rate of a lane still
			// growing must not count against it once it is full.
			pace = pacer{}
		case pkts > 0:
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

// maybePing adds a PING to a record. PINGs only ride in records that carry
// DATA, so an idle lane sends none. With TCP_NOTSENT_LOWAT they go once per
// ping interval, for liveness and, without TCP_INFO, the estimates. Without
// it they go several times a round trip, because their PONGs are what
// reopen the window; cover forces one when none is outstanding.
func (l *Lane) maybePing(buf []byte, now time.Time, backlogged, cover bool) ([]byte, bool) {
	l.pingMu.Lock()
	defer l.pingMu.Unlock()
	var due bool
	if l.lowat {
		due = len(l.pings) == 0 && now.Sub(l.lastPingSent) >= l.pingInterval
	} else {
		// Spread PINGs through the window, by time and by bytes, so
		// confirmations keep pace with what is in flight.
		every := max(uint64(l.windowBytes()/8), shape.MaxRecord)
		due = len(l.pings) < maxPings &&
			(now.Sub(l.lastPingSent) >= l.pingSpacing() || l.tracked.Load()-l.lastPingBytes >= every)
	}
	if !due && !(cover && len(l.pings) == 0) {
		return buf, false
	}
	p := outPing{tok: wire.NewPingToken(), at: now, limited: l.appLimited || !backlogged}
	l.pings = append(l.pings, p)
	l.lastPingSent = now
	l.lastPingBytes = l.tracked.Load()
	l.appLimited = false
	buf = wire.AppendHeader(buf, wire.TypePing, wire.PingLen)
	return wire.AppendPing(buf, p.tok), true
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

func (l *Lane) applyTCPInfo(ti tcpInfo, now time.Time) {
	if ti.rtt > 0 {
		l.rttSampled.Store(true)
		l.srtt.Store(int64(ti.rtt))
		if ti.minRTT > 0 {
			l.minRTT.Store(int64(ti.minRTT))
		} else if m := l.minRTT.Load(); m == 0 || int64(ti.rtt) < m {
			l.minRTT.Store(int64(ti.rtt))
		}
	}
	if ti.rate > 0 {
		l.pingMu.Lock()
		appLimited := l.appLimited
		l.pingMu.Unlock()
		l.updateRate(ti.rate, appLimited || ti.appLimited)
	}
	l.pingMu.Lock()
	if !l.retransInit {
		l.retransInit = true
	} else if ti.retrans > l.lastRetransN {
		l.lastRetrans.Store(now.UnixNano())
	}
	l.lastRetransN = ti.retrans
	l.pingMu.Unlock()
	l.stalled.Store(ti.stalled)
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
}
