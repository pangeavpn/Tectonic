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
	// not yet seen confirmed by a PONG at windowGain × rate × base RTT +
	// windowMin. That never holds back the TCP connection while the
	// network's own queue stays under one base RTT, and bounds what waits
	// unsent in the kernel to about one bandwidth-delay product.
	windowGain     = 2.0
	windowMin      = 64 << 10
	windowMax      = 64 << 20
	minRateSpan    = 20 * time.Millisecond
	baseRTTEpoch   = 10 * time.Second // the base RTT is the least seen over 10-20 s
	maxPings       = 8
	minPingSpacing = 2 * time.Millisecond

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
	baseRTT    atomic.Int64  // ns: least PONG round trip over the last 10-20 s

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
}

// outPing is a PING waiting for its PONG.
type outPing struct {
	tok     uint64
	at      time.Time
	bytes   uint64 // bytes written up to and including the PING's record
	limited bool   // the lane was not kept busy before this PING
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

	pl := l.planner.Load()
	buf := wire.AppendPadding(first, pl.FirstFlightPadding(l.role == Client, len(first)))
	if _, err := l.conn.Write(buf); err != nil {
		l.finish(err)
		return err
	}
	l.bytesSent.Add(uint64(len(buf)))
	l.lastSend.Store(time.Now().UnixNano())
	go l.run()
	return nil
}

// Send queues one WireGuard datagram as a DATA frame. It copies pkt. It
// returns false if the lane is retiring or closed, or if its queue already
// holds more than the lane can deliver in about one round trip; the
// scheduler then tries another lane.
func (l *Lane) Send(pkt []byte) bool {
	if len(pkt) > wire.MaxBodyLen {
		return false
	}
	n := wire.HeaderLen + len(pkt)
	ka := shape.IsKeepalive(pkt)
	l.mu.Lock()
	if l.retiring || l.closing || l.isDone() {
		l.mu.Unlock()
		return false
	}
	if l.queued >= minQueueBytes {
		limit := max(minQueueDelay, time.Duration(l.srtt.Load()))
		if l.queued+n > maxQueueBytes || float64(l.queued)/l.Rate() > limit.Seconds() {
			l.mu.Unlock()
			return false
		}
	}
	l.data = append(l.data, append([]byte(nil), pkt...))
	l.queued += n
	now := time.Now()
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
		l.data = nil
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
	return max(math.Float64frombits(l.rate.Load()), minRate)
}

// Queued is the number of bytes waiting in the lane's queue.
func (l *Lane) Queued() int { return int(l.queuedA.Load()) }

// ETA estimates when n more bytes queued on this lane would be delivered
// (design §7):
//
//	eta(lane) = queued_bytes(lane) / rate(lane) + srtt(lane) / 2
//
// Without TCP_NOTSENT_LOWAT the kernel may hold more unsent data, but the
// lane then PINGs several times a round trip, so srtt is fresh and already
// includes that wait.
func (l *Lane) ETA(n int) time.Duration {
	q := float64(l.queuedA.Load() + int64(n))
	return time.Duration(q/l.Rate()*float64(time.Second)) + l.RTT()/2
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
	unconfirmed, pings := l.bytesSent.Load()-l.confirmed, len(l.pings)
	l.pingMu.Unlock()
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
		l.data, l.ctrl = nil, nil
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
	for {
		l.mu.Lock()
		if len(l.ctrl) == 0 && len(l.data) == 0 {
			retiring := l.retiring
			l.mu.Unlock()
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
			l.data = l.data[1:]
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
			l.data = l.data[:0:0]
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
		// Only this goroutine writes, so the total after the write is
		// known now; record it before a fast PONG can arrive.
		total := l.bytesSent.Load() + uint64(len(buf))
		l.pingMu.Lock()
		if pinged {
			l.pings[len(l.pings)-1].bytes = total
		}
		if !backlogged {
			l.appLimited = true
		}
		l.pingMu.Unlock()
		if _, err := l.conn.Write(buf); err != nil {
			return err
		}
		l.bytesSent.Store(total)
		l.dataSent.Add(uint64(dataBytes))
		l.pktsSent.Add(uint64(pkts))
		after := time.Now()
		l.lastSend.Store(after.UnixNano())
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
		spacing := min(l.pingInterval, max(l.RTT()/4, minPingSpacing))
		every := max(uint64(l.windowBytes()/8), shape.MaxRecord)
		due = len(l.pings) < maxPings &&
			(now.Sub(l.lastPingSent) >= spacing || l.bytesSent.Load()-l.lastPingBytes >= every)
	}
	if !due && !(cover && len(l.pings) == 0) {
		return buf, false
	}
	p := outPing{tok: wire.NewPingToken(), at: now, limited: l.appLimited || !backlogged}
	l.pings = append(l.pings, p)
	l.lastPingSent = now
	l.lastPingBytes = l.bytesSent.Load()
	l.appLimited = false
	buf = wire.AppendHeader(buf, wire.TypePing, wire.PingLen)
	return wire.AppendPing(buf, p.tok), true
}

// windowOpen reports whether a lane pacing itself on PONGs may write more
// DATA: the bytes written but not yet confirmed are under
// windowGain × rate × min RTT + windowMin.
func (l *Lane) windowOpen() bool {
	w := l.windowBytes()
	l.pingMu.Lock()
	defer l.pingMu.Unlock()
	return float64(l.bytesSent.Load()-l.confirmed) < w
}

// windowBytes is the cap on unconfirmed bytes for a lane without
// TCP_NOTSENT_LOWAT.
func (l *Lane) windowBytes() float64 {
	if !l.rateSeen.Load() {
		// A new connection is in slow start; until it has shown what it
		// can deliver, offer it no more than a small first window.
		return windowMin
	}
	rtt := time.Duration(l.baseRTT.Load())
	if rtt <= 0 {
		rtt = l.RTT()
	}
	return min(windowGain*l.Rate()*rtt.Seconds()+windowMin, windowMax)
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
	if p.bytes > l.confirmed {
		l.confirmed = p.bytes
		l.confirmedA.Store(p.bytes)
	}
	if !l.lowat {
		l.observeBase(now.Sub(p.at), now)
	}
	if !l.hasTCPInfo.Load() { // otherwise TCP_INFO supplies RTT and rate
		l.updateRTT(now.Sub(p.at))
		// A delivery-rate sample spans at least one base RTT: PONGs
		// arrive in bunches, and a sample over the gap between two of
		// them says nothing.
		l.rateLimited = l.rateLimited || p.limited
		span := max(time.Duration(l.baseRTT.Load()), l.RTT()/2, minRateSpan)
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
