package sched

import (
	"cmp"
	"context"
	crand "crypto/rand"
	"errors"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pangeavpn/tectonic/lane"
	"github.com/pangeavpn/tectonic/shape"
	"github.com/pangeavpn/tectonic/wire"
)

// PoolLane is a client lane as the pool sees it. *lane.Lane implements it.
type PoolLane interface {
	Lane
	Welcomed() <-chan struct{}
	Welcome() (wire.Welcome, bool)
	Done() <-chan struct{}
	Err() error
	Retire()
	SendClose(wire.CloseReason)
	Close() error
	Stats() lane.Stats
	RTT() time.Duration
	// BaseRTT is the lane's round trip without any queueing.
	BaseRTT() time.Duration
	SetPlanner(*shape.Planner)
}

// DialRequest asks the dialer for one new lane.
type DialRequest struct {
	// Join is set when the lane should join SessionID; otherwise it starts
	// a new session.
	Join      bool
	SessionID wire.SessionID
	// TakeFirstPacket, when set, returns the datagram that must go out with
	// HELLO in the lane's first flight (or on the lane once it is up). Call
	// it once, as late as possible: the moment TLS completes.
	TakeFirstPacket func() []byte
	// InitialRTT seeds the new lane's RTT estimate from its siblings.
	InitialRTT time.Duration
	// Handler must be installed on the new lane: it delivers the lane's
	// packets and events to the pool.
	Handler lane.Handler
	// Planner is the session's current shaping profile, for the first
	// flight before WELCOME arrives.
	Planner *shape.Planner
	// Limiter is the session's send limit, to be installed on the lane.
	Limiter lane.Limiter
	// Reason says why the lane is wanted, for logs: "first", "pool",
	// "churn", "probe", "reopen" or "reconnect".
	Reason string
}

// DialFunc opens one lane. It may return before the lane's WELCOME arrives.
// An error wrapping ErrCredentialRejected stops the pool.
type DialFunc func(ctx context.Context, req DialRequest) (PoolLane, error)

// PoolConfig configures a Pool.
type PoolConfig struct {
	Dial DialFunc
	// Receive gets every datagram from the server, on the receiving lane's
	// goroutine. pkt is only valid during the call.
	Receive func(pkt []byte)
	// Profiles resolves the shaping profile WELCOME names.
	Profiles *shape.Set
	// Churn sets lane lifetimes and byte budgets; zero means the design's.
	Churn  Churn
	Logger *slog.Logger
	// DialTimeout bounds one lane dial. Zero means 20 s.
	DialTimeout time.Duration
}

// Errors the pool ends with.
var (
	// ErrCredentialRejected means the server closed the session because the
	// key_id expired or was revoked. The hub must issue a new one.
	ErrCredentialRejected = errors.New("sched: credential rejected by the server")
	// ErrPoolClosed is returned once the pool is closed.
	ErrPoolClosed = errors.New("sched: pool closed")
)

const (
	baseLanes       = 2  // the pool starts with 2 lanes
	defaultMaxLanes = 6  // until WELCOME says otherwise
	pendingMax      = 64 // datagrams held while no lane is up
	pendingBytesMax = 256 << 10
	sampleEvery     = time.Second
	// overlapRTTs is how many round trips a replacement lane gets, at
	// least, before the lane it replaces retires: slow start takes about
	// ten to reach a few thousand packets a round trip.
	overlapRTTs = 16
	backoffMin  = 500 * time.Millisecond
	backoffMax  = 30 * time.Second
)

// activeTick is how often the pool re-plans while it has lanes. A variable
// so tests can run the pool faster.
var activeTick = 500 * time.Millisecond

// Pool owns a client's lanes and the session they share.
type Pool struct {
	cfg   PoolConfig
	churn Churn
	log   *slog.Logger
	sched Scheduler
	reseq *Resequencer
	// limit holds what the session sends to what its path delivers (see
	// Limiter). Every lane shares it.
	limit Limiter

	ctx    context.Context
	cancel context.CancelFunc
	events chan func()
	kickCh chan struct{}
	done   chan struct{}

	lastActive atomic.Int64 // unix ns of the last non-keepalive packet either way

	mu        sync.Mutex
	pending   [][]byte
	pendingSz int
	heldKA    []byte
	closing   bool
	closeLane PoolLane // the lane carrying CLOSE at shutdown

	sessionUp   chan struct{}
	sessionOnce sync.Once
	errMu       sync.Mutex
	err         error

	// Owned by the loop goroutine.
	lanes       map[*laneState]struct{}
	dialing     int
	haveSession bool
	session     wire.SessionID
	welcome     wire.Welcome
	planner     *shape.Planner
	maxLanes    int
	lastLaneAt  time.Time
	backoff     time.Duration
	nextDial    time.Time
	idleFor     time.Time // the activity mark idleClose was drawn for
	idleClose   time.Duration
	lastReopen  time.Time
	dormantAt   time.Time
	reopenAfter time.Duration
	thr         *throttle
	lastSample  time.Time
	rng         *rand.Rand
	laneSeq     uint64
}

// laneState is the pool's view of one lane.
type laneState struct {
	l           PoolLane
	seq         uint64  // rises with every lane dialed: the newest lane has the highest
	src         *Source // the lane's way into the resequencer
	welcomed    bool
	session     wire.SessionID
	life        laneLife // when the lane is due to be replaced
	retiring    bool
	replacing   *laneState // the lane this one replaces, until it takes over
	handoverAt  time.Time  // the earliest the lane it replaces may retire
	carried     uint64     // payload bytes either way when last looked at, once a replacement is up
	quietSince  time.Time  // since when that has not changed
	replacement bool       // a replacement for this lane is being dialed or is up
	upAt        time.Time
	lastUp      uint64
	lastDown    uint64
}

// laneRef routes a lane's handler callbacks to its state, which only exists
// once the dial returns.
type laneRef struct {
	st          *laneState
	srcOnce     sync.Once
	src         *Source
	retired     bool
	closeReason *wire.CloseReason
}

// NewPool starts a pool. It begins connecting at once, so the session is
// usually up by the time WireGuard sends its first packet.
func NewPool(cfg PoolConfig) *Pool {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 20 * time.Second
	}
	var seed [32]byte
	crand.Read(seed[:])
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pool{
		cfg:       cfg,
		churn:     cfg.Churn.withDefaults(),
		log:       log,
		ctx:       ctx,
		cancel:    cancel,
		events:    make(chan func(), 256),
		kickCh:    make(chan struct{}, 1),
		done:      make(chan struct{}),
		sessionUp: make(chan struct{}),
		lanes:     map[*laneState]struct{}{},
		planner:   shape.NewPlanner(cfg.Profiles.Get(shape.DefaultID)),
		maxLanes:  defaultMaxLanes,
		thr:       newThrottle(),
		rng:       rand.New(rand.NewChaCha8(seed)),
	}
	p.limit.Log = log.Debug
	p.reseq = NewResequencer(func(pkt []byte) {
		if cfg.Receive != nil {
			cfg.Receive(pkt)
		}
	})
	p.lastActive.Store(time.Now().UnixNano())
	go p.loop()
	return p
}

// Send hands a WireGuard datagram to the scheduler. While no lane is up the
// datagram waits, briefly, for one; keepalives wait only while the tunnel is
// idle, and only the latest is kept.
func (p *Pool) Send(pkt []byte) {
	ka := shape.IsKeepalive(pkt)
	if !ka {
		p.lastActive.Store(time.Now().UnixNano())
	}
	if p.sched.Send(pkt) || p.sched.Len() > 0 {
		return // sent, or every lane is full: drop like a congested link
	}
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return
	}
	if ka {
		p.heldKA = append(p.heldKA[:0], pkt...)
	} else {
		p.pending = append(p.pending, append([]byte(nil), pkt...))
		p.pendingSz += len(pkt)
		for len(p.pending) > pendingMax || p.pendingSz > pendingBytesMax {
			p.pendingSz -= len(p.pending[0])
			p.pending = p.pending[1:]
		}
	}
	p.mu.Unlock()
	select {
	case p.kickCh <- struct{}{}:
	default:
	}
}

// WaitSession blocks until the first lane has logged in, the pool fails, or
// ctx ends. A pool that has stopped with an error reports the error even if
// a session came up before.
func (p *Pool) WaitSession(ctx context.Context) error {
	if err := p.Err(); err != nil {
		return err
	}
	select {
	case <-p.sessionUp:
		return p.Err()
	case <-p.done:
		if err := p.Err(); err != nil {
			return err
		}
		return ErrPoolClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Err returns the error that stopped the pool, if any.
func (p *Pool) Err() error {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.err
}

// Done is closed when the pool has stopped.
func (p *Pool) Done() <-chan struct{} { return p.done }

// Close ends the session: it sends CLOSE on one lane and closes the rest.
func (p *Pool) Close() error {
	p.mu.Lock()
	already := p.closing
	p.closing = true
	p.mu.Unlock()
	if !already {
		p.post(func() { p.shutdown(nil) })
	}
	<-p.done
	p.mu.Lock()
	cl := p.closeLane
	p.mu.Unlock()
	if cl != nil {
		// Give CLOSE a moment to reach the server, then make sure.
		select {
		case <-cl.Done():
		case <-time.After(time.Second):
		}
		cl.Close()
	}
	return nil
}

// PoolStats is a snapshot of the pool.
type PoolStats struct {
	Lanes     int
	Dialing   int
	Session   wire.SessionID
	Throttled bool
	Extra     int // lanes added because per-connection throttling was detected
	Scheduler SchedulerStats
	// Resequencer counts how packets from the server were put back in
	// order.
	Resequencer ResequencerStats
	// Limit is the session's send limit.
	Limit LimiterStats
}

// Stats returns a snapshot of the pool.
func (p *Pool) Stats() PoolStats {
	ch := make(chan PoolStats, 1)
	if !p.post(func() {
		ch <- PoolStats{
			Lanes: len(p.lanes), Dialing: p.dialing, Session: p.session,
			Throttled: p.thr.throttled, Extra: p.thr.extra,
			Scheduler: p.sched.Stats(), Resequencer: p.reseq.Stats(), Limit: p.limit.Stats(),
		}
	}) {
		return PoolStats{Scheduler: p.sched.Stats(), Resequencer: p.reseq.Stats(), Limit: p.limit.Stats()}
	}
	select {
	case s := <-ch:
		return s
	case <-p.done:
		return PoolStats{Scheduler: p.sched.Stats(), Resequencer: p.reseq.Stats(), Limit: p.limit.Stats()}
	}
}

// post runs f on the loop goroutine. It reports false once the pool is done.
func (p *Pool) post(f func()) bool {
	select {
	case p.events <- f:
		return true
	case <-p.done:
		return false
	}
}

func (p *Pool) loop() {
	defer close(p.done)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case f := <-p.events:
			f()
		case <-p.kickCh:
		case <-timer.C:
		case <-p.ctx.Done():
			return
		}
		if p.ctx.Err() != nil {
			return
		}
		next := p.maintain(time.Now())
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(next)
	}
}

// shutdown ends every lane, sending CLOSE on one of them first so the
// server can drop the session at once rather than wait out the resume
// window.
func (p *Pool) shutdown(err error) {
	p.errMu.Lock()
	if p.err == nil {
		p.err = err
	}
	p.errMu.Unlock()
	p.mu.Lock()
	p.closing = true
	p.pending, p.heldKA = nil, nil
	p.mu.Unlock()
	p.sched.SetLanes(nil)
	p.reseq.Close()
	sentClose := false
	for st := range p.lanes {
		if !sentClose && st.welcomed && err == nil {
			st.l.SendClose(wire.CloseNormal)
			sentClose = true
			p.mu.Lock()
			p.closeLane = st.l
			p.mu.Unlock()
			continue
		}
		st.l.Close()
	}
	p.lanes = map[*laneState]struct{}{}
	p.cancel()
}

// maintain brings the pool to its target and returns when to run again.
func (p *Pool) maintain(now time.Time) time.Duration {
	p.mu.Lock()
	closing := p.closing
	nPending := len(p.pending)
	held := p.heldKA != nil
	p.mu.Unlock()
	if closing {
		return time.Hour
	}

	pl := p.planner
	lastActive := time.Unix(0, p.lastActive.Load())
	idleRef := lastActive
	if p.lastReopen.After(idleRef) {
		idleRef = p.lastReopen
	}
	if !p.idleFor.Equal(idleRef) {
		p.idleFor = idleRef
		p.idleClose = pl.IdleAfter() + pl.IdleClose()
	}
	active := now.Sub(lastActive) < pl.IdleAfter() || nPending > 0
	live := 0
	for st := range p.lanes {
		if !st.retiring && st.replacing == nil {
			live++
		}
	}

	// How many lanes the pool wants.
	target := 0
	switch {
	case !p.haveSession:
		target = 1 // one lane until the session exists
	case active:
		extra := 0
		if now.Sub(p.lastSample) >= sampleEvery {
			extra = p.sampleThrottle(now, live)
		} else {
			extra = p.thr.extra
		}
		target = min(baseLanes+extra, p.maxLanes)
	case now.Sub(idleRef) < p.idleClose:
		target = 1 // idle: shrink to a single lane
	default:
		// Idle long enough: close the last lane. While no lane is open,
		// keepalives are held, and a fresh lane carries them after a
		// browser-like pause.
		if live == 0 && p.dialing == 0 {
			if p.dormantAt.IsZero() {
				p.dormantAt = now
				p.reopenAfter = pl.IdleReopen()
			}
			if held && now.Sub(p.dormantAt) >= p.reopenAfter {
				p.lastReopen = now
				p.dormantAt = time.Time{}
				target = 1
			}
		}
	}
	if target > 0 {
		p.dormantAt = time.Time{}
	}
	// Open lanes up to the target, one dial at a time.
	if live+p.dialing < target && p.dialing == 0 && !now.Before(p.nextDial) {
		reason := "pool"
		switch {
		case live == 0 && !p.haveSession:
			reason = "first"
		case live == 0 && p.lastReopen.Equal(now):
			reason = "reopen"
		case live == 0:
			reason = "reconnect"
		case target > baseLanes && live >= baseLanes:
			reason = "probe"
		}
		p.dial(now, reason, nil)
	}

	// Retire lanes beyond the target, oldest first.
	if excess := live - target; excess > 0 {
		for range excess {
			var oldest *laneState
			for st := range p.lanes {
				if st.retiring || st.replacing != nil || !st.welcomed {
					continue
				}
				if oldest == nil || st.upAt.Before(oldest.upAt) {
					oldest = st
				}
			}
			if oldest == nil {
				break
			}
			p.retire(oldest, "shrink")
		}
	}

	// Hand over from old lanes to replacements that have ramped up. An old
	// lane retires once the traffic has moved off it: it has carried
	// nothing for the length of the overlap. One still carrying traffic
	// stays, because the lanes left would have to grow to take its share,
	// and TCP outside slow start grows too slowly for the tunnel not to
	// stall meanwhile. It stays no longer than MaxOverlap, and not once it
	// has carried the most any lane's byte budget can be.
	for st := range p.lanes {
		old := st.replacing
		if old == nil || !st.welcomed || now.Before(st.handoverAt) {
			continue
		}
		if _, ok := p.lanes[old]; ok {
			s := old.l.Stats()
			if c := s.DataSent + s.DataRecv; c != old.carried || old.quietSince.IsZero() {
				old.carried, old.quietSince = c, now
			}
			quiet := now.Sub(old.quietSince) >= p.churn.Overlap
			spent := now.Sub(st.handoverAt) >= p.churn.MaxOverlap ||
				p.churn.BytesMax > 0 && s.BytesSent+s.BytesRecv >= p.churn.BytesMax
			if !quiet && !spent {
				continue
			}
			p.retire(old, "churn")
		}
		st.replacing = nil
	}

	// Lane churn: replace lanes nearing the end of their lifetime, or of
	// their byte budget if they are old enough (see Churn), but not while
	// idle; an idle lane closes soon anyway.
	if active && p.dialing == 0 && !now.Before(p.nextDial) {
		for st := range p.lanes {
			if !st.welcomed || st.retiring || st.replacement || st.replacing != nil {
				continue
			}
			s := st.l.Stats()
			if p.churn.due(st.life, now.Sub(st.upAt), s.BytesSent+s.BytesRecv) {
				st.replacement = true
				p.dial(now, "churn", st)
				break
			}
		}
	}

	switch {
	case len(p.lanes) > 0 || p.dialing > 0:
		return activeTick
	case target > 0 || nPending > 0:
		// Waiting out a dial backoff.
		return max(time.Millisecond, p.nextDial.Sub(now))
	case held && !p.dormantAt.IsZero():
		return max(time.Millisecond, p.dormantAt.Add(p.reopenAfter).Sub(now))
	default:
		return time.Hour // nothing to do until a packet arrives
	}
}

// sampleThrottle measures each lane's throughput in the busier direction and
// feeds the throttle detector.
func (p *Pool) sampleThrottle(now time.Time, live int) int {
	dt := now.Sub(p.lastSample).Seconds()
	first := p.lastSample.IsZero()
	p.lastSample = now
	var up, down []laneRate
	var sumUp, sumDown float64
	for st := range p.lanes {
		if !st.welcomed || st.retiring {
			continue
		}
		s := st.l.Stats()
		if first || dt <= 0 || st.lastUp > s.DataSent || st.lastDown > s.DataRecv {
			st.lastUp, st.lastDown = s.DataSent, s.DataRecv
			continue
		}
		u := float64(s.DataSent-st.lastUp) / dt
		d := float64(s.DataRecv-st.lastDown) / dt
		st.lastUp, st.lastDown = s.DataSent, s.DataRecv
		settled := now.Sub(st.upAt) >= p.thr.settle
		up = append(up, laneRate{rate: u, settled: settled})
		down = append(down, laneRate{rate: d, settled: settled})
		sumUp += u
		sumDown += d
	}
	if first {
		return p.thr.extra
	}
	rates := down
	if sumUp > sumDown {
		rates = up
	}
	ready := live+p.dialing >= min(baseLanes+p.thr.extra, p.maxLanes) && p.dialing == 0
	return p.thr.update(now, rates, baseLanes, p.maxLanes, ready)
}

// dial opens a lane in the background. replaces is the lane it will take
// over from, for churn.
func (p *Pool) dial(now time.Time, reason string, replaces *laneState) {
	req := DialRequest{Reason: reason, Planner: p.planner, Limiter: &p.limit}
	if p.haveSession && (p.liveCount() > 0 || now.Sub(p.lastLaneAt) < p.welcome.ResumeWindow) {
		req.Join = true
		req.SessionID = p.session
	}
	var rtt time.Duration
	for st := range p.lanes {
		if r := st.l.BaseRTT(); r > 0 && (rtt == 0 || r < rtt) {
			rtt = r
		}
	}
	req.InitialRTT = rtt
	var taken []byte // read by dialed/dialFailed only after the dial returns
	if p.liveCount() == 0 {
		req.TakeFirstPacket = func() []byte {
			p.mu.Lock()
			defer p.mu.Unlock()
			if taken == nil && len(p.pending) > 0 {
				taken = p.pending[0]
				p.pendingSz -= len(taken)
				p.pending = p.pending[1:]
			}
			return taken
		}
	}
	ref := &laneRef{}
	req.Handler = lane.Handler{
		Data: func(l *lane.Lane, pkt []byte) {
			if !shape.IsKeepalive(pkt) {
				p.lastActive.Store(time.Now().UnixNano())
			}
			var rtt time.Duration
			if l != nil {
				rtt = l.BaseRTT()
			}
			p.source(ref).Push(pkt, rtt)
		},
		Lost: func(l *lane.Lane, lost wire.Lost) {
			var rtt time.Duration
			if l != nil {
				rtt = l.BaseRTT()
			}
			p.source(ref).Lost(lost.Index, lost.Counter, lost.Count, rtt)
		},
		// Nothing more will arrive on the lane, so the packets other lanes
		// deliver no longer wait for it.
		End: func(*lane.Lane) { p.source(ref).Close() },
		Retire: func(*lane.Lane) {
			p.post(func() {
				if ref.st == nil {
					ref.retired = true
					return
				}
				p.peerRetired(ref.st)
			})
		},
		Close: func(_ *lane.Lane, reason wire.CloseReason) {
			p.post(func() {
				if ref.st == nil {
					ref.closeReason = &reason
					return
				}
				p.sessionClosed(reason)
			})
		},
	}
	p.dialing++
	p.log.Debug("dialing lane", "reason", reason, "join", req.Join)
	go func() {
		ctx, cancel := context.WithTimeout(p.ctx, p.cfg.DialTimeout)
		l, err := p.cfg.Dial(ctx, req)
		cancel()
		if !p.post(func() { p.dialed(ref, req, replaces, l, err, taken) }) {
			p.source(ref).Close()
			if l != nil {
				l.Close()
			}
		}
	}()
}

// source returns the lane's way into the resequencer, adding it on first
// use: when the dial returns, or when the lane's first packet beats that.
func (p *Pool) source(ref *laneRef) *Source {
	ref.srcOnce.Do(func() { ref.src = p.reseq.Source() })
	return ref.src
}

func (p *Pool) liveCount() int {
	n := 0
	for st := range p.lanes {
		if !st.retiring {
			n++
		}
	}
	return n
}

// dialed registers a lane whose dial has returned.
func (p *Pool) dialed(ref *laneRef, req DialRequest, replaces *laneState, l PoolLane, err error, taken []byte) {
	p.dialing--
	now := time.Now()
	if errors.Is(err, ErrCredentialRejected) {
		// The dialer knows the credential is no good (it expired); no
		// amount of redialing will help.
		p.shutdown(err)
		return
	}
	if err != nil {
		p.source(ref).Close()
		p.dialFailed(now, err, req.Reason, taken)
		if replaces != nil {
			replaces.replacement = false
		}
		return
	}
	p.mu.Lock()
	closing := p.closing
	p.mu.Unlock()
	if closing {
		p.source(ref).Close()
		l.Close()
		return
	}
	p.laneSeq++
	st := &laneState{
		l:   l,
		seq: p.laneSeq,
		// The server may send on the lane from the moment it reads HELLO,
		// so from here on packets from other lanes wait for this one.
		src:  p.source(ref),
		life: p.churn.draw(p.rng),
		upAt: now,
		replacing: func() *laneState {
			if replaces != nil {
				if _, ok := p.lanes[replaces]; ok {
					return replaces
				}
			}
			return nil
		}(),
	}
	ref.st = st
	p.lanes[st] = struct{}{}
	p.thr.laneAdded(now)
	p.refreshScheduler()
	p.flushPending(req.Reason == "reopen")
	if ref.retired {
		p.peerRetired(st)
	}
	if ref.closeReason != nil {
		p.sessionClosed(*ref.closeReason)
		return
	}
	go func() {
		select {
		case <-l.Welcomed():
		case <-l.Done():
		}
		// A lane can be welcomed and die before this goroutine looks; it
		// still logged in, so report the WELCOME first.
		if _, ok := l.Welcome(); ok {
			p.post(func() { p.welcomed(st) })
		}
		<-l.Done()
		p.post(func() { p.laneDone(st) })
	}()
}

func (p *Pool) dialFailed(now time.Time, err error, reason string, taken []byte) {
	if p.ctx.Err() != nil {
		return
	}
	p.backoff = min(max(p.backoff*2, backoffMin), backoffMax)
	jitter := time.Duration(p.rng.Int64N(int64(p.backoff)/4 + 1))
	p.nextDial = now.Add(p.backoff + jitter)
	p.log.Debug("lane dial failed", "reason", reason, "err", err, "retry_in", p.backoff+jitter)
	if len(taken) > 0 {
		// Put the packet back so the next lane carries it.
		p.mu.Lock()
		p.pending = append([][]byte{taken}, p.pending...)
		p.pendingSz += len(taken)
		p.mu.Unlock()
	}
}

// welcomed records a lane's WELCOME.
func (p *Pool) welcomed(st *laneState) {
	if _, ok := p.lanes[st]; !ok {
		return
	}
	w, _ := st.l.Welcome()
	st.welcomed = true
	st.session = w.SessionID
	st.upAt = time.Now()
	p.backoff = 0
	p.nextDial = time.Time{}
	if !p.haveSession || w.SessionID != p.session {
		if p.haveSession {
			// The session expired on the server and this lane started a
			// new one. Lanes still in the old session are dead weight.
			p.log.Debug("session replaced", "old", p.session, "new", w.SessionID)
			for other := range p.lanes {
				if other != st && other.welcomed && other.session != w.SessionID {
					p.retire(other, "old session")
				}
			}
		}
		p.haveSession = true
		p.session = w.SessionID
		p.welcome = w
		p.planner = shape.NewPlanner(p.cfg.Profiles.Get(w.Profile))
		p.maxLanes = max(1, int(w.MaxLanes))
		p.sessionOnce.Do(func() { close(p.sessionUp) })
	}
	if st.replacing != nil {
		// The replacement takes the traffic from now on, as fast as its
		// connection's slow start allows, while the old lane carries the
		// rest; the old lane goes once the new one has had time to ramp up.
		st.handoverAt = time.Now().Add(max(p.churn.Overlap, overlapRTTs*st.l.BaseRTT()))
	}
	p.refreshScheduler()
}

// peerRetired handles RETIRE from the server: the lane takes no new DATA,
// and the pool opens a replacement on its next pass.
func (p *Pool) peerRetired(st *laneState) {
	st.retiring = true
	p.refreshScheduler()
}

// sessionClosed handles CLOSE from the server.
func (p *Pool) sessionClosed(reason wire.CloseReason) {
	p.log.Debug("server closed the session", "reason", reason)
	if reason == wire.CloseCredential {
		p.shutdown(ErrCredentialRejected)
		return
	}
	// The session is over; the next lane starts a new one.
	p.haveSession = false
	for st := range p.lanes {
		st.l.Close()
	}
}

func (p *Pool) laneDone(st *laneState) {
	if _, ok := p.lanes[st]; !ok {
		return
	}
	delete(p.lanes, st)
	st.src.Close()
	err := st.l.Err()
	if !st.welcomed {
		p.dialFailed(time.Now(), err, "login", nil)
	}
	for other := range p.lanes {
		if other.replacing == st {
			other.replacing = nil // nothing left to replace
		}
	}
	if len(p.lanes) == 0 {
		p.lastLaneAt = time.Now()
	}
	p.refreshScheduler()
	p.log.Debug("lane gone", "err", err, "lanes", len(p.lanes))
}

func (p *Pool) retire(st *laneState, why string) {
	if st.retiring {
		return
	}
	st.retiring = true
	st.l.Retire()
	p.refreshScheduler()
	p.log.Debug("retiring lane", "why", why)
}

// refreshScheduler gives the scheduler every lane that takes DATA, newest
// first: a lane takes over the traffic as soon as it is up, while the lanes
// before it carry what it cannot yet. The server orders its end of the
// lanes the same way. A lane whose replacement is up comes last, so that
// little is left on it when it retires.
func (p *Pool) refreshScheduler() {
	var live []*laneState
	leaving := map[*laneState]bool{}
	for st := range p.lanes {
		if !st.retiring {
			live = append(live, st)
		}
		if st.replacing != nil && st.welcomed {
			leaving[st.replacing] = true
		}
	}
	slices.SortFunc(live, func(a, b *laneState) int {
		if leaving[a] != leaving[b] {
			if leaving[a] {
				return 1
			}
			return -1
		}
		return cmp.Compare(b.seq, a.seq)
	})
	ls := make([]Lane, len(live))
	for i, st := range live {
		ls[i] = st.l
	}
	p.sched.SetLanes(ls)
	if len(ls) > 0 {
		p.lastLaneAt = time.Now()
	}
}

// flushPending sends what waited for a lane. A held keepalive goes too when
// the lane was opened for it.
func (p *Pool) flushPending(withKeepalive bool) {
	p.mu.Lock()
	pending := p.pending
	p.pending, p.pendingSz = nil, 0
	var ka []byte
	if withKeepalive {
		ka, p.heldKA = p.heldKA, nil
	}
	p.mu.Unlock()
	for _, pkt := range pending {
		p.sched.Send(pkt)
	}
	if ka != nil {
		p.sched.Send(ka)
	}
}
