package tectonic

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/pangeavpn/tectonic/lane"
	"github.com/pangeavpn/tectonic/sched"
	"github.com/pangeavpn/tectonic/shape"
	"github.com/pangeavpn/tectonic/wire"
)

const (
	// directFailLimit consecutive direct failures switch new lanes to the
	// CDN carrier.
	directFailLimit = 3
	// directRetry is how often a session on the CDN tries a direct lane
	// again.
	directRetry = 5 * time.Minute
	// modeFailLimit consecutive login failures with a remembered SNI mode
	// make the client forget it and work the mode out again, Own first.
	modeFailLimit = 2
)

// How long an SNI mode may make no progress, on a network the client hasn't
// seen, before the next mode is tried alongside it (see tryModes). The wait
// starts when the mode's ClientHello goes out and starts again when its TLS
// handshake completes. Each of those two steps is one round trip, and a
// step that has had no answer for this long is taken for blackholed.
//
// Waiting too long costs time, once per network and only where the stronger
// mode is silently dropped: the wait is added to the first connection, and
// then the mode that worked is remembered. Not waiting long enough costs
// the disguise: a borrowed name goes out to an address that isn't its
// owner's, on a network where the cover name would have worked. So the wait
// errs on the long side.
const (
	// modeStallRTTs is the wait in round trips, measured by the attempt's
	// own TCP handshake: on a new network there is nothing else to go by.
	// A step that loses a packet takes its round trip and a retransmission
	// timeout, which on a connection this young is three round trips. Six
	// leaves half as much again for a path whose round trips vary.
	modeStallRTTs = 6
	// modeStallMin is the least the wait can be. The TCP handshake may have
	// been answered by a proxy much nearer than the node, as mobile
	// carriers and satellite links do, and then says little about the
	// path. Two seconds is the 1 s a TCP with no measurement waits before
	// it sends a lost packet again (RFC 6298) and another second for the
	// round trip and the work at both ends. On a 150 ms path a healthy
	// login takes about half a second, each step under 200 ms, so this is
	// ten times what a step needs there.
	modeStallMin = 2 * time.Second
	// modeStallMax is the most the wait can be, on a very slow path. Two
	// modes whose ClientHellos get no answer are then waited out in 10 s,
	// which leaves the third half of the pool's 20 s dial timeout to log
	// in.
	modeStallMax = 5 * time.Second
)

// dialer opens lanes for the pool. It picks the carrier and SNI mode, tries
// the modes in order on a network it hasn't seen, and learns from every
// lane's outcome.
type dialer struct {
	cfg       Config
	log       *slog.Logger
	node      string
	keyID     wire.KeyID
	deviceKey [wire.KeyLen]byte
	pins      []lane.Pin
	profiles  *shape.Set
	sessions  utls.ClientSessionCache
	modes     ModeStore
	// stallMin and stallMax are modeStallMin and modeStallMax, here so that
	// tests can shorten them.
	stallMin, stallMax time.Duration

	mu            sync.Mutex
	rng           *rand.Rand
	network       string
	cellular      bool
	directFails   int
	cdnFails      int
	onCDN         bool
	lastDirectTry time.Time
	modeFails     int
}

func newDialer(cfg Config) (*dialer, error) {
	p := cfg.Profile
	if p.Node == "" {
		return nil, errors.New("tectonic: profile has no node address")
	}
	node := p.Node
	if _, _, err := net.SplitHostPort(node); err != nil {
		node = net.JoinHostPort(node, "443")
	}
	if len(p.KeyID) != wire.KeyIDLen || len(p.DeviceKey) != wire.KeyLen {
		return nil, errors.New("tectonic: profile key_id must be 20 bytes and device_key 32")
	}
	d := &dialer{
		cfg:      cfg,
		node:     node,
		sessions: utls.NewLRUClientSessionCache(64),
		modes:    cfg.Modes,
		stallMin: modeStallMin,
		stallMax: modeStallMax,
		network:  cfg.Network,
		cellular: cfg.Cellular,
	}
	copy(d.keyID[:], p.KeyID)
	copy(d.deviceKey[:], p.DeviceKey)
	if d.keyID.Expired(time.Now()) {
		return nil, fmt.Errorf("%w: key_id expired", ErrCredentialRejected)
	}
	for _, s := range p.Pins {
		pin, err := lane.ParsePin(s)
		if err != nil {
			return nil, err
		}
		d.pins = append(d.pins, pin)
	}
	var err error
	if d.profiles, err = shape.NewSet(p.Shaping...); err != nil {
		return nil, err
	}
	if d.modes == nil {
		d.modes = NewMemoryModeStore()
	}
	if len(d.candidates()) == 0 {
		return nil, errNoModes
	}
	switch cfg.SNIMode {
	case SNIAuto:
	case SNIOwn, SNIBorrowed, SNINone:
		if !d.allowed(cfg.SNIMode) {
			return nil, fmt.Errorf("tectonic: the profile does not allow SNI mode %v", cfg.SNIMode)
		}
	default:
		return nil, fmt.Errorf("tectonic: unknown SNI mode %d", cfg.SNIMode)
	}
	if p.CDN != nil && p.CDN.Host == "" {
		return nil, errors.New("tectonic: CDN route has no host")
	}
	d.log = cfg.Logger
	if d.log == nil {
		d.log = slog.New(slog.DiscardHandler)
	}
	var seed [32]byte
	crand.Read(seed[:])
	d.rng = rand.New(rand.NewChaCha8(seed))
	return d, nil
}

// allowed reports whether the profile has what mode needs.
func (d *dialer) allowed(m SNIMode) bool {
	switch m {
	case SNIOwn:
		return d.cfg.Profile.CoverDomain != ""
	case SNIBorrowed:
		return len(d.pins) > 0 && (d.cfg.SNI != "" || len(d.cfg.Profile.BorrowedSNI) > 0)
	case SNINone:
		// Pinned, or a trusted IP certificate.
		return true
	}
	return false
}

// candidates are the modes to try on a new network, the best disguise
// first.
func (d *dialer) candidates() []Choice {
	var out []Choice
	for _, m := range []SNIMode{SNIOwn, SNIBorrowed, SNINone} {
		if d.allowed(m) {
			out = append(out, Choice{Mode: m, Name: d.nameFor(m)})
		}
	}
	return out
}

func (d *dialer) nameFor(m SNIMode) string {
	switch m {
	case SNIOwn:
		return d.cfg.Profile.CoverDomain
	case SNIBorrowed:
		if d.cfg.SNI != "" {
			return d.cfg.SNI
		}
		if list := d.cfg.Profile.BorrowedSNI; len(list) > 0 {
			if d.rng == nil {
				return list[0]
			}
			d.mu.Lock()
			defer d.mu.Unlock()
			return list[d.rng.IntN(len(list))]
		}
	}
	return ""
}

func (d *dialer) setNetwork(network string, cellular bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if network != d.network {
		d.modeFails = 0
		// A new network may not block what the old one did.
		d.directFails, d.onCDN = 0, false
	}
	d.network, d.cellular = network, cellular
}

func (d *dialer) state() (string, Choice) {
	d.mu.Lock()
	network, onCDN := d.network, d.onCDN
	d.mu.Unlock()
	c, _ := d.choice(network)
	if onCDN {
		return lane.CDN.String(), c
	}
	return lane.Direct.String(), c
}

// choice returns the SNI mode to use on network, and whether it is settled
// (forced, or remembered) rather than still to be found.
func (d *dialer) choice(network string) (Choice, bool) {
	if d.cfg.SNIMode != SNIAuto {
		return Choice{Mode: d.cfg.SNIMode, Name: d.nameFor(d.cfg.SNIMode)}, true
	}
	if c, ok := d.modes.Mode(network); ok && d.allowed(c.Mode) {
		if c.Mode == SNIBorrowed && d.cfg.SNI != "" {
			c.Name = d.cfg.SNI // the user's own name wins
		}
		return c, true
	}
	return Choice{}, false
}

// dial is the pool's DialFunc.
func (d *dialer) dial(ctx context.Context, req sched.DialRequest) (sched.PoolLane, error) {
	if d.keyID.Expired(time.Now()) {
		return nil, fmt.Errorf("%w: key_id expired", ErrCredentialRejected)
	}
	d.mu.Lock()
	network, cellular := d.network, d.cellular
	useCDN := d.cfg.Profile.CDN != nil && d.onCDN && time.Since(d.lastDirectTry) < directRetry
	if !useCDN {
		d.lastDirectTry = time.Now()
	}
	d.mu.Unlock()

	if useCDN {
		cfg := d.laneConfig(req, cellular)
		cdn := d.cfg.Profile.CDN
		cfg.Carrier = lane.CDN
		cfg.Addr = cdn.Edge
		if cfg.Addr == "" {
			cfg.Addr = net.JoinHostPort(cdn.Host, "443")
		}
		cfg.ServerName = cdn.Host
		cfg.Path = cdn.Path
		l, err := lane.Dial(ctx, cfg)
		d.watch(l, err, lane.CDN, Choice{}, network)
		return poolLane(l, err)
	}

	c, settled := d.choice(network)
	if !settled {
		return d.tryModes(ctx, req, network, cellular)
	}
	cfg := d.laneConfig(req, cellular)
	cfg.SNIMode = lane.SNIMode(c.Mode)
	cfg.ServerName = c.Name
	l, err := lane.Dial(ctx, cfg)
	d.watch(l, err, lane.Direct, c, network)
	return poolLane(l, err)
}

// poolLane converts without wrapping a nil *lane.Lane in a non-nil
// interface.
func poolLane(l *lane.Lane, err error) (sched.PoolLane, error) {
	if err != nil || l == nil {
		return nil, err
	}
	return l, nil
}

func (d *dialer) laneConfig(req sched.DialRequest, cellular bool) lane.DialConfig {
	return lane.DialConfig{
		Addr:            d.node,
		Pins:            d.pins,
		RootCAs:         d.cfg.RootCAs,
		SessionCache:    d.sessions,
		DialContext:     d.cfg.DialContext,
		Control:         d.cfg.Control,
		KeyID:           d.keyID,
		DeviceKey:       d.deviceKey,
		SessionID:       req.SessionID,
		Join:            req.Join,
		Cellular:        cellular,
		TakeFirstPacket: req.TakeFirstPacket,
		Lane: lane.Options{
			Handler:    req.Handler,
			Planner:    req.Planner,
			Profiles:   d.profiles,
			InitialRTT: req.InitialRTT,
			Limiter:    req.Limiter,
			Logger:     d.log,
		},
	}
}

// watch learns from a lane's outcome: whether it logged in decides the
// carrier and whether a remembered SNI mode still works.
func (d *dialer) watch(l *lane.Lane, err error, carrier lane.Carrier, c Choice, network string) {
	if err != nil {
		d.outcome(false, carrier, c, network)
		return
	}
	go func() {
		select {
		case <-l.Welcomed():
			d.outcome(true, carrier, c, network)
		case <-l.Done():
			if _, ok := l.Welcome(); ok {
				d.outcome(true, carrier, c, network)
			} else {
				d.outcome(false, carrier, c, network)
			}
		}
	}()
}

func (d *dialer) outcome(ok bool, carrier lane.Carrier, c Choice, network string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if carrier == lane.CDN {
		if ok {
			d.cdnFails = 0
		} else if d.cdnFails++; d.cdnFails >= directFailLimit {
			// The CDN is failing too: try direct again.
			d.cdnFails, d.directFails, d.onCDN = 0, 0, false
			d.log.Info("CDN lanes failing; trying direct again")
		}
		return
	}
	if ok {
		if d.onCDN {
			d.log.Info("direct lanes work again; leaving the CDN")
		}
		d.directFails, d.onCDN, d.modeFails = 0, false, 0
		if d.cfg.SNIMode == SNIAuto && c.Mode != SNIAuto {
			d.modes.SetMode(network, c)
		}
		return
	}
	d.directFails++
	if d.cfg.Profile.CDN != nil && d.directFails >= directFailLimit && !d.onCDN {
		d.onCDN = true
		d.log.Info("direct lanes failing; switching to the CDN carrier")
	}
	if d.cfg.SNIMode == SNIAuto && c.Mode != SNIAuto {
		if d.modeFails++; d.modeFails >= modeFailLimit {
			// The remembered mode stopped working here: work it out
			// again, starting from Own.
			d.modes.ForgetMode(network)
			d.modeFails = 0
		}
	}
}

// stallBound is how long a mode whose TCP handshake took connect may go
// without progress before the next mode is tried alongside it.
func (d *dialer) stallBound(connect time.Duration) time.Duration {
	return min(max(modeStallRTTs*connect, d.stallMin), d.stallMax)
}

// connect opens the TCP connection for tryModes, which needs to know when
// it is up. It does what lane.Dial does when left to open the connection
// itself, apart from setting TCP_NOTSENT_LOWAT before connecting; the lane
// sets that again when it takes the connection over.
func (d *dialer) connect(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.cfg.DialContext != nil {
		return d.cfg.DialContext(ctx, network, addr)
	}
	nd := net.Dialer{Control: d.cfg.Control}
	return nd.DialContext(ctx, network, addr)
}

// tryModes opens a lane on a network the client hasn't seen and finds out
// which SNI mode to use there (design §9). It tries the modes one after
// another, the best disguise first: Own, then Borrowed, then None. A weaker
// mode's ClientHello is sent only once the mode before it has
//
//   - failed after its own ClientHello went out (the connection was reset,
//     the handshake failed, or the login did), in which case the next mode
//     starts at once; or
//   - made no progress for stallBound, in which case it is left running
//     and the next mode starts alongside it.
//
// The first attempt to log in is kept and its mode remembered for the
// network. Where Own works, then, Own is what is chosen, and no other
// ClientHello is sent.
//
// A connection that fails before its ClientHello is sent says nothing
// about the name, since every mode connects to the same address. No weaker
// mode is tried on account of it, and nothing follows it: once the
// attempts already under way have ended, the dial fails as it would with a
// settled mode, and the pool dials again.
//
// The first WireGuard packet rides in an attempt's login, as it does with a
// settled mode, while that attempt is the only one under way: so where the
// first mode works it reaches the node within two round trips, and after a
// mode has failed outright it rides in the next one's login. Once two
// attempts are under way no further login carries it, and it goes out on
// the chosen lane as soon as that lane is chosen. See modeSearch.take.
func (d *dialer) tryModes(ctx context.Context, req sched.DialRequest, network string, cellular bool) (sched.PoolLane, error) {
	cands := d.candidates()
	if len(cands) == 0 {
		return nil, errNoModes
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // stops the attempts that are still connecting
	s := &modeSearch{
		d: d, ctx: ctx, req: req, cellular: cellular,
		// Each attempt sends at most one event of each kind, so no send
		// blocks, even after the search has returned.
		events: make(chan attemptEvent, attemptEventKinds*len(cands)),
		over:   make(chan struct{}),
	}
	stall := time.NewTimer(time.Hour)
	stall.Stop()
	defer stall.Stop()

	var (
		attempts []*attempt
		errs     []error
		open     int  // attempts that have neither failed nor logged in
		halted   bool // a connection failed before its ClientHello: try no more modes
	)
	// start begins the next mode's attempt, and says why in the log.
	// stalled is the attempt whose wait ran out, if that is the reason.
	start := func(stalled *attempt, why string, args ...any) {
		a := &attempt{c: cands[len(attempts)]}
		if !s.begin(a, stalled) {
			return
		}
		if len(attempts) > 0 {
			d.log.Debug(why, append(args, "next", a.c.Mode, "network", network)...)
		}
		attempts = append(attempts, a)
		open++
		stall.Stop() // its wait starts when its ClientHello goes out
		go s.run(a)
	}
	finish := func() (sched.PoolLane, error) {
		won, l, losers := s.end(attempts)
		for _, loser := range losers {
			s.discard(loser)
		}
		if won == nil {
			d.outcome(false, lane.Direct, Choice{}, network)
			return nil, fmt.Errorf("tectonic: no SNI mode logged in: %w", errors.Join(errs...))
		}
		d.log.Info("SNI mode chosen for network", "mode", won.c.Mode, "network", network)
		d.outcome(true, lane.Direct, won.c, network)
		return l, nil
	}

	start(nil, "")
	for {
		select {
		case ev := <-s.events:
			newest := ev.a == attempts[len(attempts)-1]
			switch ev.kind {
			case loggedIn:
				return finish()
			case helloSent, loginSent:
				// The step before this one was answered. Give the next
				// one as long.
				if ev.kind == helloSent {
					ev.a.wait = d.stallBound(ev.rtt)
				} else {
					ev.a.login = true
				}
				if newest && len(attempts) < len(cands) && !halted {
					stall.Reset(ev.a.wait)
				}
			case failed:
				open--
				errs = append(errs, fmt.Errorf("%v: %w", ev.a.c.Mode, ev.err))
				if !ev.sent {
					halted = true
				}
				if newest {
					stall.Stop()
				}
				switch {
				case newest && len(attempts) < len(cands) && !halted:
					start(nil, "SNI mode failed; trying the next", "mode", ev.a.c.Mode, "err", ev.err)
				case open == 0:
					return finish()
				}
			}
		case <-stall.C:
			if len(attempts) < len(cands) && !halted {
				newest := attempts[len(attempts)-1]
				start(newest, "SNI mode is getting no answer; trying the next alongside it", "mode", newest.c.Mode)
			}
		case <-ctx.Done():
			errs = append(errs, ctx.Err())
			return finish()
		}
	}
}

// modeSearch is one run of tryModes.
type modeSearch struct {
	d        *dialer
	ctx      context.Context
	req      sched.DialRequest
	cellular bool
	events   chan attemptEvent
	over     chan struct{} // closed when the search returns
	// won is the attempt that was chosen. Only its lane's events reach the
	// pool.
	won atomic.Pointer[attempt]

	mu       sync.Mutex
	finished bool
	live     int      // attempts started that have not failed
	newest   *attempt // the last one started
	first    []byte   // the first packet, once it has been taken from the pool
	carrier  *attempt // the attempt whose login it went out with, while that attempt is open
}

// attempt is one SNI mode's try at logging in.
type attempt struct {
	c Choice
	// wait is the attempt's stallBound, and login whether its login has
	// been sent, as far as tryModes's loop has heard. Only the loop's
	// goroutine uses them.
	wait  time.Duration
	login bool

	// Guarded by modeSearch.mu.
	l    *lane.Lane // from when its login has been written
	dead bool       // it ended without logging in
}

// What an attempt tells tryModes's loop.
const (
	helloSent = iota // TCP is up and the ClientHello is on its way
	loginSent        // TLS is done and HELLO has been written
	loggedIn         // WELCOME arrived and the attempt was chosen
	failed
	attemptEventKinds
)

type attemptEvent struct {
	a    *attempt
	kind int
	rtt  time.Duration // helloSent: how long the TCP handshake took
	err  error         // failed: why
	sent bool          // failed: whether its ClientHello had gone out
}

// run makes one attempt and reports how it goes.
func (s *modeSearch) run(a *attempt) {
	cfg := s.d.laneConfig(s.req, s.cellular)
	cfg.SNIMode = lane.SNIMode(a.c.Mode)
	cfg.ServerName = a.c.Name
	sent := false
	cfg.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		start := time.Now()
		conn, err := s.d.connect(ctx, network, addr)
		if err == nil {
			sent = true
			s.events <- attemptEvent{a: a, kind: helloSent, rtt: time.Since(start)}
		}
		return conn, err
	}
	cfg.TakeFirstPacket = nil
	if s.req.TakeFirstPacket != nil {
		cfg.TakeFirstPacket = func() []byte { return s.take(a) }
	}
	cfg.Lane.Handler = s.handler(a)

	l, err := lane.Dial(s.ctx, cfg)
	if err == nil {
		s.mu.Lock()
		a.l = l
		finished, won := s.finished, s.won.Load() == a
		s.mu.Unlock()
		switch {
		case won:
			return // chosen already, from its lane's Welcome
		case finished:
			s.discard(l) // the search ended while this was connecting
			return
		}
		s.events <- attemptEvent{a: a, kind: loginSent}
		select {
		case <-l.Done():
			if err = l.Err(); err == nil {
				err = lane.ErrClosed
			}
		case <-s.over:
			return // chosen, or discarded by tryModes
		}
	}
	if s.fail(a) {
		s.events <- attemptEvent{a: a, kind: failed, err: err, sent: sent}
	}
}

// begin counts a in as the newest attempt. It refuses if an attempt has
// logged in and the loop has yet to hear of it. stalled is the attempt
// whose wait ran out, if that is why a is starting; begin also refuses if
// stalled has sent its login with the first packet in the meantime: the
// login gets a wait of its own, which starts when the loop hears of it.
func (s *modeSearch) begin(a, stalled *attempt) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.won.Load() != nil {
		return false
	}
	if stalled != nil && s.carrier == stalled && !stalled.login {
		return false
	}
	s.live++
	s.newest = a
	return true
}

// take is an attempt's TakeFirstPacket: lane.Dial calls it the moment TLS
// completes, and what it returns goes out in the same record as HELLO.
//
// The packet must reach the session the pool ends up with, and no other
// session that lives. So an attempt gets it for its login only while it is
// the only attempt under way: the newest, with every one before it failed.
// Another attempt then starts only when this one has failed, or when its
// login has gone a whole stallBound without an answer, and those are the
// only two cases in which the carrier is given up for another. Its packet
// is then sent again on the lane that is chosen (see welcomed), so it is
// not lost with a mode that turned out to be blocked.
//
// One case cannot be told apart from here. If the carrier's login reached
// the node and was accepted, and WELCOME then never came back or came too
// late, the node has started a session and passed the packet on, and the
// packet goes again on the chosen lane. That first session has no lanes,
// and the node drops it when its resume window ends; WireGuard discards the
// second copy as a replay. Not sending it again would lose the packet in
// the likelier case, that the login never arrived or was refused.
func (s *modeSearch) take(a *attempt) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished || s.live != 1 || s.newest != a || s.carrier != nil {
		// With two attempts under way the packet waits for the one that
		// is chosen. After the search the pool's own hand-over is running:
		// the packet is the chosen lane's, or back in the pool's queue.
		return nil
	}
	if s.first == nil {
		s.first = s.req.TakeFirstPacket()
	}
	if len(s.first) == 0 {
		return nil
	}
	s.carrier = a
	return s.first
}

// fail records that a ended without logging in. It reports false if that
// no longer matters: a was chosen, or the search is over.
func (s *modeSearch) fail(a *attempt) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished || s.won.Load() == a {
		return false
	}
	a.dead = true
	s.live--
	if s.carrier == a {
		s.carrier = nil
	}
	return true
}

// welcomed runs on a's lane when WELCOME arrives, before the lane reads
// anything else. The first attempt to get here is chosen, so everything its
// lane receives from now on reaches the pool.
func (s *modeSearch) welcomed(a *attempt, l *lane.Lane) {
	s.mu.Lock()
	if s.finished || a.dead || s.won.Load() != nil {
		s.mu.Unlock()
		return
	}
	a.l = l
	s.won.Store(a)
	var pkt []byte
	if s.carrier != a {
		// The first packet, if the pool has handed it over, went with an
		// attempt that failed or is being given up. If the pool still has
		// it, the pool sends it when the dial returns.
		pkt = s.first
	}
	s.carrier = a
	s.mu.Unlock()
	if len(pkt) > 0 {
		l.Send(pkt)
	}
	s.events <- attemptEvent{a: a, kind: loggedIn}
}

// end closes the search. It returns the attempt that was chosen and its
// lane, if any, and the lanes of the others that got as far as sending
// their login.
func (s *modeSearch) end(attempts []*attempt) (won *attempt, l *lane.Lane, losers []*lane.Lane) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finished = true
	close(s.over)
	won = s.won.Load()
	for _, a := range attempts {
		switch {
		case a == won:
			l = a.l
		case a.l != nil:
			losers = append(losers, a.l)
		}
	}
	return won, l, losers
}

// discard closes the lane of an attempt that wasn't chosen.
func (s *modeSearch) discard(l *lane.Lane) {
	if _, ok := l.Welcome(); ok && !s.req.Join {
		// It started a session of its own; end it on the server.
		l.SendClose(wire.CloseNormal)
		return
	}
	l.Close()
}

// handler passes a lane's events on to the pool once its attempt has been
// chosen. The others' are dropped: they belong to no session of the pool's.
func (s *modeSearch) handler(a *attempt) lane.Handler {
	h := s.req.Handler
	chosen := func() bool { return s.won.Load() == a }
	return lane.Handler{
		Welcome: func(l *lane.Lane, w wire.Welcome) {
			s.welcomed(a, l)
			if chosen() && h.Welcome != nil {
				h.Welcome(l, w)
			}
		},
		Data: func(l *lane.Lane, pkt []byte) {
			if chosen() && h.Data != nil {
				h.Data(l, pkt)
			}
		},
		Lost: func(l *lane.Lane, lost wire.Lost) {
			if chosen() && h.Lost != nil {
				h.Lost(l, lost)
			}
		},
		Retire: func(l *lane.Lane) {
			if chosen() && h.Retire != nil {
				h.Retire(l)
			}
		},
		Close: func(l *lane.Lane, r wire.CloseReason) {
			if chosen() && h.Close != nil {
				h.Close(l, r)
			}
		},
		End: func(l *lane.Lane) {
			if chosen() && h.End != nil {
				h.End(l)
			}
		},
	}
}
