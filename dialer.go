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
	// make the client forget it and race again.
	modeFailLimit = 2
)

// dialer opens lanes for the pool. It picks the carrier and SNI mode, races
// the modes on a network it hasn't seen, and learns from every lane's
// outcome.
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

// candidates are the choices raced on a new network.
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
// (forced, or remembered) rather than to be raced.
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
		return d.race(ctx, req, network, cellular)
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
			// The remembered mode stopped working here: race again.
			d.modes.ForgetMode(network)
			d.modeFails = 0
		}
	}
}

// race tries every SNI mode at once for a lane on a network the client
// hasn't seen, keeps the first that logs in, and remembers it (design §9).
// Allowlist filters usually reject a blocked handshake within one round
// trip, so racing costs little. The racing lanes carry no DATA: only the
// winner gets the first packet, once it has won.
func (d *dialer) race(ctx context.Context, req sched.DialRequest, network string, cellular bool) (sched.PoolLane, error) {
	cands := d.candidates()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		l   *lane.Lane
		c   Choice
		err error
	}
	results := make(chan result, len(cands))
	var winner atomic.Pointer[lane.Lane]
	for _, c := range cands {
		cfg := d.laneConfig(req, cellular)
		cfg.TakeFirstPacket = nil
		cfg.SNIMode = lane.SNIMode(c.Mode)
		cfg.ServerName = c.Name
		// Only the winner's events reach the pool.
		h := req.Handler
		cfg.Lane.Handler = lane.Handler{
			Data: func(l *lane.Lane, pkt []byte) {
				if winner.Load() == l && h.Data != nil {
					h.Data(l, pkt)
				}
			},
			Lost: func(l *lane.Lane, lost wire.Lost) {
				if winner.Load() == l && h.Lost != nil {
					h.Lost(l, lost)
				}
			},
			Retire: func(l *lane.Lane) {
				if winner.Load() == l && h.Retire != nil {
					h.Retire(l)
				}
			},
			Close: func(l *lane.Lane, r wire.CloseReason) {
				if winner.Load() == l && h.Close != nil {
					h.Close(l, r)
				}
			},
		}
		go func() {
			l, err := lane.Dial(ctx, cfg)
			if err == nil {
				select {
				case <-l.Welcomed():
				case <-l.Done():
					err = l.Err()
				case <-ctx.Done():
					err = ctx.Err()
				}
			}
			results <- result{l, c, err}
		}()
	}

	var errs []error
	var won *result
	for range cands {
		r := <-results
		if r.err == nil && won == nil {
			won = &r
			winner.Store(r.l)
			cancel() // stop the others
			continue
		}
		if r.l != nil {
			if _, ok := r.l.Welcome(); ok && !req.Join {
				// It started a session of its own; end it on the server.
				r.l.SendClose(wire.CloseNormal)
			} else {
				r.l.Close()
			}
		}
		if r.err != nil && !errors.Is(r.err, context.Canceled) {
			errs = append(errs, fmt.Errorf("%v: %w", r.c.Mode, r.err))
		}
	}
	if won == nil {
		d.outcome(false, lane.Direct, Choice{}, network)
		return nil, fmt.Errorf("tectonic: no SNI mode logged in: %w", errors.Join(errs...))
	}
	d.log.Info("SNI mode chosen for network", "mode", won.c.Mode, "network", network)
	d.outcome(true, lane.Direct, won.c, network)
	if req.TakeFirstPacket != nil {
		if pkt := req.TakeFirstPacket(); len(pkt) > 0 {
			won.l.Send(pkt)
		}
	}
	return won.l, nil
}
