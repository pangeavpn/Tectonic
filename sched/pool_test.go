package sched

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic/lane"
	"github.com/pangeavpn/tectonic/shape"
	"github.com/pangeavpn/tectonic/wire"
)

// fakeLane is a PoolLane whose events the test drives.
type fakeLane struct {
	req   DialRequest
	first []byte

	mu          sync.Mutex
	sent        [][]byte
	retired     bool
	closeReason *wire.CloseReason
	welcome     wire.Welcome
	stats       lane.Stats

	welcomed     chan struct{}
	welcomedOnce sync.Once
	done         chan struct{}
	doneOnce     sync.Once
	err          error
}

func newFakeLane(req DialRequest) *fakeLane {
	return &fakeLane{req: req, welcomed: make(chan struct{}), done: make(chan struct{})}
}

func (l *fakeLane) Send(pkt []byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.retired || l.isDone() {
		return false
	}
	l.sent = append(l.sent, append([]byte(nil), pkt...))
	l.stats.DataSent += uint64(len(pkt))
	return true
}
func (l *fakeLane) ETA(int) time.Duration     { return time.Millisecond }
func (l *fakeLane) Retransmitting() bool      { return false }
func (l *fakeLane) Lost(wire.Lost) bool       { return true }
func (l *fakeLane) Welcomed() <-chan struct{} { return l.welcomed }
func (l *fakeLane) Welcome() (wire.Welcome, bool) {
	select {
	case <-l.welcomed:
		return l.welcome, true
	default:
		return wire.Welcome{}, false
	}
}
func (l *fakeLane) Done() <-chan struct{} { return l.done }
func (l *fakeLane) Err() error {
	select {
	case <-l.done:
		return l.err
	default:
		return nil
	}
}
func (l *fakeLane) Retire() {
	l.mu.Lock()
	l.retired = true
	l.mu.Unlock()
	l.end(nil)
}
func (l *fakeLane) SendClose(r wire.CloseReason) {
	l.mu.Lock()
	l.closeReason = &r
	l.mu.Unlock()
	l.end(lane.ErrSessionClosed)
}
func (l *fakeLane) Close() error { l.end(lane.ErrClosed); return nil }
func (l *fakeLane) Stats() lane.Stats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stats
}
func (l *fakeLane) RTT() time.Duration        { return 10 * time.Millisecond }
func (l *fakeLane) BaseRTT() time.Duration    { return 10 * time.Millisecond }
func (l *fakeLane) SetPlanner(*shape.Planner) {}
func (l *fakeLane) isDone() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}
func (l *fakeLane) end(err error) {
	l.doneOnce.Do(func() { l.err = err; close(l.done) })
}
func (l *fakeLane) doWelcome(sid byte) {
	l.welcome = wire.Welcome{MaxLanes: 6, ResumeWindow: time.Minute}
	l.welcome.SessionID[0] = sid
	l.welcomedOnce.Do(func() { close(l.welcomed) })
}
func (l *fakeLane) wasRetired() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.retired
}
func (l *fakeLane) sentCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sent)
}

// carry records n bytes of payload arriving from the server on the lane.
func (l *fakeLane) carry(n uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stats.DataRecv += n
}

// fakeDialer hands out fakeLanes and lets the test see each request.
type fakeDialer struct {
	lanes   chan *fakeLane
	gate    chan struct{} // if set, each dial waits for a token (the TLS handshake)
	mu      sync.Mutex
	welcome byte // if non-zero, lanes are welcomed into this session at once
	fail    int
}

func (d *fakeDialer) setWelcome(sid byte) {
	d.mu.Lock()
	d.welcome = sid
	d.mu.Unlock()
}

func newFakeDialer() *fakeDialer { return &fakeDialer{lanes: make(chan *fakeLane, 64)} }

func (d *fakeDialer) dial(ctx context.Context, req DialRequest) (PoolLane, error) {
	if d.gate != nil {
		select {
		case <-d.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	d.mu.Lock()
	if d.fail > 0 {
		d.fail--
		d.mu.Unlock()
		return nil, errors.New("network down")
	}
	welcome := d.welcome
	d.mu.Unlock()
	l := newFakeLane(req)
	if req.TakeFirstPacket != nil {
		l.first = req.TakeFirstPacket()
	}
	if welcome != 0 {
		l.doWelcome(welcome)
	}
	d.lanes <- l
	return l, nil
}

func (d *fakeDialer) next(t *testing.T) *fakeLane {
	t.Helper()
	select {
	case l := <-d.lanes:
		return l
	case <-time.After(5 * time.Second):
		t.Fatal("no lane dialed")
		return nil
	}
}

func (d *fakeDialer) none(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case l := <-d.lanes:
		t.Fatalf("unexpected dial: %+v", l.req.Reason)
	case <-time.After(within):
	}
}

func fastTicks(t *testing.T) {
	old := activeTick
	activeTick = 10 * time.Millisecond
	t.Cleanup(func() { activeTick = old })
}

func testProfiles(t *testing.T, mod func(*shape.Profile)) *shape.Set {
	p := shape.Default()
	if mod != nil {
		mod(p)
	}
	s, err := shape.NewSet(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newTestPool(t *testing.T, d *fakeDialer, cfg PoolConfig) *Pool {
	fastTicks(t)
	cfg.Dial = d.dial
	if cfg.Profiles == nil {
		cfg.Profiles = testProfiles(t, nil)
	}
	p := NewPool(cfg)
	t.Cleanup(func() { p.Close() })
	return p
}

func wgInit() []byte {
	b := make([]byte, 148)
	b[0] = 1
	return b
}

func keepalive() []byte {
	b := make([]byte, 32)
	b[0] = 4
	return b
}

func TestPoolFirstPacketRidesTheFirstFlight(t *testing.T) {
	d := newFakeDialer()
	d.gate = make(chan struct{})
	p := newTestPool(t, d, PoolConfig{})
	// WireGuard's handshake arrives while the first lane's TLS handshake is
	// still running.
	time.Sleep(20 * time.Millisecond)
	p.Send(wgInit())
	d.gate <- struct{}{}
	l1 := d.next(t)
	if l1.req.Reason != "first" || l1.req.Join {
		t.Fatalf("first request = %+v", l1.req)
	}
	if !bytes.Equal(l1.first, wgInit()) {
		t.Fatal("the first WireGuard packet missed the first flight")
	}
	if l1.sentCount() != 0 {
		t.Fatal("first packet sent twice")
	}

	// After WELCOME a second lane opens straight away and joins the session.
	l1.doWelcome(7)
	if err := p.WaitSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.gate <- struct{}{}
	l2 := d.next(t)
	if !l2.req.Join || l2.req.SessionID[0] != 7 {
		t.Fatalf("second lane request = %+v", l2.req)
	}
	l2.doWelcome(7)
	d.none(t, 100*time.Millisecond) // two lanes is the base

	for range 10 {
		p.Send(make([]byte, 1000))
	}
	if l1.sentCount()+l2.sentCount() != 10 {
		t.Fatalf("sent %d+%d", l1.sentCount(), l2.sentCount())
	}
}

func TestPoolReceives(t *testing.T) {
	d := newFakeDialer()
	d.welcome = 1
	got := make(chan []byte, 1)
	newTestPool(t, d, PoolConfig{Receive: func(pkt []byte) { got <- append([]byte(nil), pkt...) }})
	l := d.next(t)
	l.req.Handler.Data(nil, []byte("hello"))
	if b := <-got; string(b) != "hello" {
		t.Fatalf("received %q", b)
	}
}

func TestPoolDoesNotWaitForWhatTheNodeDropped(t *testing.T) {
	d := newFakeDialer()
	d.welcome = 1
	got := make(chan uint64, 8)
	p := newTestPool(t, d, PoolConfig{Receive: func(pkt []byte) {
		_, ctr, _ := transportHeader(pkt)
		got <- ctr
	}})
	l1, l2 := d.next(t), d.next(t)
	// Counter 0 arrives on one lane. The node dropped 1 and says so on the
	// lane that carries 2, which is handed on without waiting for the
	// first lane to show that it has passed 1.
	l1.req.Handler.Data(nil, wgData(3, 0, 1400))
	l2.req.Handler.Lost(nil, wire.Lost{Index: 3, Counter: 1, Count: 1})
	l2.req.Handler.Data(nil, wgData(3, 2, 1400))
	for _, want := range []uint64{0, 2} {
		select {
		case ctr := <-got:
			if ctr != want {
				t.Fatalf("received counter %d, want %d", ctr, want)
			}
		case <-time.After(HoldBase / 2):
			t.Fatalf("counter %d was held back for a packet the node said it dropped", want)
		}
	}
	if st := p.Stats().Resequencer; st.Lost != 1 || st.Skipped != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestPoolGivesEveryLaneTheSessionsSendLimit(t *testing.T) {
	d := newFakeDialer()
	d.welcome = 1
	p := newTestPool(t, d, PoolConfig{})
	l1, l2 := d.next(t), d.next(t)
	if l1.req.Limiter != lane.Limiter(&p.limit) || l2.req.Limiter != lane.Limiter(&p.limit) {
		t.Fatalf("lanes were given limiters %v and %v, want the session's", l1.req.Limiter, l2.req.Limiter)
	}
	if st := p.Stats().Limit; st.Rate != 0 || st.On != 0 {
		t.Fatalf("a new session has a send limit: %+v", st)
	}
}

func TestPoolChurnReplacesBeforeRetiring(t *testing.T) {
	d := newFakeDialer()
	d.welcome = 1
	p := newTestPool(t, d, PoolConfig{Churn: Churn{
		LifetimeMedian: 300 * time.Millisecond, LifetimeMin: 300 * time.Millisecond, LifetimeMax: 300 * time.Millisecond,
		Lead: 100 * time.Millisecond, Overlap: 50 * time.Millisecond,
	}})
	keepBusy := make(chan struct{})
	defer close(keepBusy)
	go func() {
		for {
			select {
			case <-keepBusy:
				return
			case <-time.After(20 * time.Millisecond):
				p.Send(make([]byte, 100))
			}
		}
	}()
	l1, l2 := d.next(t), d.next(t)
	start := time.Now()
	r := d.next(t)
	if r.req.Reason != "churn" || !r.req.Join {
		t.Fatalf("replacement request = %+v", r.req)
	}
	if el := time.Since(start); el < 100*time.Millisecond {
		t.Fatalf("replacement after %v, too early", el)
	}
	// It was welcomed at once, so exactly one of the old lanes retires.
	deadline := time.Now().Add(2 * time.Second)
	for !l1.wasRetired() && !l2.wasRetired() {
		if time.Now().After(deadline) {
			t.Fatal("old lane never retired after its replacement came up")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if l1.wasRetired() && l2.wasRetired() && time.Since(start) < 150*time.Millisecond {
		t.Fatal("both lanes retired at once")
	}
}

func TestPoolPrefersTheNewestLane(t *testing.T) {
	d := newFakeDialer()
	d.welcome = 1
	p := newTestPool(t, d, PoolConfig{})
	p.Send(wgInit())
	l1, l2 := d.next(t), d.next(t)
	deadline := time.Now().Add(2 * time.Second)
	for p.sched.Len() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the second lane never joined the scheduler")
		}
		time.Sleep(time.Millisecond)
	}
	// Both lanes report the same delivery estimate, so the scheduler's
	// order of preference decides: the newest lane takes the traffic.
	before1, before2 := l1.sentCount(), l2.sentCount()
	for range 10 {
		p.Send(make([]byte, 500))
	}
	if got1, got2 := l1.sentCount()-before1, l2.sentCount()-before2; got1 != 0 || got2 != 10 {
		t.Fatalf("older lane took %d packets and the newest %d, want 0 and 10", got1, got2)
	}
}

// busyChurn replaces lanes after 200 ms and keeps the tunnel active, with
// the server sending on the first two lanes until the returned stop is
// called.
func busyChurn(t *testing.T, maxOverlap time.Duration) (l1, l2 *fakeLane, stop func()) {
	d := newFakeDialer()
	d.welcome = 1
	p := newTestPool(t, d, PoolConfig{Churn: Churn{
		LifetimeMedian: 200 * time.Millisecond, LifetimeMin: 200 * time.Millisecond, LifetimeMax: 200 * time.Millisecond,
		Lead: 50 * time.Millisecond, Overlap: 40 * time.Millisecond, MaxOverlap: maxOverlap,
	}})
	l1, l2 = d.next(t), d.next(t)
	done := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			close(done)
		}
	})
	busy := make(chan struct{})
	go func() {
		carrying := true
		for {
			select {
			case <-done:
				return
			case <-busy:
				carrying, busy = false, nil
			case <-time.After(5 * time.Millisecond):
				p.Send(make([]byte, 100)) // goes to the newest lane
				if carrying {
					l1.carry(1000)
					l2.carry(1000)
				}
			}
		}
	}()
	go func() { // take the replacements as they are dialed
		for {
			select {
			case <-done:
				return
			case <-d.lanes:
			}
		}
	}()
	return l1, l2, func() { close(busy) }
}

func TestPoolKeepsAnOldLaneWhileItStillCarriesTraffic(t *testing.T) {
	l1, l2, stop := busyChurn(t, time.Minute)
	// Well past the lifetime and several overlaps: the replacements are
	// up, but the old lanes are still carrying the server's traffic, so
	// retiring them would leave the tunnel short.
	time.Sleep(500 * time.Millisecond)
	if l1.wasRetired() || l2.wasRetired() {
		t.Fatal("a lane retired while it was still carrying traffic")
	}
	// The traffic moves off them: they go.
	stop()
	deadline := time.Now().Add(2 * time.Second)
	for !l1.wasRetired() || !l2.wasRetired() {
		if time.Now().After(deadline) {
			t.Fatalf("old lanes not retired once quiet: %v %v", l1.wasRetired(), l2.wasRetired())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPoolRetiresABusyOldLaneAfterMaxOverlap(t *testing.T) {
	l1, l2, _ := busyChurn(t, 150*time.Millisecond)
	deadline := time.Now().Add(3 * time.Second)
	for !l1.wasRetired() || !l2.wasRetired() {
		if time.Now().After(deadline) {
			t.Fatalf("busy old lanes never retired: %v %v", l1.wasRetired(), l2.wasRetired())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPoolChurnWaitsForReplacementWelcome(t *testing.T) {
	d := newFakeDialer()
	d.welcome = 1
	p := newTestPool(t, d, PoolConfig{Churn: Churn{
		LifetimeMedian: 200 * time.Millisecond, LifetimeMin: 200 * time.Millisecond, LifetimeMax: 200 * time.Millisecond,
		Lead: 50 * time.Millisecond, Overlap: 50 * time.Millisecond,
	}})
	go func() {
		for range 100 {
			p.Send(make([]byte, 100))
			time.Sleep(10 * time.Millisecond)
		}
	}()
	l1, l2 := d.next(t), d.next(t)
	d.setWelcome(0) // replacements stay unwelcomed for now
	r := d.next(t)
	time.Sleep(100 * time.Millisecond)
	if l1.wasRetired() || l2.wasRetired() {
		t.Fatal("a lane retired before its replacement logged in")
	}
	r.doWelcome(1)
	deadline := time.Now().Add(2 * time.Second)
	for !l1.wasRetired() && !l2.wasRetired() {
		if time.Now().After(deadline) {
			t.Fatal("old lane not retired after WELCOME")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func idleProfiles(t *testing.T) *shape.Set {
	return testProfiles(t, func(p *shape.Profile) {
		p.IdleAfter = shape.Duration(100 * time.Millisecond)
		p.IdleClose = shape.DurationRange{Min: shape.Duration(150 * time.Millisecond), Max: shape.Duration(150 * time.Millisecond)}
		p.IdleReopen = shape.DurationRange{Min: shape.Duration(200 * time.Millisecond), Max: shape.Duration(200 * time.Millisecond)}
	})
}

func TestPoolIdleShrinksClosesAndReopens(t *testing.T) {
	d := newFakeDialer()
	d.welcome = 3
	p := newTestPool(t, d, PoolConfig{Profiles: idleProfiles(t)})
	l1, l2 := d.next(t), d.next(t)

	// Idle: one lane goes, then the last one.
	waitRetired := func(n int) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			c := 0
			for _, l := range []*fakeLane{l1, l2} {
				if l.wasRetired() {
					c++
				}
			}
			if c >= n {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d lanes retired, want %d", c, n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitRetired(1)
	waitRetired(2)
	closedAt := time.Now()
	d.none(t, 50*time.Millisecond)

	// A keepalive with no lane open is held, then carried by a fresh lane
	// once the reopen pause since the last lane closed has passed.
	p.Send(keepalive())
	r := d.next(t)
	if r.req.Reason != "reopen" || !r.req.Join {
		t.Fatalf("reopen request = %+v", r.req)
	}
	if el := time.Since(closedAt); el < 180*time.Millisecond {
		t.Fatalf("keepalive reopened a lane %v after the last one closed, want the 200ms pause", el)
	}
	deadline := time.Now().Add(time.Second)
	for r.sentCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("held keepalive never sent")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPoolRealTrafficReopensAtOnce(t *testing.T) {
	d := newFakeDialer()
	d.welcome = 3
	p := newTestPool(t, d, PoolConfig{Profiles: idleProfiles(t)})
	l1, l2 := d.next(t), d.next(t)
	deadline := time.Now().Add(3 * time.Second)
	for !(l1.wasRetired() && l2.wasRetired()) {
		if time.Now().After(deadline) {
			t.Fatal("pool never went dormant")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	p.Send(wgInit())
	r := d.next(t)
	if el := time.Since(start); el > 100*time.Millisecond {
		t.Fatalf("real traffic waited %v for a lane", el)
	}
	if !r.req.Join || !bytes.Equal(r.first, wgInit()) {
		t.Fatalf("reconnect request = %+v first=%d bytes", r.req, len(r.first))
	}
}

func TestPoolReconnectsAfterNetworkChange(t *testing.T) {
	d := newFakeDialer()
	d.welcome = 9
	p := newTestPool(t, d, PoolConfig{})
	l1, l2 := d.next(t), d.next(t)
	// Every lane dies at once, as when a phone switches networks.
	l1.end(errors.New("reset"))
	l2.end(errors.New("reset"))
	p.Send(wgInit())
	r := d.next(t)
	if !r.req.Join || r.req.SessionID[0] != 9 {
		t.Fatalf("rejoin request = %+v", r.req)
	}
}

func TestPoolBacksOffOnFailures(t *testing.T) {
	d := newFakeDialer()
	d.fail = 3
	d.welcome = 1
	start := time.Now()
	p := newTestPool(t, d, PoolConfig{})
	p.Send(wgInit())
	l := d.next(t)
	// Three failures: 0.5 + 1 + 2 s of backoff, plus jitter.
	if el := time.Since(start); el < 3*time.Second {
		t.Fatalf("succeeded after %v; backoff too short", el)
	}
	if !bytes.Equal(l.first, wgInit()) {
		t.Fatal("first packet lost across failed dials")
	}
}

func TestPoolAdoptsReplacementSession(t *testing.T) {
	d := newFakeDialer()
	d.welcome = 1
	p := newTestPool(t, d, PoolConfig{})
	l1, l2 := d.next(t), d.next(t)
	// The server lost session 1; the next lane comes back in session 2.
	d.setWelcome(2)
	l2.end(errors.New("reset"))
	p.Send(make([]byte, 100))
	l3 := d.next(t)
	if !l3.req.Join || l3.req.SessionID[0] != 1 {
		t.Fatalf("request = %+v", l3.req)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !l1.wasRetired() {
		if time.Now().After(deadline) {
			t.Fatal("lane in the dead session was not retired")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if st := p.Stats(); st.Session[0] != 2 {
		t.Fatalf("pool session = %x", st.Session)
	}
}

func TestPoolCredentialCloseIsFatal(t *testing.T) {
	d := newFakeDialer()
	d.welcome = 1
	p := newTestPool(t, d, PoolConfig{})
	l := d.next(t)
	l.req.Handler.Close(nil, wire.CloseCredential)
	select {
	case <-p.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("pool kept running after the credential was rejected")
	}
	if !errors.Is(p.Err(), ErrCredentialRejected) {
		t.Fatalf("err = %v", p.Err())
	}
	if err := p.WaitSession(context.Background()); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("WaitSession = %v, want the credential error", err)
	}
}

func TestPoolCloseSendsClose(t *testing.T) {
	d := newFakeDialer()
	d.welcome = 1
	p := newTestPool(t, d, PoolConfig{})
	l1, l2 := d.next(t), d.next(t)
	time.Sleep(20 * time.Millisecond)
	p.Close()
	n := 0
	for _, l := range []*fakeLane{l1, l2} {
		l.mu.Lock()
		if l.closeReason != nil && *l.closeReason == wire.CloseNormal {
			n++
		}
		l.mu.Unlock()
		if !l.isDone() {
			t.Fatal("lane left open after Close")
		}
	}
	if n != 1 {
		t.Fatalf("CLOSE sent on %d lanes, want 1", n)
	}
}

func TestPoolWaitSessionTimesOut(t *testing.T) {
	d := newFakeDialer() // lanes are never welcomed
	p := newTestPool(t, d, PoolConfig{})
	d.next(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := p.WaitSession(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}
