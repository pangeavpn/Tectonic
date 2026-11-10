package server

import (
	"bufio"
	"crypto/rand"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/pangeavpn/tectonic/lane"
	"github.com/pangeavpn/tectonic/sched"
	"github.com/pangeavpn/tectonic/shape"
	"github.com/pangeavpn/tectonic/wire"
)

const (
	// laneSlack lets a session briefly run more lanes than max_lanes while
	// the client swaps an old lane for its replacement.
	laneSlack       = 2
	pendingMax      = 128
	pendingBytesMax = 256 << 10
)

// session belongs to a device, not to a connection: lanes join and leave,
// and the session lives on for the resume window after the last one goes
// (design §4, step 7).
type session struct {
	s        *Server
	id       wire.SessionID
	keyID    wire.KeyID
	cellular bool
	udp      *net.UDPConn
	sched    sched.Scheduler
	done     chan struct{}

	mu        sync.Mutex
	lanes     []*laneInfo
	pending   [][]byte // downlink held while no lane is up
	pendingSz int
	expire    *time.Timer
	closed    bool
}

type laneInfo struct {
	l        *lane.Lane
	lastRecv uint64
	quietAt  time.Time
}

// startLane logs a connection into its session and starts it as a lane.
func (s *Server) startLane(conn, raw net.Conn, br *bufio.Reader, h wire.Hello) bool {
	ss, err := s.attach(h)
	if err != nil {
		s.log.Warn("cannot open session", "err", err)
		return false
	}
	maxLanes := s.cfg.MaxLanes
	if h.Cellular() {
		maxLanes = s.cfg.MaxLanesCellular
	}
	w := wire.Welcome{
		SessionID:    ss.id,
		MaxLanes:     uint8(maxLanes),
		ResumeWindow: s.cfg.ResumeWindow,
		Profile:      s.profile.ID,
	}
	l := lane.New(conn, br, lane.Options{
		Role:    lane.Server,
		Planner: shape.NewPlanner(s.profile),
		Raw:     raw,
		Logger:  s.log,
		Handler: lane.Handler{
			Data: func(_ *lane.Lane, pkt []byte) { ss.udp.Write(pkt) },
			Retire: func(*lane.Lane) {
				ss.refresh()
			},
			Close: func(*lane.Lane, wire.CloseReason) {
				// The client ended the session: drop it now rather than
				// wait out the resume window.
				go ss.abort()
			},
		},
	})
	if !ss.add(l, maxLanes) {
		l.Close()
		return false
	}
	s.lanes.Add(1)
	go func() {
		<-l.Done()
		s.lanes.Add(-1)
		ss.remove(l)
	}()
	if err := l.Start(wire.AppendFrame(nil, wire.TypeWelcome, w.AppendBody(nil))); err != nil {
		return true // the lane has ended; its watcher removes it
	}
	ss.refresh()
	ss.flush()
	return true
}

// attach finds the session a HELLO joins or creates a new one. Joining
// needs the session_id and the same key_id that created it, so a leaked
// session_id is useless on its own. A join that can't be honoured (the
// session expired, say) gets a new session, and the client adopts it.
func (s *Server) attach(h wire.Hello) (*session, error) {
	s.mu.Lock()
	if h.Join() && !h.SessionID.IsZero() {
		if ss := s.sessions[h.SessionID]; ss != nil && ss.keyID == h.KeyID && ss.alive() {
			s.mu.Unlock()
			return ss, nil
		}
	}
	s.mu.Unlock()

	udp, err := net.DialUDP("udp", nil, s.wgAddr)
	if err != nil {
		return nil, err
	}
	ss := &session{s: s, keyID: h.KeyID, cellular: h.Cellular(), udp: udp, done: make(chan struct{})}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		udp.Close()
		return nil, ErrServerClosed
	}
	for {
		rand.Read(ss.id[:])
		if _, taken := s.sessions[ss.id]; !taken && !ss.id.IsZero() {
			break
		}
	}
	s.sessions[ss.id] = ss
	go ss.readWireGuard()
	s.log.Debug("session opened", "key_id", h.KeyID.String())
	return ss, nil
}

func (ss *session) alive() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return !ss.closed
}

// add registers a lane. Past the lane limit plus slack for churn, the
// oldest lane is retired to make room.
func (ss *session) add(l *lane.Lane, maxLanes int) bool {
	ss.mu.Lock()
	if ss.closed {
		ss.mu.Unlock()
		return false
	}
	if ss.expire != nil {
		ss.expire.Stop()
		ss.expire = nil
	}
	ss.lanes = append(ss.lanes, &laneInfo{l: l, quietAt: time.Now()})
	var victim *lane.Lane
	if n := ss.liveLocked(); n > maxLanes+laneSlack {
		for _, li := range ss.lanes {
			if !li.l.Retiring() {
				victim = li.l
				break
			}
		}
	}
	ss.mu.Unlock()
	if victim != nil {
		victim.Retire()
	}
	return true
}

func (ss *session) liveLocked() int {
	n := 0
	for _, li := range ss.lanes {
		if !li.l.Retiring() {
			n++
		}
	}
	return n
}

// remove forgets a lane that has ended. When the last one goes, the
// session waits out the resume window for the client to come back.
func (ss *session) remove(l *lane.Lane) {
	ss.mu.Lock()
	for i, li := range ss.lanes {
		if li.l == l {
			// Copy rather than delete in place: close and abort iterate
			// over snapshots of this slice without the lock.
			ss.lanes = slices.Concat(ss.lanes[:i], ss.lanes[i+1:])
			break
		}
	}
	if len(ss.lanes) == 0 && !ss.closed && ss.expire == nil {
		ss.expire = time.AfterFunc(ss.s.cfg.ResumeWindow, ss.expireNow)
	}
	ss.mu.Unlock()
	ss.refresh()
}

func (ss *session) expireNow() {
	ss.mu.Lock()
	idle := len(ss.lanes) == 0
	ss.mu.Unlock()
	if idle {
		ss.s.log.Debug("session expired", "key_id", ss.keyID.String())
		ss.abort()
	}
}

// refresh gives the scheduler every lane that takes DATA.
func (ss *session) refresh() {
	ss.mu.Lock()
	ls := make([]sched.Lane, 0, len(ss.lanes))
	for _, li := range ss.lanes {
		if !li.l.Retiring() {
			ls = append(ls, li.l)
		}
	}
	ss.mu.Unlock()
	ss.sched.SetLanes(ls)
}

// readWireGuard forwards WireGuard's datagrams to the client across the
// session's lanes, holding a few while no lane is up.
func (ss *session) readWireGuard() {
	buf := make([]byte, 65535)
	for {
		n, err := ss.udp.Read(buf)
		if err != nil {
			if ss.alive() {
				// A refused datagram (WireGuard restarting) is not fatal.
				if ne, ok := err.(net.Error); ok && !ne.Timeout() {
					select {
					case <-ss.done:
						return
					case <-time.After(10 * time.Millisecond):
					}
					continue
				}
			}
			return
		}
		pkt := buf[:n]
		if ss.sched.Send(pkt) || ss.sched.Len() > 0 {
			continue
		}
		ss.mu.Lock()
		if !ss.closed {
			ss.pending = append(ss.pending, append([]byte(nil), pkt...))
			ss.pendingSz += n
			for len(ss.pending) > pendingMax || ss.pendingSz > pendingBytesMax {
				ss.pendingSz -= len(ss.pending[0])
				ss.pending = ss.pending[1:]
			}
		}
		ss.mu.Unlock()
	}
}

// flush sends downlink that waited for a lane.
func (ss *session) flush() {
	ss.mu.Lock()
	pending := ss.pending
	ss.pending, ss.pendingSz = nil, 0
	ss.mu.Unlock()
	for _, pkt := range pending {
		ss.sched.Send(pkt)
	}
}

// close ends the session, telling the client why with CLOSE on one lane.
func (ss *session) close(reason wire.CloseReason) {
	ss.mu.Lock()
	lanes := ss.lanes
	ss.mu.Unlock()
	sent := false
	for _, li := range lanes {
		if !sent && !li.l.Retiring() {
			li.l.SendClose(reason)
			sent = true
			continue
		}
		li.l.Close()
	}
	if sent {
		// Let CLOSE go out before the session's lanes are torn down.
		for _, li := range lanes {
			select {
			case <-li.l.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}
	ss.abort()
}

// abort tears the session down at once.
func (ss *session) abort() {
	ss.mu.Lock()
	if ss.closed {
		ss.mu.Unlock()
		return
	}
	ss.closed = true
	if ss.expire != nil {
		ss.expire.Stop()
	}
	lanes := ss.lanes
	ss.pending = nil
	ss.mu.Unlock()
	for _, li := range lanes {
		li.l.Close()
	}
	ss.sched.SetLanes(nil)
	ss.udp.Close()
	ss.s.mu.Lock()
	if ss.s.sessions[ss.id] == ss {
		delete(ss.s.sessions, ss.id)
	}
	ss.s.mu.Unlock()
	close(ss.done)
}

// reapIdle closes lanes that have received nothing for timeout: the client
// is gone, or a middlebox silently dropped the connection.
func (ss *session) reapIdle(timeout time.Duration) {
	now := time.Now()
	var dead []*lane.Lane
	ss.mu.Lock()
	for _, li := range ss.lanes {
		if r := li.l.Stats().BytesRecv; r != li.lastRecv {
			li.lastRecv, li.quietAt = r, now
		} else if now.Sub(li.quietAt) >= timeout {
			dead = append(dead, li.l)
		}
	}
	ss.mu.Unlock()
	for _, l := range dead {
		l.Close()
	}
}
