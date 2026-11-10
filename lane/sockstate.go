package lane

import (
	"time"

	"github.com/pangeavpn/tectonic/shape"
)

// With TCP_NOTSENT_LOWAT a lane's queue is meant to stay in the lane, but
// not all of it does. The kernel takes up to notSentLowat bytes it cannot
// send yet, and how fast it sends is the connection's business: a
// connection that has just opened, or carried little lately, may send ten
// segments and then nothing until they are acknowledged, a round trip
// later. A scheduler that only counts the lane's own queue, over a rate the
// lane reached at some earlier time, takes such a lane for an empty one and
// gives it packets that then wait a round trip in the kernel, while another
// lane had room. The receiver delivers in order, so the whole tunnel waits
// with them, and a TCP connection inside the tunnel that sees its round
// trip jump like that stops growing (HyStart).
//
// So the estimate is made from what the kernel says about the connection
// now (sockState), read again whenever the lane writes and at most every
// sockMaxAge while anything is in flight.

const (
	// sockMaxAge is how old the kernel's figures may be while the
	// connection has anything outstanding. A window opens and closes
	// within a round trip, and the scheduler picks a lane for every packet.
	sockMaxAge = time.Millisecond
	// A connection that has sat idle is taken to have at least this many
	// bytes of window left, as a new one has.
	idleWindow = initialWindow
	// A record holds no more than its connection sends in a thirty-second
	// of the round trip, within recordSpanMin and recordSpanMax. Nothing in
	// a TLS record can be used until all of it has arrived, so the first
	// packet in a record is late by as long as the record takes to send.
	// At 100 Mbit/s 16 KB take about a millisecond. A connection that has
	// just opened sends a few hundred kilobytes a second: 16 KB take it
	// tens of milliseconds, which is more than a TCP connection inside the
	// tunnel allows a round trip to grow by before it stops its slow start.
	recordSpanMin = time.Millisecond
	recordSpanMax = 4 * time.Millisecond
	// pacedAfter is how many times a connection must be seen holding back
	// bytes its window had room for before it is taken to pace its packets.
	pacedAfter = 3
)

// sockState is what the kernel last said about a lane's connection.
type sockState struct {
	at time.Time
	// cwnd is the congestion window and inflight what is using it, both in
	// bytes; notsent is what has been written to the socket and not sent.
	cwnd, inflight, notsent float64
	// pacing is the rate the connection spaces its packets out at, in
	// bytes per second; zero if it doesn't, or isn't known to.
	pacing float64
	rtt    time.Duration
	// rto is the retransmission timeout: Linux halves the window of a
	// connection for each rto it sits idle.
	rto time.Duration
}

// wait estimates how long it takes the connection to send the last of q
// more bytes given to it now, when its last send was idle ago.
//
// Two things hold bytes back. The window: what is beyond it leaves as
// acknowledgements come in, a window's worth each round trip. And pacing:
// a connection that spaces its packets out (see paces) sends at its pacing
// rate however much window it has.
func (s *sockState) wait(q float64, idle time.Duration) time.Duration {
	if s.cwnd <= 0 || s.rtt <= 0 {
		return 0
	}
	cwnd := s.cwnd
	if s.inflight == 0 && s.rto > 0 && cwnd > idleWindow {
		for d := idle; d > s.rto && cwnd > idleWindow; d -= s.rto {
			cwnd /= 2
		}
		cwnd = max(cwnd, idleWindow)
	}
	ahead := q + s.notsent
	var secs float64
	if room := max(cwnd-s.inflight, 0); ahead > room {
		secs = (ahead - room) / (cwnd / s.rtt.Seconds())
	}
	if s.pacing > 0 {
		secs = max(secs, ahead/s.pacing)
	}
	return time.Duration(secs * float64(time.Second))
}

// sendRate is the rate the connection is sending at, in bytes per second:
// its pacing rate, or without one a window each round trip.
func (s *sockState) sendRate() float64 {
	if s.pacing > 0 {
		return s.pacing
	}
	if s.rtt <= 0 {
		return 0
	}
	return s.cwnd / s.rtt.Seconds()
}

// recordLimit is the most bytes of frames a record on this connection
// should hold: what it sends in a thirty-second of the round trip (see
// recordSpanMin), and no more than a full record. Without pacing, whatever
// the window has room for leaves at once and can share a record. A record
// always takes one packet, however slow the connection.
func (s *sockState) recordLimit() int {
	rate := s.sendRate()
	if rate <= 0 {
		return shape.MaxRecord
	}
	span := min(max(s.rtt/32, recordSpanMin), recordSpanMax)
	limit := rate * span.Seconds()
	if s.pacing <= 0 {
		limit = max(limit, s.cwnd-s.inflight-s.notsent)
	}
	return int(min(limit, shape.MaxRecord))
}

// kernel returns what the kernel says about the lane's connection, reading
// it again if it is stale and may have changed. It returns nil where the
// platform doesn't say.
func (l *Lane) kernel(now time.Time) *sockState {
	s := l.sock.Load()
	if s == nil {
		return nil
	}
	if now.Sub(s.at) > sockMaxAge && (s.inflight > 0 || s.notsent > 0) {
		if at := s.at.UnixNano(); l.sockPoll.CompareAndSwap(at, now.UnixNano()) {
			// One caller reads; the others go on with what there is.
			if ns := l.readSock(now); ns != nil {
				return ns
			}
		}
	}
	return s
}

// readSock reads the connection's state from the kernel and records it.
func (l *Lane) readSock(now time.Time) *sockState {
	if l.rc == nil || !l.hasTCPInfo.Load() {
		return nil
	}
	ti, ok := readTCPInfo(l.rc)
	if !ok {
		return nil
	}
	return l.noteTCPInfo(ti, now)
}

// noteTCPInfo records what is true of the connection at this moment: its
// round trip, its window, and whether it is retransmitting.
func (l *Lane) noteTCPInfo(ti tcpInfo, now time.Time) *sockState {
	if ti.rtt > 0 {
		l.rttSampled.Store(true)
		l.srtt.Store(int64(ti.rtt))
		if ti.minRTT > 0 {
			l.minRTT.Store(int64(ti.minRTT))
		} else if m := l.minRTT.Load(); m == 0 || int64(ti.rtt) < m {
			l.minRTT.Store(int64(ti.rtt))
		}
	}
	l.pingMu.Lock()
	if !l.retransInit {
		l.retransInit = true
	} else if ti.retrans > l.lastRetransN {
		l.lastRetrans.Store(now.UnixNano())
	}
	l.lastRetransN = max(l.lastRetransN, ti.retrans)
	l.pingMu.Unlock()
	l.stalled.Store(ti.stalled)
	if ti.cwnd <= 0 {
		return nil
	}
	s := &sockState{
		at: now, cwnd: ti.cwnd, inflight: ti.inflight, notsent: ti.notsent,
		rtt: ti.rtt, rto: ti.rto,
	}
	if l.paces(ti) {
		s.pacing = ti.pacing
	}
	l.sock.Store(s)
	l.sockPoll.Store(now.UnixNano())
	return s
}

// paces reports whether the connection spaces its packets out. The kernel
// reports a pacing rate for every connection and enforces it for some: BBR
// asks for it, and so does a host whose queueing discipline is fq. A
// connection that is not paced sends whatever its window has room for at
// once, and treating it as paced would cut its records small for nothing.
//
// BBR is known by name when the lane is made. Otherwise a connection shows
// that it paces by holding back a segment or more that its window had room
// for; a few sightings settle it for the life of the lane.
func (l *Lane) paces(ti tcpInfo) bool {
	if l.paced.Load() >= pacedAfter {
		return true
	}
	if ti.mss > 0 && ti.notsent >= ti.mss && ti.cwnd-ti.inflight >= ti.notsent+ti.mss {
		return l.paced.Add(1) >= pacedAfter
	}
	return false
}
