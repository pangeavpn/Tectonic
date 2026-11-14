package server

import (
	"sync"
	"time"

	"github.com/pangeavpn/tectonic/wire"
)

// A direct lane's login is bound to its TLS session through an exporter, so
// a copy of it opens nothing on any other connection. A CDN lane's cannot
// be: the client's TLS ends at the CDN, and both ends only share the
// WebSocket handshake, so the login is bound to the client's
// Sec-WebSocket-Key (design §10). That key travels in the clear between the
// CDN and the node, and the client chooses it, so whoever holds a recorded
// upgrade and its first message, the CDN itself or anyone on that leg, can
// send them again. Both timestamps in them stay valid for their window.
//
// So the node remembers the keys whose logins it has accepted, and accepts
// each one once.

const (
	// replayFor is how long an accepted key is remembered: long enough that
	// neither timestamp in a recorded login is still in its window. A
	// login's HELLO timestamp may be a window ahead of the node's clock
	// when it arrives, and stays valid a window past that.
	replayFor = 2 * wire.TimestampWindow
	// maxReplaySeen bounds what the set costs. A node accepting a hundred
	// CDN lanes a second holds about 24,000 keys; past this it refuses CDN
	// logins rather than forget a key it has seen, since forgetting one
	// would let that login be used again. Direct lanes are unaffected.
	maxReplaySeen = 1 << 17
)

// replayGuard accepts each Sec-WebSocket-Key once within replayFor. Keys
// are kept in two sets and the older is dropped whole, so nothing is pruned
// one key at a time and a key is remembered for between one and two
// windows.
type replayGuard struct {
	mu       sync.Mutex
	cur      map[string]struct{}
	prev     map[string]struct{}
	rotated  time.Time
	full     bool
	fullSaid time.Time
}

// fresh reports whether key has not been seen, and remembers it. It reports
// false for a key seen already, and for any key once the set is full.
func (g *replayGuard) fresh(key string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cur == nil {
		g.cur, g.rotated = map[string]struct{}{}, now
	}
	if now.Sub(g.rotated) >= replayFor || now.Before(g.rotated) {
		g.prev, g.cur, g.rotated = g.cur, map[string]struct{}{}, now
		g.full = false
	}
	if _, seen := g.cur[key]; seen {
		return false
	}
	if _, seen := g.prev[key]; seen {
		return false
	}
	if len(g.cur)+len(g.prev) >= maxReplaySeen {
		g.full = true
		return false
	}
	g.cur[key] = struct{}{}
	return true
}

// sayFull reports whether the caller should log that the set is full, at
// most once a minute.
func (g *replayGuard) sayFull(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.full || now.Sub(g.fullSaid) < time.Minute {
		return false
	}
	g.fullSaid = now
	return true
}
