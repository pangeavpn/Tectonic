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
	// maxReplayPerKey is what one credential may hold of the set. A client
	// opens a CDN lane every minute or two, so this is thousands of times
	// what one has ever needed. Without it the first credential to ask for
	// a share of the set can fill it, and the node then refuses every
	// other client's CDN logins: the carrier a client whose node is
	// null-routed is left with.
	maxReplayPerKey = maxReplaySeen / 32
)

// verdict is what the guard makes of a login's key.
type verdict int

const (
	keyFresh  verdict = iota
	keyUsed           // this key opened a lane already
	keyIDFull         // this key_id holds its share of the set
	guardFull         // the set holds as much as it may
)

// replayGuard accepts each Sec-WebSocket-Key once within replayFor. Keys
// are kept in two sets and the older is dropped whole, so nothing is pruned
// one key at a time and a key is remembered for between one and two
// windows.
type replayGuard struct {
	mu      sync.Mutex
	cur     map[string]struct{}
	prev    map[string]struct{}
	byKey   map[wire.KeyID]int // how much of cur each key_id holds
	rotated time.Time
	said    time.Time
}

// check says what the guard makes of key, logging in under id, and
// remembers it if it is fresh.
func (g *replayGuard) check(key string, id wire.KeyID, now time.Time) verdict {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cur == nil {
		g.cur, g.byKey, g.rotated = map[string]struct{}{}, map[wire.KeyID]int{}, now
	}
	if now.Sub(g.rotated) >= replayFor || now.Before(g.rotated) {
		g.prev, g.cur, g.rotated = g.cur, map[string]struct{}{}, now
		g.byKey = map[wire.KeyID]int{}
	}
	if _, seen := g.cur[key]; seen {
		return keyUsed
	}
	if _, seen := g.prev[key]; seen {
		return keyUsed
	}
	if g.byKey[id] >= maxReplayPerKey {
		return keyIDFull
	}
	if len(g.cur)+len(g.prev) >= maxReplaySeen {
		return guardFull
	}
	g.cur[key] = struct{}{}
	g.byKey[id]++
	return keyFresh
}

// saySo reports whether the caller should log that it is refusing logins
// for want of room, at most once a minute.
func (g *replayGuard) saySo(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Sub(g.said) < time.Minute {
		return false
	}
	g.said = now
	return true
}
