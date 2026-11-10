package server

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pangeavpn/tectonic/wire"
)

// Revocation is the short list of key_ids the hub has revoked before their
// expiry (design §5). It is safe for concurrent use and can be replaced
// while the server runs.
type Revocation struct {
	mu  sync.RWMutex
	ids map[wire.KeyID]struct{}
}

// NewRevocation returns a list holding ids.
func NewRevocation(ids ...wire.KeyID) *Revocation {
	r := &Revocation{}
	r.Set(ids)
	return r
}

// Set replaces the list. Call Server.EnforceRevocation afterwards to end
// sessions that are now revoked.
func (r *Revocation) Set(ids []wire.KeyID) {
	m := make(map[wire.KeyID]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	r.mu.Lock()
	r.ids = m
	r.mu.Unlock()
}

// Revoked reports whether id is on the list.
func (r *Revocation) Revoked(id wire.KeyID) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	_, ok := r.ids[id]
	r.mu.RUnlock()
	return ok
}

// Len returns how many key_ids are revoked.
func (r *Revocation) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.ids)
}

// ParseRevocationList reads key_ids in hex, one per line. Blank lines and
// lines starting with '#' are ignored.
func ParseRevocationList(rd io.Reader) ([]wire.KeyID, error) {
	var ids []wire.KeyID
	sc := bufio.NewScanner(rd)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, err := wire.ParseKeyID(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		ids = append(ids, id)
	}
	return ids, sc.Err()
}

// The CDN carrier's node "also checks a header signed by the CDN" (design
// §10). EdgeHeader is that check: the CDN (an edge function or worker
// holding a secret shared with the node) adds
//
//	<name>: <unix seconds>.<base64url(HMAC-SHA256(secret, "<unix seconds>." + Sec-WebSocket-Key))>
//
// to every WebSocket upgrade it forwards. Binding the signature to the
// client's key ties it to this one connection.

// EdgeWindow is how far an edge signature's timestamp may be from the
// node's clock.
const EdgeWindow = wire.TimestampWindow

// SignEdgeHeader returns the header value a CDN adds for a request carrying
// the given Sec-WebSocket-Key.
func SignEdgeHeader(secret []byte, wsKey string, now time.Time) string {
	ts := strconv.FormatInt(now.Unix(), 10)
	return ts + "." + edgeMAC(secret, ts, wsKey)
}

func edgeMAC(secret []byte, ts, wsKey string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts + "." + wsKey))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// EdgeHeader returns a CDNConfig.Verify function that checks the signed
// header called name. now may be nil.
func EdgeHeader(name string, secret []byte, now func() time.Time) func(*http.Request) bool {
	if now == nil {
		now = time.Now
	}
	return func(r *http.Request) bool {
		ts, mac, ok := strings.Cut(r.Header.Get(name), ".")
		if !ok {
			return false
		}
		sec, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			return false
		}
		if d := now().Sub(time.Unix(sec, 0)); d > EdgeWindow || d < -EdgeWindow {
			return false
		}
		want := edgeMAC(secret, ts, r.Header.Get("Sec-WebSocket-Key"))
		return hmac.Equal([]byte(mac), []byte(want))
	}
}
