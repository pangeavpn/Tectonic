// Package server is Tectonic's node side (design §4, §5, §9, §10): a cover
// website that every connection starts as and that presents the right
// certificate for whatever name the client sends, a constant-time HELLO
// check that makes a connection a lane, a table of sessions that outlive
// their lanes, and UDP forwarding to the node's WireGuard.
package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pangeavpn/tectonic/shape"
	"github.com/pangeavpn/tectonic/wire"
)

// Defaults from the design.
const (
	DefaultMaxLanes         = 6
	DefaultMaxLanesCellular = 3
	DefaultResumeWindow     = 60 * time.Second
	DefaultHandshakeTimeout = 10 * time.Second
	DefaultLaneIdleTimeout  = 5 * time.Minute
)

// Config configures a Server.
type Config struct {
	// NodeSecret is the node's (or region's) secret. Device keys are
	// derived from it, so the node needs no device database.
	NodeSecret []byte

	// CoverDomain is the node's own domain, such as "n12.example-cdn.net",
	// or a wildcard such as "*.example-cdn.net". A ClientHello naming it
	// gets OwnCertificate.
	CoverDomain string
	// OwnCertificate returns the real certificate for CoverDomain. It is
	// called on every handshake, so it can serve a reloaded certificate.
	// Nil means the node has no real certificate and always presents the
	// default one.
	OwnCertificate func() (*tls.Certificate, error)
	// DefaultCertificate returns the certificate for any other name, or
	// none, as most web servers do. Clients in Borrowed and None mode pin
	// it. Required.
	DefaultCertificate func() (*tls.Certificate, error)

	// Cover is the cover website. Every connection that doesn't log in is
	// served by it, as it would serve any visitor. Required.
	Cover http.Handler

	// WireGuard is the node's WireGuard UDP address, usually
	// "127.0.0.1:51820". Each session forwards from its own UDP socket, so
	// WireGuard sees one stable endpoint per session however its lanes
	// come and go.
	WireGuard string

	// MaxLanes is the most lanes a client should run, sent in WELCOME:
	// 6 by default, and MaxLanesCellular (3) for clients on cellular.
	MaxLanes         int
	MaxLanesCellular int
	// ResumeWindow is how long a session outlives its last lane (60 s).
	ResumeWindow time.Duration
	// Shaping is the profile announced in WELCOME. Nil means the default.
	Shaping *shape.Profile

	// Revoked lists key_ids to refuse before they expire.
	Revoked *Revocation

	// CDN enables the CDN carrier. Nil disables it.
	CDN *CDNConfig

	// HandshakeTimeout is the cover web server's ReadHeaderTimeout: it
	// bounds the TLS handshake, and then the wait for the headers of an
	// HTTP/1.1 request (10 s). On HTTP/2, net/http waits a fixed 10 s for
	// the client's preface whatever this is, so a node that changes it
	// looks like a Go web server whose owner changed it.
	HandshakeTimeout time.Duration
	// LaneIdleTimeout closes a lane that has received nothing this long
	// (5 min). Clients close idle lanes far sooner; this only reaps dead
	// ones.
	LaneIdleTimeout time.Duration

	Logger *slog.Logger
	// Now is the clock for HELLO timestamps and key_id expiry.
	Now func() time.Time
}

// CDNConfig configures the CDN carrier (design §10): lanes arrive as
// WebSocket upgrades on Path, forwarded by a CDN that vouches for each
// request with a header Verify checks.
type CDNConfig struct {
	Path string
	// Verify reports whether a request really came through the CDN. See
	// EdgeHeader for the usual check.
	Verify func(r *http.Request) bool
}

// Server is a Tectonic node.
type Server struct {
	cfg     Config
	log     *slog.Logger
	now     func() time.Time
	tls     *tls.Config
	profile *shape.Profile
	wgAddr  *net.UDPAddr

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	sessions  map[wire.SessionID]*session
	listeners map[net.Listener]struct{}
	conns     map[net.Conn]struct{} // connections not yet logged in or handed off
	closed    bool

	cover *cover
	lanes atomic.Int64
	// bufWarn limits the warning about a small socket buffer to one.
	bufWarn sync.Once
}

// New checks cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	return newServer(cfg, httpServesTLSConns)
}

// newServer is New with the choice of how the cover web server is given its
// connections (see cover.direct). The Go version makes that choice for New.
func newServer(cfg Config, direct bool) (*Server, error) {
	if len(cfg.NodeSecret) < 16 {
		return nil, errors.New("server: node secret must be at least 16 bytes")
	}
	if cfg.DefaultCertificate == nil {
		return nil, errors.New("server: a default certificate is required")
	}
	if cfg.Cover == nil {
		return nil, errors.New("server: a cover website is required")
	}
	if cfg.CDN != nil && (cfg.CDN.Path == "" || cfg.CDN.Verify == nil) {
		return nil, errors.New("server: the CDN carrier needs a path and a Verify function")
	}
	wg, err := net.ResolveUDPAddr("udp", cfg.WireGuard)
	if err != nil {
		return nil, fmt.Errorf("server: WireGuard address: %w", err)
	}
	if cfg.MaxLanes <= 0 {
		cfg.MaxLanes = DefaultMaxLanes
	}
	if cfg.MaxLanesCellular <= 0 {
		cfg.MaxLanesCellular = DefaultMaxLanesCellular
	}
	cfg.MaxLanes = min(cfg.MaxLanes, 255)
	cfg.MaxLanesCellular = min(cfg.MaxLanesCellular, cfg.MaxLanes)
	if cfg.ResumeWindow <= 0 {
		cfg.ResumeWindow = DefaultResumeWindow
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if cfg.LaneIdleTimeout <= 0 {
		cfg.LaneIdleTimeout = DefaultLaneIdleTimeout
	}
	if cfg.Shaping == nil {
		cfg.Shaping = shape.Default()
	}
	if err := cfg.Shaping.Validate(); err != nil {
		return nil, err
	}
	if cfg.Revoked == nil {
		cfg.Revoked = NewRevocation()
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		cfg:       cfg,
		log:       log,
		now:       now,
		profile:   cfg.Shaping,
		wgAddr:    wg,
		ctx:       ctx,
		cancel:    cancel,
		sessions:  map[wire.SessionID]*session{},
		listeners: map[net.Listener]struct{}{},
		conns:     map[net.Conn]struct{}{},
	}
	// One tls.Config for every connection: its session ticket keys are
	// what let a client's later lanes resume TLS.
	s.tls = &tls.Config{
		MinVersion:                  tls.VersionTLS12, // the cover site serves older browsers too
		NextProtos:                  []string{"h2", "http/1.1"},
		GetCertificate:              s.certificate,
		DynamicRecordSizingDisabled: true, // the shaper sizes records
	}
	s.cover, err = newCover(s, direct)
	if err != nil {
		cancel()
		return nil, err
	}
	if !direct {
		log.Warn("built with Go before 1.27: the cover website's HTTP/2 is close to a Go web server's but not the same; build the node with Go 1.27 or newer")
	}
	go s.janitor()
	return s, nil
}

// certificate presents the real certificate when the client names the
// node's own domain, and the default certificate for any other name or none
// (design §9).
func (s *Server) certificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s.cfg.OwnCertificate != nil && matchDomain(hi.ServerName, s.cfg.CoverDomain) {
		if c, err := s.cfg.OwnCertificate(); err == nil && c != nil {
			return c, nil
		}
	}
	return s.cfg.DefaultCertificate()
}

// matchDomain reports whether name is pattern, or matches a "*." wildcard
// pattern by exactly one label.
func matchDomain(name, pattern string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
	if name == "" || pattern == "" {
		return false
	}
	if rest, ok := strings.CutPrefix(pattern, "*."); ok {
		label, parent, ok := strings.Cut(name, ".")
		return ok && label != "" && parent == rest
	}
	return name == pattern
}

// ErrServerClosed is returned by Serve after Shutdown or Close.
var ErrServerClosed = errors.New("server: closed")

// ListenAndServe listens on addr ("[host]:443") and serves.
func (s *Server) ListenAndServe(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve accepts connections on l, a plain TCP listener; the server does TLS
// itself. It returns ErrServerClosed after Shutdown or Close.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		l.Close()
		return ErrServerClosed
	}
	s.listeners[l] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.listeners, l)
		s.mu.Unlock()
	}()
	var delay time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if s.isClosed() {
				return ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		go s.handle(c)
	}
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) track(c net.Conn, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		if s.closed {
			return false
		}
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
	return true
}

// handle gives a connection to the cover web server, which is what every
// connection starts as (see cover). A login is found in the web server's
// first read, in conn.Read.
func (s *Server) handle(raw net.Conn) {
	if !s.track(raw, true) {
		raw.Close()
		return
	}
	ok := s.cover.serve(raw)
	s.track(raw, false)
	if !ok {
		raw.Close()
	}
}

// checkHello verifies a HELLO in constant time: every check runs whatever
// the outcome of the others, so success and failure take the same time and
// a probe learns nothing from how fast the server answers.
//
// body is a HELLO body, or the start of one that stops inside the tag. The
// tag is then checked as far as it goes, which says whether the rest is
// worth waiting for and nothing more: only a whole body logs a client in.
// Whatever body is, even nothing, the same work is done on it.
func (s *Server) checkHello(body, exporter []byte) (wire.Hello, bool) {
	const signed = wire.HelloLen - wire.TagLen
	var whole [wire.HelloLen]byte
	n := copy(whole[:], body)
	h, _ := wire.ParseHello(whole[:])
	now := s.now()
	want := h.ComputeTag(wire.LaneKey(wire.DeviceKey(s.cfg.NodeSecret, h.KeyID), exporter))
	tag := max(n-signed, 0)
	ok := subtle.ConstantTimeCompare(want[:tag], whole[signed:signed+tag])
	ok &= b2i(tag > 0 && n == len(body))
	ok &= subtle.ConstantTimeByteEq(h.Version, wire.Version)
	ok &= b2i(h.TimestampOK(now))
	ok &= b2i(!h.KeyID.Expired(now))
	ok &= b2i(!s.cfg.Revoked.Revoked(h.KeyID))
	return h, ok == 1
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Stats is a snapshot of the server.
type Stats struct {
	Sessions int
	Lanes    int
}

// Stats returns how many sessions and lanes are open.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	n := len(s.sessions)
	s.mu.Unlock()
	return Stats{Sessions: n, Lanes: int(s.lanes.Load())}
}

// Shutdown stops accepting connections, tells every session the server is
// going away (CLOSE with reason shutdown), and waits until their lanes have
// closed or ctx ends.
func (s *Server) Shutdown(ctx context.Context) error {
	sessions := s.stop()
	for _, ss := range sessions {
		ss.close(wire.CloseShutdown)
	}
	cerr := s.cover.shutdown(ctx)
	for _, ss := range sessions {
		select {
		case <-ss.done:
		case <-ctx.Done():
			s.Close()
			return ctx.Err()
		}
	}
	s.cancel()
	return cerr
}

// Close stops the server at once.
func (s *Server) Close() error {
	sessions := s.stop()
	for _, ss := range sessions {
		ss.abort()
	}
	s.cover.close()
	s.cancel()
	return nil
}

func (s *Server) stop() []*session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for l := range s.listeners {
		l.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	out := make([]*session, 0, len(s.sessions))
	for _, ss := range s.sessions {
		out = append(out, ss)
	}
	return out
}

// EnforceRevocation ends every session whose key_id is now revoked or
// expired, telling the client with CLOSE (reason credential). Call it after
// updating the revocation list; the server also runs it every minute.
func (s *Server) EnforceRevocation() {
	now := s.now()
	s.mu.Lock()
	var bad []*session
	for _, ss := range s.sessions {
		if ss.keyID.Expired(now) || s.cfg.Revoked.Revoked(ss.keyID) {
			bad = append(bad, ss)
		}
	}
	s.mu.Unlock()
	for _, ss := range bad {
		s.log.Info("ending session: credential no longer valid", "key_id", ss.keyID.String())
		ss.close(wire.CloseCredential)
	}
}

// janitor enforces revocation and expiry and reaps dead lanes.
func (s *Server) janitor() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
		s.EnforceRevocation()
		s.mu.Lock()
		all := make([]*session, 0, len(s.sessions))
		for _, ss := range s.sessions {
			all = append(all, ss)
		}
		s.mu.Unlock()
		for _, ss := range all {
			ss.reapIdle(s.cfg.LaneIdleTimeout)
		}
	}
}
