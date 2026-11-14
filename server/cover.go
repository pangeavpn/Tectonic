package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pangeavpn/tectonic/lane"
	"github.com/pangeavpn/tectonic/wire"
)

// The cover website is a net/http server, and every connection the node
// accepts is that server's connection from the start. net/http runs the TLS
// handshake, sends its SETTINGS frame first on HTTP/2, times out a client
// that stalls and closes through TLS, so a stranger sees what any Go HTTPS
// server shows: it is one. The server never sends a Tectonic-specific error
// (design §5).
//
// The node's own part is one hook, in conn.Read: the web server's first read
// on a connection that could be a lane is where a HELLO is looked for. A
// valid one takes the connection away from the web server and makes it a
// lane. Anything else is the web server's to answer, with every byte the
// client sent.
type cover struct {
	s *Server
	// direct means net/http serves a connection it is handed the way it
	// serves a tls.Conn it accepted itself, HTTP/2 included. It does from
	// Go 1.27. Before that the node runs the handshake and picks one of two
	// web servers by ALPN, and HTTP/2 is served the way net/http serves it
	// without TLS, which is close to the real thing but not the same.
	direct bool
	web    []*http.Server // direct: one. Otherwise HTTP/1.1, then HTTP/2.
	in     []*connListener
	// opening is what the web server writes when an HTTP/2 connection
	// opens, before the client has said anything: its SETTINGS frame.
	opening []byte
	wg      sync.WaitGroup
}

func newCover(s *Server, direct bool) (*cover, error) {
	c := &cover{s: s, direct: direct}
	if direct {
		c.add(func(p *http.Protocols) { p.SetHTTP1(true); p.SetHTTP2(true) })
	} else {
		c.add(func(p *http.Protocols) { p.SetHTTP1(true) })
		c.add(func(p *http.Protocols) { p.SetUnencryptedHTTP2(true) })
	}
	opening, err := c.rehearse()
	if err != nil {
		c.close()
		return nil, err
	}
	c.opening = opening
	return c, nil
}

func (c *cover) add(protos func(*http.Protocols)) {
	var p http.Protocols
	protos(&p)
	srv := &http.Server{
		Handler:           http.HandlerFunc(c.serveHTTP),
		Protocols:         &p,
		ReadHeaderTimeout: c.s.cfg.HandshakeTimeout,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(io.Discard, "", 0), // probes are not news
		ConnContext: func(ctx context.Context, nc net.Conn) context.Context {
			if pc, ok := nc.(plainConn); ok {
				nc = pc.Conn
			}
			if cn, ok := nc.(*conn); ok {
				return context.WithValue(ctx, connKey{}, cn)
			}
			return ctx
		},
	}
	l := newConnListener()
	c.web = append(c.web, srv)
	c.in = append(c.in, l)
	c.wg.Add(1)
	go func() { defer c.wg.Done(); srv.Serve(l) }()
}

type connKey struct{}

// serve gives a connection the node has accepted to the web server. It
// reports whether the web server took it.
func (c *cover) serve(raw net.Conn) bool {
	cn := &conn{Conn: tls.Server(raw, c.s.tls), s: c.s, raw: raw}
	if c.direct {
		return c.in[0].push(cn)
	}
	ctx, cancel := context.WithTimeout(c.s.ctx, c.s.cfg.HandshakeTimeout)
	err := cn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		return false
	}
	if cn.ConnectionState().NegotiatedProtocol != "h2" {
		return c.in[0].push(cn)
	}
	// Without TLS, net/http waits for the client's preface before it sends
	// SETTINGS. Over TLS it sends them at once, so the node does that for
	// it here and drops them when the web server gets round to it.
	cn.Conn.Write(c.opening)
	cn.opened, cn.skip = true, c.opening
	return c.in[1].push(plainConn{cn})
}

var errOpening = errors.New("server: the cover web server did not open an HTTP/2 connection with a SETTINGS frame; this version of Go is not one the server knows")

// h2Preface is what an HTTP/2 client sends first (RFC 9113 §3.4).
const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// rehearse opens an HTTP/2 connection to the web server with nobody on the
// other end and returns what the web server writes first. A lane needs
// those bytes (see conn.handOver), and taking them from the web server
// itself keeps them right whatever the Go version or the server's settings.
// It is also the check that the web server speaks first at all.
func (c *cover) rehearse() ([]byte, error) {
	rc := &rehearsal{wrote: make(chan []byte, 1), done: make(chan struct{})}
	defer rc.Close()
	var nc net.Conn = rc
	in := c.in[0]
	if !c.direct {
		rc.says = []byte(h2Preface)
		nc, in = plainConn{rc}, c.in[1]
	}
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	select {
	case in.ch <- nc:
	case <-t.C:
		return nil, errOpening
	}
	select {
	case b := <-rc.wrote:
		if !isSettings(b) {
			return nil, errOpening
		}
		return b, nil
	case <-t.C:
		return nil, errOpening
	}
}

// isSettings reports whether b is exactly one HTTP/2 SETTINGS frame, and not
// an acknowledgement (RFC 9113 §6.5).
func isSettings(b []byte) bool {
	const headerLen, settings = 9, 0x4
	return len(b) >= headerLen &&
		len(b) == headerLen+(int(b[0])<<16|int(b[1])<<8|int(b[2])) &&
		b[3] == settings && b[4] == 0 && binary.BigEndian.Uint32(b[5:]) == 0
}

// rehearsal is a TLS 1.3 connection that negotiated HTTP/2, as far as the
// web server can tell. It keeps the first thing the web server writes.
type rehearsal struct {
	says []byte // what the client sends before it goes quiet
	// chunks, if set, is what the client sends instead, one TLS record
	// each: a read returns from one record only, as tls.Conn's does.
	chunks [][]byte
	wrote  chan []byte
	done   chan struct{}
	once   sync.Once
}

func (r *rehearsal) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{
		Version:            tls.VersionTLS13,
		HandshakeComplete:  true,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2",
	}
}

func (r *rehearsal) Read(p []byte) (int, error) {
	for len(r.chunks) > 0 {
		if len(r.chunks[0]) == 0 {
			r.chunks = r.chunks[1:]
			continue
		}
		n := copy(p, r.chunks[0])
		r.chunks[0] = r.chunks[0][n:]
		return n, nil
	}
	if len(r.says) > 0 {
		n := copy(p, r.says)
		r.says = r.says[n:]
		return n, nil
	}
	<-r.done
	return 0, io.EOF
}

func (r *rehearsal) Write(p []byte) (int, error) {
	select {
	case r.wrote <- append([]byte(nil), p...):
	default:
	}
	return len(p), nil
}

func (r *rehearsal) Close() error                     { r.once.Do(func() { close(r.done) }); return nil }
func (r *rehearsal) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4zero, Port: 443} }
func (r *rehearsal) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4zero} }
func (r *rehearsal) SetDeadline(time.Time) error      { return nil }
func (r *rehearsal) SetReadDeadline(time.Time) error  { return nil }
func (r *rehearsal) SetWriteDeadline(time.Time) error { return nil }

// serveHTTP is the cover site, plus the CDN carrier's WebSocket path.
func (c *cover) serveHTTP(w http.ResponseWriter, r *http.Request) {
	cn, _ := r.Context().Value(connKey{}).(*conn)
	if cn != nil && r.TLS == nil {
		// HTTP/2 served the way it is without TLS, on a connection that
		// has it all the same.
		cs := cn.ConnectionState()
		r.TLS = &cs
	}
	if cdn := c.s.cfg.CDN; cdn != nil && r.URL.Path == cdn.Path && r.ProtoMajor == 1 &&
		lane.IsWebSocketUpgrade(r) && cdn.Verify(r) {
		var raw net.Conn
		if cn != nil {
			raw = cn.raw // the TCP connection to the CDN, for TCP_INFO
		}
		c.s.serveCDN(w, r, raw)
		return
	}
	c.s.cfg.Cover.ServeHTTP(w, r)
}

func (c *cover) shutdown(ctx context.Context) error {
	var errs []error
	for _, l := range c.in {
		l.Close()
	}
	for _, srv := range c.web {
		errs = append(errs, srv.Shutdown(ctx))
	}
	c.wg.Wait()
	return errors.Join(errs...)
}

func (c *cover) close() {
	for _, l := range c.in {
		l.Close()
	}
	for _, srv := range c.web {
		srv.Close()
	}
	c.wg.Wait()
}

// serveCDN runs a CDN lane: the WebSocket upgrade, then HELLO in the first
// message, bound to the client's Sec-WebSocket-Key because the client's TLS
// ended at the CDN.
func (s *Server) serveCDN(w http.ResponseWriter, r *http.Request, raw net.Conn) {
	conn, key, err := lane.AcceptWebSocket(w, r)
	if err != nil {
		s.cfg.Cover.ServeHTTP(w, r)
		return
	}
	conn.SetReadDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	br := bufio.NewReaderSize(conn, 64<<10)
	frame, err := br.Peek(helloLen)
	if err != nil || !startsHello(frame) {
		conn.Close()
		return
	}
	h, ok := s.checkHello(frame[wire.HeaderLen:], lane.WebSocketBinding(key))
	if !ok {
		conn.Close()
		return
	}
	// A login is bound to this key, and each key opens one lane: see
	// replayGuard. The check runs only on a login that is otherwise valid,
	// so what a probe sees is unchanged.
	if !s.replay.fresh(key, s.now()) {
		if s.replay.sayFull(s.now()) {
			s.log.Warn("refusing CDN logins: too many keys to remember", "limit", maxReplaySeen)
		} else {
			s.log.Warn("refusing a CDN login whose WebSocket key was used already", "key", keyTag(h.KeyID))
		}
		conn.Close()
		return
	}
	br.Discard(len(frame))
	conn.SetReadDeadline(time.Time{})
	if !s.startLane(conn, raw, br, h) {
		conn.Close()
	}
}

// connListener feeds connections the server has already accepted to an
// http.Server.
type connListener struct {
	ch     chan net.Conn
	done   chan struct{}
	closed sync.Once
}

func newConnListener() *connListener {
	return &connListener{ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *connListener) push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.closed.Do(func() { close(l.done) })
	return nil
}

func (l *connListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 443} }
