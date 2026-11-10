package server

import (
	"bufio"
	"context"
	"crypto/tls"
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

// When a login fails, the server never sends a Tectonic-specific error.
// Whatever bytes arrived go to the cover website's HTTP handler: a valid
// HTTP request gets the site, and anything else gets an ordinary 400 Bad
// Request and the connection closed (design §5). Connections that
// negotiated h2 are served HTTP/2, as any HTTP/2 server would.
type cover struct {
	s      *Server
	h1, h2 *http.Server
	l1, l2 *connListener
	wg     sync.WaitGroup
}

func newCover(s *Server) *cover {
	c := &cover{s: s, l1: newConnListener(), l2: newConnListener()}
	handler := http.HandlerFunc(c.serveHTTP)
	newServer := func(protos func(*http.Protocols)) *http.Server {
		var p http.Protocols
		protos(&p)
		return &http.Server{
			Handler:           handler,
			Protocols:         &p,
			ReadHeaderTimeout: s.cfg.HandshakeTimeout,
			IdleTimeout:       2 * time.Minute,
			ErrorLog:          log.New(io.Discard, "", 0), // probes are not news
			ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
				if bc, ok := conn.(*bufferedConn); ok {
					return context.WithValue(ctx, connKey{}, bc)
				}
				return ctx
			},
		}
	}
	c.h1 = newServer(func(p *http.Protocols) { p.SetHTTP1(true) })
	// Our connections are TLS already but don't look it to net/http, so
	// HTTP/2 is served the way it serves h2 with prior knowledge.
	c.h2 = newServer(func(p *http.Protocols) { p.SetUnencryptedHTTP2(true) })
	c.wg.Add(2)
	go func() { defer c.wg.Done(); c.h1.Serve(c.l1) }()
	go func() { defer c.wg.Done(); c.h2.Serve(c.l2) }()
	return c
}

type connKey struct{}

// serve hands a connection, with everything already read from it, to the
// cover website.
func (c *cover) serve(tc *tls.Conn, br *bufio.Reader, state tls.ConnectionState) bool {
	bc := &bufferedConn{Conn: tc, r: br, state: state}
	l := c.l1
	if state.NegotiatedProtocol == "h2" {
		l = c.l2
	}
	return l.push(bc)
}

// serveHTTP is the cover site, plus the CDN carrier's WebSocket path.
func (c *cover) serveHTTP(w http.ResponseWriter, r *http.Request) {
	bc, _ := r.Context().Value(connKey{}).(*bufferedConn)
	if bc != nil && r.TLS == nil {
		r.TLS = &bc.state
	}
	if cdn := c.s.cfg.CDN; cdn != nil && r.URL.Path == cdn.Path && r.ProtoMajor == 1 &&
		lane.IsWebSocketUpgrade(r) && cdn.Verify(r) {
		var raw net.Conn
		if bc != nil {
			if tc, ok := bc.Conn.(*tls.Conn); ok {
				raw = tc.NetConn() // the TCP connection to the CDN, for TCP_INFO
			}
		}
		c.s.serveCDN(w, r, raw)
		return
	}
	c.s.cfg.Cover.ServeHTTP(w, r)
}

func (c *cover) shutdown(ctx context.Context) error {
	c.l1.Close()
	c.l2.Close()
	err := errors.Join(c.h1.Shutdown(ctx), c.h2.Shutdown(ctx))
	c.wg.Wait()
	return err
}

func (c *cover) close() {
	c.l1.Close()
	c.l2.Close()
	c.h1.Close()
	c.h2.Close()
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
	frame, err := br.Peek(wire.HeaderLen + wire.HelloLen)
	if err != nil || frame[0] != wire.TypeHello || int(frame[1])<<8|int(frame[2]) != wire.HelloLen {
		conn.Close()
		return
	}
	h, ok := s.checkHello(frame[wire.HeaderLen:], lane.WebSocketBinding(key))
	if !ok {
		conn.Close()
		return
	}
	br.Discard(len(frame))
	conn.SetReadDeadline(time.Time{})
	if !s.startLane(conn, raw, br, h) {
		conn.Close()
	}
}

// bufferedConn replays what the server read while checking HELLO before
// reading on from the connection.
type bufferedConn struct {
	net.Conn
	r     *bufio.Reader
	state tls.ConnectionState
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

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
