package lane

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/pangeavpn/tectonic/wire"
)

// SNIMode is what a direct lane puts in its ClientHello's server name
// (design §9). The server accepts any name, or none, because the login
// happens inside TLS.
type SNIMode uint8

const (
	// SNIOwn sends the node's cover domain and checks the real certificate
	// by name. SNI, DNS, IP and certificate all agree.
	SNIOwn SNIMode = iota + 1
	// SNIBorrowed sends any name the network allows and checks the node's
	// default certificate against a pin.
	SNIBorrowed
	// SNINone sends no server name, as Chrome does for https://<IP>, and
	// checks the default certificate against a pin, or accepts a trusted IP
	// certificate.
	SNINone
)

func (m SNIMode) String() string {
	switch m {
	case SNIOwn:
		return "own"
	case SNIBorrowed:
		return "borrowed"
	case SNINone:
		return "none"
	}
	return "unknown"
}

// ParseSNIMode parses "own", "borrowed" or "none".
func ParseSNIMode(s string) (SNIMode, error) {
	for _, m := range []SNIMode{SNIOwn, SNIBorrowed, SNINone} {
		if s == m.String() {
			return m, nil
		}
	}
	return 0, fmt.Errorf("lane: unknown SNI mode %q", s)
}

// Carrier is how a lane reaches the node (design §10).
type Carrier uint8

const (
	// Direct is a TLS 1.3 connection to the node, usually on port 443.
	Direct Carrier = iota
	// CDN is a WebSocket over TLS to a CDN edge that forwards to the node.
	CDN
)

func (c Carrier) String() string {
	if c == CDN {
		return "cdn"
	}
	return "direct"
}

// DialConfig says how to open one client lane.
type DialConfig struct {
	Carrier Carrier
	// Addr is the host:port to connect to: the node for Direct, the CDN
	// edge for CDN.
	Addr string
	// SNIMode applies to Direct lanes. CDN lanes always send ServerName and
	// check the edge's certificate by name.
	SNIMode SNIMode
	// ServerName is the cover domain (Own), the allowed name (Borrowed), or
	// the CDN edge's host name (CDN). It is ignored in None mode.
	ServerName string
	// Pins are the node's default-certificate pins, for Borrowed and None.
	Pins []Pin
	// RootCAs verifies certificates checked by name; nil means the system
	// roots.
	RootCAs *x509.CertPool
	// SessionCache lets later lanes resume TLS like a returning browser.
	// Share one cache across a client's lanes.
	SessionCache utls.ClientSessionCache
	// DialContext opens the TCP connection. Nil means a net.Dialer that
	// runs Control.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Control runs on the socket before it connects, for example to protect
	// it from a mobile VPN's own routing. Ignored when DialContext is set.
	Control func(network, address string, c syscall.RawConn) error
	// Path is the WebSocket path on the CDN edge.
	Path string
	// UserAgent overrides the CDN carrier's User-Agent.
	UserAgent string

	KeyID     wire.KeyID
	DeviceKey [wire.KeyLen]byte
	SessionID wire.SessionID // zero for a new session
	Join      bool
	Cellular  bool
	// Now is the clock for HELLO's timestamp; nil means time.Now.
	Now func() time.Time

	// FirstPacket, if set, rides in the same record as HELLO, so the first
	// WireGuard packet reaches the node within two round trips.
	FirstPacket []byte
	// TakeFirstPacket, if FirstPacket is nil, is called the moment TLS
	// completes, so a packet that arrived during the handshake still makes
	// the first flight.
	TakeFirstPacket func() []byte

	// Lane configures the lane itself. Role and Raw are filled in by Dial.
	Lane Options
}

// ErrNotTLS13 is returned when the server negotiates an older TLS version.
var ErrNotTLS13 = errors.New("lane: server did not negotiate TLS 1.3")

// Dial opens a client lane: TCP, a Chrome ClientHello, the TLS 1.3
// handshake, and then HELLO and the first WireGuard packet in one write. It
// returns as soon as that first flight is written, without waiting for
// WELCOME; Welcomed reports the server's answer, and a lane whose login
// fails ends with ErrLoginFailed.
func Dial(ctx context.Context, cfg DialConfig) (*Lane, error) {
	if cfg.Carrier == Direct && (cfg.SNIMode < SNIOwn || cfg.SNIMode > SNINone) {
		return nil, fmt.Errorf("lane: SNI mode %d", cfg.SNIMode)
	}
	raw, err := dialTCP(ctx, cfg)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			raw.Close()
		}
	}()
	// Abort a WebSocket handshake that outlives ctx.
	stop := context.AfterFunc(ctx, func() { raw.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	uconn, err := handshake(ctx, raw, cfg)
	if err != nil {
		return nil, err
	}
	var conn net.Conn = uconn
	var from io.Reader // where the lane reads frames; nil means conn
	var binding []byte
	switch cfg.Carrier {
	case Direct:
		cs := uconn.ConnectionState()
		binding, err = cs.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
		if err != nil {
			return nil, err
		}
		if cs.NegotiatedProtocol == "h2" {
			from = &pastSettings{r: uconn}
		}
	case CDN:
		ws, key, err := clientWebSocket(uconn, cfg.ServerName, cfg.Path, cfg.UserAgent)
		if err != nil {
			return nil, err
		}
		conn, binding = ws, WebSocketBinding(key)
	default:
		return nil, fmt.Errorf("lane: carrier %d", cfg.Carrier)
	}
	if !stop() {
		return nil, ctx.Err()
	}
	raw.SetDeadline(time.Time{})

	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	h := wire.Hello{Version: wire.Version, KeyID: cfg.KeyID, SessionID: cfg.SessionID, Timestamp: uint64(now().Unix())}
	if cfg.Join {
		h.Flags |= wire.FlagJoin
	}
	if cfg.Cellular {
		h.Flags |= wire.FlagCellular
	}
	h.Sign(wire.LaneKey(cfg.DeviceKey, binding))
	if cfg.FirstPacket == nil && cfg.TakeFirstPacket != nil {
		cfg.FirstPacket = cfg.TakeFirstPacket()
	}
	first := wire.AppendFrame(nil, wire.TypeHello, h.AppendBody(nil))
	if len(cfg.FirstPacket) > 0 && len(cfg.FirstPacket) <= wire.MaxBodyLen {
		first = wire.AppendFrame(first, wire.TypeData, cfg.FirstPacket)
	}

	opts := cfg.Lane
	opts.Role = Client
	opts.Raw = raw
	l := New(conn, from, opts)
	if len(cfg.FirstPacket) > 0 {
		l.dataSent.Add(uint64(len(cfg.FirstPacket)))
		l.pktsSent.Add(1)
	}
	if err := l.Start(first); err != nil {
		return nil, err
	}
	ok = true
	return l, nil
}

// pastSettings reads a direct lane's frames from a node that speaks first.
//
// Until a client logs in, the node is a web server, and a web server opens
// an HTTP/2 connection by sending its SETTINGS frame the moment the TLS
// handshake ends, before it has read anything. So that frame is on every
// connection that negotiated HTTP/2, a lane's included, and Tectonic's
// frames come after it. An HTTP/2 frame starts with its length in three
// bytes, so a SETTINGS frame starts with a zero byte, which no Tectonic
// frame does: a server that sends none is read as it always was.
//
// The frame is read past on the lane's first read, not in Dial, so Dial
// still returns without waiting for the server.
type pastSettings struct {
	r    io.Reader
	past bool
}

var errNotSettings = errors.New("lane: the server opened with an HTTP/2 frame that is not SETTINGS")

func (s *pastSettings) Read(p []byte) (int, error) {
	if s.past || len(p) == 0 {
		return s.r.Read(p)
	}
	// An HTTP/2 frame header: length (3 bytes), type, flags, stream.
	const settings, ack = 0x4, 0x1
	var hdr [9]byte
	if _, err := io.ReadFull(s.r, hdr[:1]); err != nil {
		return 0, err
	}
	s.past = true
	if hdr[0] != 0 {
		p[0] = hdr[0]
		return 1, nil
	}
	if _, err := io.ReadFull(s.r, hdr[1:]); err != nil {
		return 0, midFrame(err)
	}
	if hdr[3] != settings || hdr[4]&ack != 0 || binary.BigEndian.Uint32(hdr[5:])&0x7fffffff != 0 {
		return 0, errNotSettings
	}
	if _, err := io.CopyN(io.Discard, s.r, int64(binary.BigEndian.Uint16(hdr[1:]))); err != nil {
		return 0, midFrame(err)
	}
	return s.r.Read(p)
}

// midFrame is err for a stream that ended inside a frame.
func midFrame(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

func dialTCP(ctx context.Context, cfg DialConfig) (net.Conn, error) {
	if cfg.DialContext != nil {
		return cfg.DialContext(ctx, "tcp", cfg.Addr)
	}
	d := net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		if cfg.Control != nil {
			if err := cfg.Control(network, address, c); err != nil {
				return err
			}
		}
		setNotSentLowat(c, notSentLowat) // New checks it took
		return nil
	}}
	return d.DialContext(ctx, "tcp", cfg.Addr)
}

func handshake(ctx context.Context, raw net.Conn, cfg DialConfig) (*utls.UConn, error) {
	tc := &utls.Config{
		RootCAs:                     cfg.RootCAs,
		ClientSessionCache:          cfg.SessionCache,
		OmitEmptyPsk:                true,
		DynamicRecordSizingDisabled: true, // the shaper sizes records
	}
	h2 := true
	switch {
	case cfg.Carrier == CDN:
		// Chrome opens WebSockets on a connection that offers only
		// HTTP/1.1.
		tc.ServerName = cfg.ServerName
		h2 = false
	case cfg.SNIMode == SNIOwn:
		tc.ServerName = cfg.ServerName
	case cfg.SNIMode == SNIBorrowed:
		if cfg.ServerName == "" {
			return nil, errors.New("lane: borrowed mode needs a server name")
		}
		if len(cfg.Pins) == 0 {
			return nil, errors.New("lane: borrowed mode needs a pin")
		}
		tc.ServerName = cfg.ServerName
		tc.InsecureSkipVerify = true // replaced by the pin check below
		pins := cfg.Pins
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			return verifyPinned(raw, pins, nil, "")
		}
	case cfg.SNIMode == SNINone:
		host, _, err := net.SplitHostPort(cfg.Addr)
		if err != nil {
			return nil, err
		}
		tc.InsecureSkipVerify = true // replaced by the pin or IP-certificate check below
		pins, roots := cfg.Pins, cfg.RootCAs
		ipHost := ""
		if net.ParseIP(host) != nil {
			ipHost = host
		}
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			return verifyPinned(raw, pins, roots, ipHost)
		}
	}

	spec, err := chromeSpec(h2)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(raw, tc, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, err
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if uconn.ConnectionState().Version != utls.VersionTLS13 {
		return nil, ErrNotTLS13
	}
	// Chrome's renegotiation_info extension switched the config to
	// RenegotiateOnceAsClient, and uTLS then refuses TLS exporters. TLS 1.3
	// has no renegotiation, and the ClientHello has already gone out exactly
	// as Chrome's, so turning it off now changes nothing on the wire.
	tc.Renegotiation = utls.RenegotiateNever
	return uconn, nil
}

// chromeSpec is Chrome's ClientHello with pre_shared_key added last, so a
// lane can resume TLS like a returning browser. uTLS leaves the extension out
// when there is no ticket to resume, as Chrome does. With h2 false it offers
// only HTTP/1.1, as Chrome does on a WebSocket connection.
func chromeSpec(h2 bool) (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		return nil, err
	}
	exts := spec.Extensions[:0]
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.ALPNExtension:
			if !h2 {
				e.AlpnProtocols = []string{"http/1.1"}
			}
		case *utls.ApplicationSettingsExtensionNew:
			if !h2 {
				continue // ALPS only accompanies h2
			}
		}
		exts = append(exts, ext)
	}
	spec.Extensions = append(exts, &utls.UtlsPreSharedKeyExtension{})
	return &spec, nil
}

// ResumedTLS reports whether a lane's TLS session was resumed. It is meant
// for tests and diagnostics.
func ResumedTLS(l *Lane) bool {
	c := l.conn
	if ws, ok := c.(*wsConn); ok {
		c = ws.Conn
	}
	if u, ok := c.(*utls.UConn); ok {
		return u.HandshakeState.State13.UsingPSK
	}
	return false
}
