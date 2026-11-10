package lane

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// The CDN carrier (design §10) runs a lane as a WebSocket over TLS to a CDN
// edge, which forwards it to the node. The lane's frames travel as a byte
// stream split across binary WebSocket messages; HELLO goes in the first one.
//
// The TLS connection ends at the CDN, so the node can't compute the client's
// TLS exporter. Both ends do see the WebSocket handshake, so a CDN lane binds
// its HELLO to the client's random Sec-WebSocket-Key instead:
//
//	exporter = SHA-256("tectonic cdn binding v1" ‖ Sec-WebSocket-Key)
//
// Only the CDN sees inside that TLS connection, and the node separately
// checks a header the CDN signs, so a HELLO can't be replayed onto another
// connection by anyone else.

const cdnBindingLabel = "tectonic cdn binding v1"

// WebSocketBinding is the CDN carrier's stand-in for the TLS exporter.
func WebSocketBinding(key string) []byte {
	h := sha256.New()
	h.Write([]byte(cdnBindingLabel))
	h.Write([]byte(key))
	return h.Sum(nil)
}

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// ChromeUserAgent is the User-Agent the CDN carrier sends, matching the
// Chrome version whose ClientHello uTLS imitates.
const ChromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// clientWebSocket performs the opening handshake the way Chrome does,
// headers in Chrome's order, and returns the connection and the key it sent.
func clientWebSocket(conn net.Conn, host, path, userAgent string) (*wsConn, string, error) {
	if path == "" {
		path = "/"
	}
	if userAgent == "" {
		userAgent = ChromeUserAgent
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, "", err
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Pragma: no-cache\r\n")
	b.WriteString("Cache-Control: no-cache\r\n")
	fmt.Fprintf(&b, "User-Agent: %s\r\n", userAgent)
	b.WriteString("Upgrade: websocket\r\n")
	fmt.Fprintf(&b, "Origin: https://%s\r\n", host)
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	b.WriteString("Accept-Encoding: gzip, deflate, br, zstd\r\n")
	b.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Key: %s\r\n", key)
	b.WriteString("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return nil, "", err
	}

	br := bufio.NewReaderSize(conn, readBufferSize)
	req, _ := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, "", fmt.Errorf("lane: websocket handshake: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, "", fmt.Errorf("lane: websocket handshake: status %s", resp.Status)
	}
	if !headerHas(resp.Header, "Upgrade", "websocket") || !headerHas(resp.Header, "Connection", "upgrade") {
		return nil, "", errors.New("lane: websocket handshake: not an upgrade")
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(key) {
		return nil, "", errors.New("lane: websocket handshake: bad Sec-WebSocket-Accept")
	}
	if resp.Header.Get("Sec-WebSocket-Extensions") != "" {
		return nil, "", errors.New("lane: websocket handshake: extensions are not supported")
	}
	return &wsConn{Conn: conn, br: br, client: true}, key, nil
}

// IsWebSocketUpgrade reports whether r asks to open a WebSocket.
func IsWebSocketUpgrade(r *http.Request) bool {
	return r.Method == http.MethodGet && headerHas(r.Header, "Upgrade", "websocket") &&
		headerHas(r.Header, "Connection", "upgrade")
}

// AcceptWebSocket completes a WebSocket opening handshake on the server and
// returns the connection and the client's Sec-WebSocket-Key. On error nothing
// has been written, so the caller can still answer like an ordinary website.
func AcceptWebSocket(w http.ResponseWriter, r *http.Request) (net.Conn, string, error) {
	if !IsWebSocketUpgrade(r) || r.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, "", errors.New("lane: not a websocket upgrade")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if b, err := base64.StdEncoding.DecodeString(key); err != nil || len(b) != 16 {
		return nil, "", errors.New("lane: bad Sec-WebSocket-Key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, "", errors.New("lane: connection can't be hijacked")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, "", err
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsAccept(key) + "\r\n\r\n"
	if _, err := io.WriteString(conn, resp); err != nil {
		conn.Close()
		return nil, "", err
	}
	return &wsConn{Conn: conn, br: rw.Reader}, key, nil
}

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// WebSocket opcodes (RFC 6455 §5.2).
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// wsConn carries a byte stream over WebSocket messages. Each Write becomes
// one binary message; Read returns message payloads back to back. Control
// frames are handled inside Read.
type wsConn struct {
	net.Conn
	br     *bufio.Reader
	client bool // client frames are masked

	wmu        sync.Mutex
	closeSent  bool
	wbuf       []byte
	remaining  uint64
	masked     bool
	mask       [4]byte
	maskPos    int
	readClosed bool
}

func (c *wsConn) Read(p []byte) (int, error) {
	for c.remaining == 0 {
		if c.readClosed {
			return 0, io.EOF
		}
		if err := c.nextFrame(); err != nil {
			return 0, err
		}
	}
	if uint64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.br.Read(p)
	if c.masked {
		for i := range n {
			p[i] ^= c.mask[(c.maskPos+i)&3]
		}
		c.maskPos += n
	}
	c.remaining -= uint64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

// nextFrame reads frame headers until a data frame with a payload begins,
// answering control frames on the way.
func (c *wsConn) nextFrame() error {
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
			return err
		}
		op := hdr[0] & 0x0F
		masked := hdr[1]&0x80 != 0
		n := uint64(hdr[1] & 0x7F)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(c.br, b[:]); err != nil {
				return err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(c.br, b[:]); err != nil {
				return err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(c.br, mask[:]); err != nil {
				return err
			}
		}
		switch op {
		case opContinuation, opText, opBinary:
			if n == 0 {
				continue
			}
			c.remaining, c.masked, c.mask, c.maskPos = n, masked, mask, 0
			return nil
		case opClose, opPing, opPong:
			if n > 125 {
				return errors.New("lane: websocket control frame too long")
			}
			body := make([]byte, n)
			if _, err := io.ReadFull(c.br, body); err != nil {
				return err
			}
			if masked {
				for i := range body {
					body[i] ^= mask[i&3]
				}
			}
			switch op {
			case opPing:
				if err := c.writeFrame(opPong, body); err != nil {
					return err
				}
			case opClose:
				c.readClosed = true
				_ = c.CloseWrite()
				return io.EOF
			}
		default:
			return fmt.Errorf("lane: websocket opcode %#x", op)
		}
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.writeFrame(opBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// CloseWrite sends a normal close frame, the WebSocket counterpart of TLS
// close_notify.
func (c *wsConn) CloseWrite() error {
	c.wmu.Lock()
	sent := c.closeSent
	c.wmu.Unlock()
	if sent {
		return nil
	}
	return c.writeFrame(opClose, []byte{0x03, 0xE8}) // 1000: normal closure
}

func (c *wsConn) writeFrame(op byte, p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closeSent {
		return net.ErrClosed
	}
	if op == opClose {
		c.closeSent = true
	}
	b := c.wbuf[:0]
	b = append(b, 0x80|op)
	maskBit := byte(0)
	if c.client {
		maskBit = 0x80
	}
	switch n := len(p); {
	case n < 126:
		b = append(b, maskBit|byte(n))
	case n <= 0xFFFF:
		b = append(b, maskBit|126)
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	default:
		b = append(b, maskBit|127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	if c.client {
		var mask [4]byte
		if _, err := rand.Read(mask[:]); err != nil {
			return err
		}
		b = append(b, mask[:]...)
		start := len(b)
		b = append(b, p...)
		for i := range p {
			b[start+i] ^= mask[i&3]
		}
	} else {
		b = append(b, p...)
	}
	c.wbuf = b
	_, err := c.Conn.Write(b)
	return err
}
