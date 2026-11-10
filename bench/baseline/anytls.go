package baseline

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// AnyTLS session commands (protocol v2).
const (
	cmdWaste               = 0
	cmdSYN                 = 1
	cmdPSH                 = 2
	cmdFIN                 = 3
	cmdSettings            = 4
	cmdAlert               = 5
	cmdUpdatePaddingScheme = 6
	cmdSYNACK              = 7
	cmdHeartRequest        = 8
	cmdHeartResponse       = 9
	cmdServerSettings      = 10
)

// frameHeaderLen is command (1) + stream id (4) + data length (2).
const frameHeaderLen = 7

// anytlsPassword is the bench user's password.
const anytlsPassword = "tectonic-bench"

// uotMagic is the destination that asks for sing-box UDP-over-TCP v2.
const uotMagic = "sp.v2.udp-over-tcp.arpa"

// SOCKS5 address types, as sing's M.SocksaddrSerializer writes them.
const (
	socksIP4  = 1
	socksFQDN = 3
	socksIP6  = 4
)

// anytlsStream is the one stream the model opens per session.
const anytlsStream = 1

func appendFrame(b []byte, cmd byte, sid uint32, data []byte) []byte {
	b = append(b, cmd)
	b = binary.BigEndian.AppendUint32(b, sid)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func appendSocksFQDN(b []byte, host string, port uint16) []byte {
	b = append(b, socksFQDN, byte(len(host)))
	b = append(b, host...)
	return binary.BigEndian.AppendUint16(b, port)
}

func appendSocksIP4(b []byte, ip [4]byte, port uint16) []byte {
	b = append(b, socksIP4)
	b = append(b, ip[:]...)
	return binary.BigEndian.AppendUint16(b, port)
}

// readSocksAddr reads a SOCKS5-style address and returns its host.
func readSocksAddr(r io.Reader) (string, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return "", err
	}
	var host []byte
	switch t[0] {
	case socksIP4:
		host = make([]byte, 4)
	case socksIP6:
		host = make([]byte, 16)
	case socksFQDN:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		host = make([]byte, n[0])
	default:
		return "", fmt.Errorf("baseline: SOCKS address type %d", t[0])
	}
	if _, err := io.ReadFull(r, host); err != nil {
		return "", err
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	if t[0] == socksFQDN {
		return string(host), nil
	}
	return net.IP(host).String(), nil
}

// anytlsWriter writes AnyTLS session frames. On the client it applies the
// padding scheme exactly as anytls-go's Session.writeConn does; the server
// never pads.
type anytlsWriter struct {
	conn      net.Conn
	padding   *paddingScheme // nil: no padding
	pkt       uint32         // client writes so far, after the auth packet
	buffering bool
	buffer    []byte
}

func (w *anytlsWriter) writeFrame(cmd byte, sid uint32, data []byte) error {
	return w.writeConn(appendFrame(make([]byte, 0, frameHeaderLen+len(data)), cmd, sid, data))
}

func (w *anytlsWriter) writeConn(b []byte) error {
	if w.buffering {
		w.buffer = append(w.buffer, b...)
		return nil
	}
	if len(w.buffer) > 0 {
		b = append(w.buffer, b...)
		w.buffer = nil
	}
	if w.padding == nil {
		_, err := w.conn.Write(b)
		return err
	}
	w.pkt++
	if w.pkt >= w.padding.stop {
		w.padding = nil // padding is over for this session
		_, err := w.conn.Write(b)
		return err
	}
	for _, l := range w.padding.sizes(w.pkt) {
		remain := len(b)
		if l == checkMark {
			if remain == 0 {
				break
			}
			continue
		}
		switch {
		case remain > l: // this piece is all payload
			if _, err := w.conn.Write(b[:l]); err != nil {
				return err
			}
			b = b[l:]
		case remain > 0: // the rest of the payload, padded up to l
			if pad := l - remain - frameHeaderLen; pad > 0 {
				b = appendFrame(b, cmdWaste, 0, make([]byte, pad))
			}
			if _, err := w.conn.Write(b); err != nil {
				return err
			}
			b = nil
		default: // pure padding
			if _, err := w.conn.Write(appendFrame(nil, cmdWaste, 0, make([]byte, l))); err != nil {
				return err
			}
		}
	}
	if len(b) > 0 {
		_, err := w.conn.Write(b)
		return err
	}
	return nil
}

// frameReader yields the PSH payload of one stream as a byte stream and
// hands every other frame to control. A stream id of 0 means "not open yet";
// control may set it when it sees cmdSYN.
type frameReader struct {
	br        *bufio.Reader
	sid       uint32
	remaining int // unread bytes of the current PSH frame
	control   func(cmd byte, sid uint32, data []byte) error
}

func (r *frameReader) Read(p []byte) (int, error) {
	for r.remaining == 0 {
		var h [frameHeaderLen]byte
		if _, err := io.ReadFull(r.br, h[:]); err != nil {
			return 0, err
		}
		cmd, sid, n := h[0], binary.BigEndian.Uint32(h[1:5]), int(binary.BigEndian.Uint16(h[5:7]))
		switch {
		case cmd == cmdPSH && sid == r.sid && sid != 0:
			r.remaining = n
			continue
		case cmd == cmdPSH || cmd == cmdWaste:
			if _, err := r.br.Discard(n); err != nil {
				return 0, err
			}
			continue
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(r.br, data); err != nil {
			return 0, err
		}
		if err := r.control(cmd, sid, data); err != nil {
			return 0, err
		}
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.br.Read(p)
	r.remaining -= n
	return n, err
}

// anytlsClient is the client side of one AnyTLS session with one
// UDP-over-TCP stream.
type anytlsClient struct {
	w      anytlsWriter
	wmu    *sync.Mutex // the packetConn's write lock
	fr     *frameReader
	uotHdr []byte // UoT request, sent with the first datagram
}

// newAnyTLSClient sends the authentication packet (write 0) and the
// session preamble (write 1: cmdSettings, cmdSYN and a PSH naming the UoT
// destination), as anytls-go's client and sing-box's outbound do.
func newAnyTLSClient(conn net.Conn, br *bufio.Reader, wmu *sync.Mutex) (*anytlsClient, error) {
	c := &anytlsClient{w: anytlsWriter{conn: conn, padding: defaultPadding}, wmu: wmu}

	sum := sha256.Sum256([]byte(anytlsPassword))
	auth := append([]byte(nil), sum[:]...)
	pad0 := 0
	if s := defaultPadding.sizes(0); len(s) > 0 && s[0] > 0 {
		pad0 = s[0]
	}
	auth = binary.BigEndian.AppendUint16(auth, uint16(pad0))
	auth = append(auth, make([]byte, pad0)...)
	if _, err := conn.Write(auth); err != nil {
		return nil, err
	}

	settings := "v=2\nclient=tectonic-bench/anytls-model\npadding-md5=" + defaultPadding.md5
	c.w.buffering = true
	if err := c.w.writeFrame(cmdSettings, 0, []byte(settings)); err != nil {
		return nil, err
	}
	if err := c.w.writeFrame(cmdSYN, anytlsStream, nil); err != nil {
		return nil, err
	}
	c.w.buffering = false
	if err := c.w.writeFrame(cmdPSH, anytlsStream, appendSocksFQDN(nil, uotMagic, 0)); err != nil {
		return nil, err
	}

	// UoT v2 request: isConnect, then the destination (ignored by the
	// model's server, which forwards to its wgAddr).
	c.uotHdr = appendSocksIP4([]byte{1}, vlessTarget, vlessTargetPort)
	c.fr = &frameReader{br: br, sid: anytlsStream, control: c.control}
	return c, nil
}

func (c *anytlsClient) writeDatagram(p []byte) error {
	data := make([]byte, 0, len(c.uotHdr)+2+len(p))
	data = append(data, c.uotHdr...)
	c.uotHdr = nil
	data = appendDatagram(data, p)
	return c.w.writeFrame(cmdPSH, anytlsStream, data)
}

func (c *anytlsClient) reader() io.Reader { return c.fr }

// control handles the server's non-data frames on the read goroutine.
func (c *anytlsClient) control(cmd byte, sid uint32, data []byte) error {
	switch cmd {
	case cmdSYNACK:
		if len(data) > 0 {
			return fmt.Errorf("baseline: AnyTLS stream refused: %s", data)
		}
	case cmdFIN:
		if sid == anytlsStream {
			return io.EOF
		}
	case cmdAlert:
		return fmt.Errorf("baseline: AnyTLS alert: %s", data)
	case cmdHeartRequest:
		c.wmu.Lock()
		defer c.wmu.Unlock()
		return c.w.writeFrame(cmdHeartResponse, sid, nil)
	}
	// cmdServerSettings, cmdUpdatePaddingScheme (which only affects later
	// sessions) and anything unknown need no action.
	return nil
}

// anytlsServer is the server side of one session after its stream's UoT
// request has been read.
type anytlsServer struct {
	mu  sync.Mutex // serializes writes from both goroutines
	w   anytlsWriter
	fr  *frameReader
	sid uint32
}

func acceptAnyTLS(conn net.Conn, br *bufio.Reader) (*anytlsServer, error) {
	var auth [sha256.Size + 2]byte
	if _, err := io.ReadFull(br, auth[:]); err != nil {
		return nil, err
	}
	if [sha256.Size]byte(auth[:sha256.Size]) != sha256.Sum256([]byte(anytlsPassword)) {
		return nil, errors.New("baseline: AnyTLS authentication failed")
	}
	if _, err := br.Discard(int(binary.BigEndian.Uint16(auth[sha256.Size:]))); err != nil {
		return nil, err
	}

	s := &anytlsServer{w: anytlsWriter{conn: conn}}
	settings := false
	s.fr = &frameReader{br: br, control: func(cmd byte, sid uint32, data []byte) error {
		switch cmd {
		case cmdSettings:
			settings = true
			s.mu.Lock()
			defer s.mu.Unlock()
			if !strings.Contains(string(data), "padding-md5="+defaultPadding.md5) {
				if err := s.w.writeFrame(cmdUpdatePaddingScheme, 0, []byte(DefaultAnyTLSPaddingScheme)); err != nil {
					return err
				}
			}
			return s.w.writeFrame(cmdServerSettings, 0, []byte("v=2"))
		case cmdSYN:
			if !settings {
				s.mu.Lock()
				defer s.mu.Unlock()
				s.w.writeFrame(cmdAlert, 0, []byte("client did not send its settings"))
				return errors.New("baseline: AnyTLS SYN before settings")
			}
			if s.fr.sid != 0 {
				return errors.New("baseline: the AnyTLS model supports one stream per session")
			}
			s.fr.sid, s.sid = sid, sid
		case cmdFIN:
			if sid == s.sid {
				return io.EOF
			}
		case cmdHeartRequest:
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.w.writeFrame(cmdHeartResponse, sid, nil)
		}
		return nil
	}}

	dst, err := readSocksAddr(s.fr)
	if err != nil {
		return nil, err
	}
	if dst != uotMagic {
		return nil, fmt.Errorf("baseline: AnyTLS destination %q, model supports UDP-over-TCP only", dst)
	}
	var isConnect [1]byte
	if _, err := io.ReadFull(s.fr, isConnect[:]); err != nil {
		return nil, err
	}
	if _, err := readSocksAddr(s.fr); err != nil {
		return nil, err
	}
	if isConnect[0] != 1 {
		return nil, errors.New("baseline: the AnyTLS model supports UoT connect mode only")
	}
	// The outbound socket is ready: report the stream open.
	s.mu.Lock()
	err = s.w.writeFrame(cmdSYNACK, s.sid, nil)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *anytlsServer) reader() io.Reader { return s.fr }

func (s *anytlsServer) writeDatagram(p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data := appendDatagram(make([]byte, 0, 2+len(p)), p)
	return s.w.writeFrame(cmdPSH, s.sid, data)
}
