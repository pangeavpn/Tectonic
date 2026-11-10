package baseline

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// VLESS request: version, user UUID, addons, command, port, address.
const (
	vlessVersion = 0
	vlessCmdUDP  = 2
	vlessAddrIP4 = 1
	vlessAddrDom = 2
	vlessAddrIP6 = 3
)

// vlessUUID is the bench user's id. The model does not authenticate.
var vlessUUID = [16]byte{0x74, 0x65, 0x63, 0x74, 0x6f, 0x6e, 0x69, 0x63, 0x2d, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x00, 0x01}

// vlessTarget is the destination the client names in its request. The
// model's server ignores it and forwards to Serve's wgAddr.
var vlessTarget = [4]byte{127, 0, 0, 1}

const vlessTargetPort = 51820

// realityClient frames datagrams VLESS-style. The request header goes out
// with the first datagram, as Xray sends it.
type realityClient struct {
	conn net.Conn
	br   *bufio.Reader
	hdr  []byte // pending request header; nil once sent
	buf  []byte
	resp bool // response header consumed
}

func newRealityClient(conn net.Conn, br *bufio.Reader) *realityClient {
	hdr := []byte{vlessVersion}
	hdr = append(hdr, vlessUUID[:]...)
	hdr = append(hdr, 0, vlessCmdUDP) // no addons
	hdr = binary.BigEndian.AppendUint16(hdr, vlessTargetPort)
	hdr = append(hdr, vlessAddrIP4)
	hdr = append(hdr, vlessTarget[:]...)
	return &realityClient{conn: conn, br: br, hdr: hdr}
}

func (c *realityClient) writeDatagram(p []byte) error {
	b := c.buf[:0]
	if c.hdr != nil {
		b = append(b, c.hdr...)
		c.hdr = nil
	}
	b = appendDatagram(b, p)
	c.buf = b
	_, err := c.conn.Write(b)
	return err
}

func (c *realityClient) reader() io.Reader { return realityResponseReader{c} }

// realityResponseReader strips the VLESS response header (version and
// addons) that precedes the server's first datagram.
type realityResponseReader struct{ c *realityClient }

func (r realityResponseReader) Read(p []byte) (int, error) {
	if !r.c.resp {
		var h [2]byte
		if _, err := io.ReadFull(r.c.br, h[:]); err != nil {
			return 0, err
		}
		if h[0] != vlessVersion {
			return 0, fmt.Errorf("baseline: VLESS response version %d", h[0])
		}
		if _, err := r.c.br.Discard(int(h[1])); err != nil {
			return 0, err
		}
		r.c.resp = true
	}
	return r.c.br.Read(p)
}

// realityServer is the server side after the VLESS request.
type realityServer struct {
	conn net.Conn
	br   *bufio.Reader
	hdr  []byte // pending response header; nil once sent
	buf  []byte
}

func acceptReality(conn net.Conn, br *bufio.Reader) (*realityServer, error) {
	var h [18]byte // version, UUID, addons length
	if _, err := io.ReadFull(br, h[:]); err != nil {
		return nil, err
	}
	if h[0] != vlessVersion || [16]byte(h[1:17]) != vlessUUID {
		return nil, errors.New("baseline: bad VLESS request")
	}
	if _, err := br.Discard(int(h[17])); err != nil {
		return nil, err
	}
	var cmd [4]byte // command, port, address type
	if _, err := io.ReadFull(br, cmd[:]); err != nil {
		return nil, err
	}
	if cmd[0] != vlessCmdUDP {
		return nil, fmt.Errorf("baseline: VLESS command %d, model supports UDP only", cmd[0])
	}
	var addrLen int
	switch cmd[3] {
	case vlessAddrIP4:
		addrLen = 4
	case vlessAddrIP6:
		addrLen = 16
	case vlessAddrDom:
		n, err := br.ReadByte()
		if err != nil {
			return nil, err
		}
		addrLen = int(n)
	default:
		return nil, fmt.Errorf("baseline: VLESS address type %d", cmd[3])
	}
	if _, err := br.Discard(addrLen); err != nil {
		return nil, err
	}
	return &realityServer{conn: conn, br: br, hdr: []byte{vlessVersion, 0}}, nil
}

func (s *realityServer) reader() io.Reader { return s.br }

// writeDatagram is only called from the UDP→TLS goroutine.
func (s *realityServer) writeDatagram(p []byte) error {
	b := s.buf[:0]
	if s.hdr != nil {
		b = append(b, s.hdr...)
		s.hdr = nil
	}
	b = appendDatagram(b, p)
	s.buf = b
	_, err := s.conn.Write(b)
	return err
}
