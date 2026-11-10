// Package wire defines what Tectonic puts inside TLS: frames, the HELLO login
// and WELCOME reply, and the keys that sign HELLO. It does no I/O beyond
// reading frames from an io.Reader, so it can be unit- and fuzz-tested alone.
//
// A lane carries a series of frames:
//
//	frame = type (1 byte) ‖ length (2 bytes, big-endian) ‖ body (length bytes)
//
// Several frames can share one TLS record; the shaper decides record sizes.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame types (design §6).
const (
	TypeHello   byte = 0x01 // C → S, always the first frame on a lane
	TypeWelcome byte = 0x02 // S → C, the reply to a valid HELLO
	TypeData    byte = 0x03 // exactly one WireGuard datagram
	TypePad     byte = 0x04 // zeros, thrown away on receipt
	TypePing    byte = 0x05 // PING and PONG: an 8-byte token
	TypeRetire  byte = 0x06 // no new DATA on this lane
	TypeClose   byte = 0x07 // ends the whole session; 1-byte reason
	TypeLost    byte = 0x08 // WireGuard datagrams the sender dropped
)

// HeaderLen is the size of a frame header: type and big-endian length.
const HeaderLen = 3

// MaxBodyLen is the largest body a single frame can carry.
const MaxBodyLen = 0xFFFF

// MaxFrameLen is the largest frame, header included.
const MaxFrameLen = HeaderLen + MaxBodyLen

// ErrFrameTooLong is returned when a body does not fit a frame's length field.
var ErrFrameTooLong = errors.New("wire: frame body longer than 65535 bytes")

// AppendFrame appends one frame to dst. It panics if body is longer than
// MaxBodyLen, which is always a programming error: WireGuard datagrams and
// control bodies are far smaller.
func AppendFrame(dst []byte, typ byte, body []byte) []byte {
	dst = AppendHeader(dst, typ, len(body))
	return append(dst, body...)
}

// AppendHeader appends a frame header announcing a body of n bytes, for
// callers that write the body themselves.
func AppendHeader(dst []byte, typ byte, n int) []byte {
	if n < 0 || n > MaxBodyLen {
		panic(ErrFrameTooLong)
	}
	return append(dst, typ, byte(n>>8), byte(n))
}

// CanPad reports whether exactly n bytes of padding can be expressed as PAD
// frames. A PAD frame is at least a header, so 1 and 2 cannot.
func CanPad(n int) bool { return n == 0 || n >= HeaderLen }

// AppendPadding appends PAD frames that occupy exactly n bytes in total. It
// panics unless CanPad(n).
func AppendPadding(dst []byte, n int) []byte {
	if !CanPad(n) {
		panic(fmt.Sprintf("wire: cannot pad %d bytes", n))
	}
	for n > 0 {
		body := n - HeaderLen
		if body > MaxBodyLen {
			body = MaxBodyLen
			// Never leave a remainder that is too small to be a frame.
			if rest := n - HeaderLen - body; rest > 0 && rest < HeaderLen {
				body -= HeaderLen
			}
		}
		dst = AppendHeader(dst, TypePad, body)
		dst = append(dst, make([]byte, body)...)
		n -= HeaderLen + body
	}
	return dst
}

// Reader splits a byte stream into frames.
type Reader struct {
	r    io.Reader
	hdr  [HeaderLen]byte
	body []byte
}

// NewReader returns a Reader that reads frames from r. Wrap r in a
// bufio.Reader if it is costly to read in small pieces.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: r, body: make([]byte, MaxBodyLen)}
}

// Next reads the next frame. The body aliases an internal buffer and is only
// valid until the following call to Next. Unknown frame types are returned
// like any other; skipping them is the caller's choice, and the length field
// makes it safe. A stream that ends cleanly between frames returns io.EOF; one
// that ends inside a frame returns io.ErrUnexpectedEOF.
func (r *Reader) Next() (typ byte, body []byte, err error) {
	if _, err := io.ReadFull(r.r, r.hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(r.hdr[1:]))
	if _, err := io.ReadFull(r.r, r.body[:n]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	return r.hdr[0], r.body[:n], nil
}
