package wire

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"
)

// WELCOME body layout. The design lists the fields; their widths are fixed
// here:
//
//	session_id     16 bytes
//	max_lanes       1 byte
//	resume_window   2 bytes   seconds, big-endian
//	profile         2 bytes   shaping profile ID, big-endian
//
// A receiver ignores bytes after these, so fields can be appended later.
const WelcomeLen = SessionIDLen + 1 + 2 + 2 // 21

// ErrWelcomeLength is returned for a WELCOME body that is too short.
var ErrWelcomeLength = errors.New("wire: WELCOME body shorter than 21 bytes")

// Welcome is the server's reply to a valid HELLO.
type Welcome struct {
	SessionID    SessionID
	MaxLanes     uint8
	ResumeWindow time.Duration // whole seconds on the wire
	Profile      uint16        // shaping profile ID
}

// AppendBody appends the WELCOME body to dst.
func (w *Welcome) AppendBody(dst []byte) []byte {
	dst = append(dst, w.SessionID[:]...)
	dst = append(dst, w.MaxLanes)
	secs := w.ResumeWindow / time.Second
	if secs > 0xFFFF {
		secs = 0xFFFF
	}
	if secs < 0 {
		secs = 0
	}
	dst = binary.BigEndian.AppendUint16(dst, uint16(secs))
	return binary.BigEndian.AppendUint16(dst, w.Profile)
}

// ParseWelcome decodes a WELCOME body.
func ParseWelcome(body []byte) (Welcome, error) {
	var w Welcome
	if len(body) < WelcomeLen {
		return w, ErrWelcomeLength
	}
	copy(w.SessionID[:], body[:16])
	w.MaxLanes = body[16]
	w.ResumeWindow = time.Duration(binary.BigEndian.Uint16(body[17:19])) * time.Second
	w.Profile = binary.BigEndian.Uint16(body[19:21])
	return w, nil
}

// PingLen is the size of a PING/PONG body: one 8-byte token.
const PingLen = 8

// PING and PONG share frame type 0x05 and an 8-byte token. The top bit of the
// token tells them apart: a PING has it clear, and the PONG echoes the token
// with it set. That way neither side can mistake a late PONG for a new PING
// and bounce it back forever.
const pongBit = 1 << 63

// NewPingToken returns a random token for a PING.
func NewPingToken() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint64(b[:]) &^ pongBit
}

// AppendPing appends a PING body carrying token.
func AppendPing(dst []byte, token uint64) []byte {
	return binary.BigEndian.AppendUint64(dst, token&^pongBit)
}

// AppendPong appends the PONG body that answers a PING carrying token.
func AppendPong(dst []byte, token uint64) []byte {
	return binary.BigEndian.AppendUint64(dst, token|pongBit)
}

// ParsePing decodes a PING/PONG body into its token (top bit cleared) and
// whether it is a PONG. A body of the wrong size is an error.
func ParsePing(body []byte) (token uint64, pong bool, err error) {
	if len(body) != PingLen {
		return 0, false, errors.New("wire: PING body must be 8 bytes")
	}
	v := binary.BigEndian.Uint64(body)
	return v &^ pongBit, v&pongBit != 0, nil
}

// LostLen is the size of a LOST body:
//
//	key index   4 bytes   the WireGuard receiver index, as a number
//	counter     8 bytes   the first datagram dropped
//	count       4 bytes   how many, counting up from it
//
// all big-endian. A receiver ignores bytes after these.
const LostLen = 4 + 8 + 4

// Lost names a run of WireGuard data packets, by the key index and counter
// in their headers, that the sender dropped and will never send: its queues
// were full, or the packets never reached it. A receiver that is merging
// lanes back into order stops waiting for them.
type Lost struct {
	Index   uint32
	Counter uint64
	Count   uint32
}

// AppendLost appends a LOST frame to dst.
func AppendLost(dst []byte, l Lost) []byte {
	dst = AppendHeader(dst, TypeLost, LostLen)
	dst = binary.BigEndian.AppendUint32(dst, l.Index)
	dst = binary.BigEndian.AppendUint64(dst, l.Counter)
	return binary.BigEndian.AppendUint32(dst, l.Count)
}

// ParseLost decodes a LOST body.
func ParseLost(body []byte) (Lost, error) {
	if len(body) < LostLen {
		return Lost{}, errors.New("wire: LOST body shorter than 16 bytes")
	}
	return Lost{
		Index:   binary.BigEndian.Uint32(body),
		Counter: binary.BigEndian.Uint64(body[4:]),
		Count:   binary.BigEndian.Uint32(body[12:]),
	}, nil
}

// CloseReason is the 1-byte body of a CLOSE frame.
type CloseReason byte

// Close reasons. The design leaves the codes open; these are the ones the
// client and server act on.
const (
	CloseNormal     CloseReason = 0 // the session is over; nothing went wrong
	CloseShutdown   CloseReason = 1 // the server is going away; start a new session
	CloseCredential CloseReason = 2 // the key_id expired or was revoked; get a new one
	CloseProtocol   CloseReason = 3 // the peer broke the protocol
)

func (r CloseReason) String() string {
	switch r {
	case CloseNormal:
		return "normal"
	case CloseShutdown:
		return "shutdown"
	case CloseCredential:
		return "credential"
	case CloseProtocol:
		return "protocol"
	}
	return "unknown"
}

// ParseClose decodes a CLOSE body. Unknown codes are returned as-is; an empty
// body counts as CloseNormal.
func ParseClose(body []byte) CloseReason {
	if len(body) == 0 {
		return CloseNormal
	}
	return CloseReason(body[0])
}
