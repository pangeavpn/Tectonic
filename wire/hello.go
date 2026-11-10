package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"time"
)

// Version is the HELLO version this package speaks.
const Version = 1

// HELLO flags. Only bit 0 is defined by the design; bit 1 is how a client on
// cellular asks for the server's cellular lane limit (design §7: "6 by
// default, and 3 on cellular"). Receivers ignore bits they don't know.
const (
	FlagJoin     byte = 1 << 0 // join an existing session
	FlagCellular byte = 1 << 1 // the client is on a cellular network
)

// SessionIDLen is the size of a session_id.
const SessionIDLen = 16

// SessionID names a session. It belongs to the device, not to a connection,
// so lanes can come and go while it lives. All zeros means "no session".
type SessionID [SessionIDLen]byte

// IsZero reports whether s is the all-zeros "new session" value.
func (s SessionID) IsZero() bool { return s == SessionID{} }

// HELLO body layout (design §5):
//
//	version     1 byte    = 1
//	flags       1 byte    bit 0: join an existing session
//	key_id     20 bytes
//	session_id 16 bytes   zeros for a new session
//	timestamp   8 bytes   unix seconds
//	tag        32 bytes   HMAC-SHA256(lane_key, all fields above)
const (
	helloSignedLen = 1 + 1 + KeyIDLen + SessionIDLen + 8 // 46
	TagLen         = 32
	// HelloLen is the size of a HELLO body.
	HelloLen = helloSignedLen + TagLen // 78
)

// TimestampWindow is how far a HELLO's timestamp may be from the server's
// clock, in either direction.
const TimestampWindow = 120 * time.Second

// ErrHelloLength is returned for a HELLO body of the wrong size.
var ErrHelloLength = errors.New("wire: HELLO body must be 78 bytes")

// Hello is the login a client sends as the first frame on every lane.
type Hello struct {
	Version   byte
	Flags     byte
	KeyID     KeyID
	SessionID SessionID
	Timestamp uint64 // unix seconds
	Tag       [TagLen]byte
}

// Join reports whether the HELLO asks to join an existing session.
func (h *Hello) Join() bool { return h.Flags&FlagJoin != 0 }

// Cellular reports whether the client says it is on a cellular network.
func (h *Hello) Cellular() bool { return h.Flags&FlagCellular != 0 }

// AppendBody appends the 78-byte HELLO body to dst.
func (h *Hello) AppendBody(dst []byte) []byte {
	dst = h.appendSigned(dst)
	return append(dst, h.Tag[:]...)
}

func (h *Hello) appendSigned(dst []byte) []byte {
	dst = append(dst, h.Version, h.Flags)
	dst = append(dst, h.KeyID[:]...)
	dst = append(dst, h.SessionID[:]...)
	return binary.BigEndian.AppendUint64(dst, h.Timestamp)
}

// ParseHello decodes a HELLO body. It checks only the length; Verify and the
// server's login check decide whether the HELLO is any good.
func ParseHello(body []byte) (Hello, error) {
	var h Hello
	if len(body) != HelloLen {
		return h, ErrHelloLength
	}
	h.Version = body[0]
	h.Flags = body[1]
	copy(h.KeyID[:], body[2:22])
	copy(h.SessionID[:], body[22:38])
	h.Timestamp = binary.BigEndian.Uint64(body[38:46])
	copy(h.Tag[:], body[46:78])
	return h, nil
}

// ComputeTag returns HMAC-SHA256(lane_key, all fields before the tag).
func (h *Hello) ComputeTag(laneKey [KeyLen]byte) [TagLen]byte {
	var buf [helloSignedLen]byte
	m := hmac.New(sha256.New, laneKey[:])
	m.Write(h.appendSigned(buf[:0]))
	var tag [TagLen]byte
	m.Sum(tag[:0])
	return tag
}

// Sign sets the tag.
func (h *Hello) Sign(laneKey [KeyLen]byte) { h.Tag = h.ComputeTag(laneKey) }

// Verify reports, in constant time, whether the tag is correct.
func (h *Hello) Verify(laneKey [KeyLen]byte) bool {
	want := h.ComputeTag(laneKey)
	return subtle.ConstantTimeCompare(want[:], h.Tag[:]) == 1
}

// TimestampOK reports whether the timestamp is within TimestampWindow of now.
// It does not branch on the timestamp's value beyond the comparison itself.
func (h *Hello) TimestampOK(now time.Time) bool {
	ts := int64(h.Timestamp)
	if h.Timestamp > 1<<62 { // nonsense; avoid overflow below
		return false
	}
	d := now.Unix() - ts
	w := int64(TimestampWindow / time.Second)
	return d >= -w && d <= w
}
