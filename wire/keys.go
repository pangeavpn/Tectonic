package wire

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

// Labels from design §5. Changing any of them is a protocol change.
const (
	// ExporterLabel is the TLS exporter label that binds HELLO to its TLS
	// connection. The exporter context is empty and the output is 32 bytes.
	ExporterLabel = "EXPORTER-tectonic-hello"
	// ExporterLen is the exporter output length.
	ExporterLen = 32

	deviceKeyLabel = "tectonic device v1"
	laneKeyInfo    = "tectonic lane v1"
)

// KeyLen is the size of device and lane keys.
const KeyLen = 32

// KeyIDLen is the size of a key_id: 16 random bytes and a 4-byte expiry.
const KeyIDLen = 20

// KeyID identifies a device credential. Its last four bytes are the expiry as
// a big-endian count of days since the Unix epoch.
//
//	key_id = 16 random bytes ‖ expiry (uint32, unix days)
type KeyID [KeyIDLen]byte

// NewKeyID returns a fresh key_id that stays valid through the UTC day
// containing expiry.
func NewKeyID(expiry time.Time) (KeyID, error) {
	var id KeyID
	if _, err := rand.Read(id[:16]); err != nil {
		return id, err
	}
	binary.BigEndian.PutUint32(id[16:], UnixDay(expiry))
	return id, nil
}

// ExpiryDay is the last Unix day on which the key_id is valid.
func (k KeyID) ExpiryDay() uint32 { return binary.BigEndian.Uint32(k[16:]) }

// Expired reports whether now is after the key_id's expiry day.
func (k KeyID) Expired(now time.Time) bool { return UnixDay(now) > k.ExpiryDay() }

// String returns the key_id in hex, the form revocation lists use.
func (k KeyID) String() string { return hex.EncodeToString(k[:]) }

// ParseKeyID parses a key_id from its hex form.
func ParseKeyID(s string) (KeyID, error) {
	var k KeyID
	b, err := hex.DecodeString(s)
	if err != nil {
		return k, err
	}
	if len(b) != KeyIDLen {
		return k, errors.New("wire: key_id must be 20 bytes")
	}
	copy(k[:], b)
	return k, nil
}

// UnixDay is the number of whole days between the Unix epoch and t, in UTC.
func UnixDay(t time.Time) uint32 {
	s := t.Unix()
	if s < 0 {
		return 0
	}
	return uint32(s / 86400)
}

// DeviceKey derives a device's key from the node secret, so a node needs no
// device database:
//
//	device_key = HMAC-SHA256(node_secret, "tectonic device v1" ‖ key_id)
func DeviceKey(nodeSecret []byte, id KeyID) [KeyLen]byte {
	m := hmac.New(sha256.New, nodeSecret)
	m.Write([]byte(deviceKeyLabel))
	m.Write(id[:])
	var k [KeyLen]byte
	m.Sum(k[:0])
	return k
}

// LaneKey derives the key that signs one lane's HELLO from the device key and
// that lane's TLS exporter value:
//
//	lane_key = HKDF-SHA256(ikm = device_key, salt = exporter, info = "tectonic lane v1")
func LaneKey(deviceKey [KeyLen]byte, exporter []byte) [KeyLen]byte {
	b, err := hkdf.Key(sha256.New, deviceKey[:], exporter, laneKeyInfo, KeyLen)
	if err != nil {
		// Only possible for an output longer than 255 hash blocks.
		panic(err)
	}
	var k [KeyLen]byte
	copy(k[:], b)
	return k
}
