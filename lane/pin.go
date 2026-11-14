package lane

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Pin is the SHA-256 of a certificate's SubjectPublicKeyInfo. In Borrowed and
// None mode the client checks the node's default certificate against the
// pins the hub supplies, because the certificate can't match a borrowed name
// (design §9).
type Pin [sha256.Size]byte

// PinOf returns the pin for cert.
func PinOf(cert *x509.Certificate) Pin { return sha256.Sum256(cert.RawSubjectPublicKeyInfo) }

// ParsePin parses a base64 pin, optionally prefixed with "sha256/".
func ParsePin(s string) (Pin, error) {
	var p Pin
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "sha256/"))
	if err != nil {
		return p, fmt.Errorf("lane: bad pin %q: %w", s, err)
	}
	if len(b) != len(p) {
		return p, fmt.Errorf("lane: pin %q is %d bytes, want 32", s, len(b))
	}
	copy(p[:], b)
	return p, nil
}

// String returns the pin in base64.
func (p Pin) String() string { return base64.StdEncoding.EncodeToString(p[:]) }

// ErrCertificate means the server's certificate failed the lane's check: it
// was not valid for the name, or its key matched no pin. Something other
// than the node finished the TLS handshake, such as a TLS interceptor, a
// captive portal or the wrong server, and the lane sent it nothing.
var ErrCertificate = errors.New("lane: the server's certificate failed the check")

// errPinMismatch is returned when no certificate matches a pin.
var errPinMismatch = fmt.Errorf("%w: it matches no pin", ErrCertificate)

// ErrIntercepted means the certificate failed the check and what was served
// instead is a chain the device itself trusts for the name the lane asked
// for: a TLS interceptor with a CA in the device's own store. It wraps
// ErrCertificate, so a caller that does not care still sees that.
//
// The difference matters for the CDN carrier, whose edge the client checks
// by name alone: an interceptor the device trusts passes that check, where
// a captive portal's certificate or a censor's self-signed one cannot. So
// only this says anything about the CDN (design §9).
var ErrIntercepted = fmt.Errorf("%w: and a certificate the device trusts was served in its place", ErrCertificate)

// check is what verifyPinned checks a chain against.
type check struct {
	pins  []Pin
	roots *x509.CertPool
	// name is what the lane asked for: the server name it sent, or the
	// address it dialled where it sent none. A chain that the roots make
	// valid for it is an interceptor's, not the wrong server's.
	name string
	// ipHost is None mode's dialled IP address, which may legitimately
	// hold an IP certificate where the hub sends no pins.
	ipHost string
	// verified says the handshake made its own check of the chain and it
	// passed, so a mismatch is an interceptor's whatever the roots here
	// would say.
	verified bool
}

// verifyPinned accepts the chain if its leaf matches a pin. With no pins
// and ipHost set, it accepts a certificate issued for that IP address by a
// trusted root instead (None mode with a Let's Encrypt IP certificate).
//
// Pins rule the IP certificate out. A TLS interceptor whose CA the device
// trusts can issue a certificate for any address, so accepting one beside
// the pins would hand it the login the pins are there to keep from it. A
// node with pins that serves an IP certificate has its key pinned too.
func verifyPinned(rawCerts [][]byte, c check) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("%w: the server sent none", ErrCertificate)
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCertificate, err)
	}
	if len(c.pins) > 0 {
		got := PinOf(leaf)
		match := 0
		for _, p := range c.pins {
			match |= subtle.ConstantTimeCompare(got[:], p[:])
		}
		if match == 1 {
			return nil
		}
		if c.verified || trustedFor(leaf, rawCerts[1:], c.roots, c.name) {
			return ErrIntercepted
		}
		return errPinMismatch
	}
	if c.ipHost == "" {
		return fmt.Errorf("%w: no pins, and no IP address to check it for", ErrCertificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       c.ipHost,
		Roots:         c.roots,
		Intermediates: intermediates(rawCerts[1:]),
	}); err != nil {
		return fmt.Errorf("%w: no pins, and no valid IP certificate: %w", ErrCertificate, err)
	}
	return nil
}

// trustedFor reports whether the roots make leaf valid for name. With no
// name to check it for there is nothing to tell an interceptor from the
// wrong server, so it reports false.
func trustedFor(leaf *x509.Certificate, rest [][]byte, roots *x509.CertPool, name string) bool {
	if name == "" {
		return false
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       name,
		Roots:         roots,
		Intermediates: intermediates(rest),
	})
	return err == nil
}

func intermediates(rest [][]byte) *x509.CertPool {
	inter := x509.NewCertPool()
	for _, raw := range rest {
		if c, err := x509.ParseCertificate(raw); err == nil {
			inter.AddCert(c)
		}
	}
	return inter
}
