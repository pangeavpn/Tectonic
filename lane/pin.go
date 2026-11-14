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

// verifyPinned accepts the chain if its leaf matches a pin. With no pins
// and ipHost set, it accepts a certificate issued for that IP address by a
// trusted root instead (None mode with a Let's Encrypt IP certificate).
//
// Pins rule the IP certificate out. A TLS interceptor whose CA the device
// trusts can issue a certificate for any address, so accepting one beside
// the pins would hand it the login the pins are there to keep from it. A
// node with pins that serves an IP certificate has its key pinned too.
func verifyPinned(rawCerts [][]byte, pins []Pin, roots *x509.CertPool, ipHost string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("%w: the server sent none", ErrCertificate)
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCertificate, err)
	}
	if len(pins) > 0 {
		got := PinOf(leaf)
		match := 0
		for _, p := range pins {
			match |= subtle.ConstantTimeCompare(got[:], p[:])
		}
		if match == 1 {
			return nil
		}
		return errPinMismatch
	}
	if ipHost == "" {
		return fmt.Errorf("%w: no pins, and no IP address to check it for", ErrCertificate)
	}
	inter := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		if c, err := x509.ParseCertificate(raw); err == nil {
			inter.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: ipHost, Roots: roots, Intermediates: inter}); err != nil {
		return fmt.Errorf("%w: no pins, and no valid IP certificate: %w", ErrCertificate, err)
	}
	return nil
}
