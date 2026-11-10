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

// errPinMismatch is returned when no certificate matches a pin.
var errPinMismatch = errors.New("lane: server certificate matches no pin")

// verifyPinned accepts the chain if its leaf matches a pin. Otherwise, if
// ipHost is set, it accepts a certificate issued for that IP address by a
// trusted root (None mode with a Let's Encrypt IP certificate).
func verifyPinned(rawCerts [][]byte, pins []Pin, roots *x509.CertPool, ipHost string) error {
	if len(rawCerts) == 0 {
		return errors.New("lane: server sent no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	got := PinOf(leaf)
	match := 0
	for _, p := range pins {
		match |= subtle.ConstantTimeCompare(got[:], p[:])
	}
	if match == 1 {
		return nil
	}
	if ipHost == "" {
		return errPinMismatch
	}
	inter := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		if c, err := x509.ParseCertificate(raw); err == nil {
			inter.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: ipHost, Roots: roots, Intermediates: inter}); err != nil {
		return fmt.Errorf("%w, and no valid IP certificate: %v", errPinMismatch, err)
	}
	return nil
}
