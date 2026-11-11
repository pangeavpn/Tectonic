package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// newDefaultCert creates a default certificate called name in a fresh
// directory and loads it.
func newDefaultCert(t *testing.T, name string) (*certFiles, *x509.Certificate) {
	t.Helper()
	dir := t.TempDir()
	c := &certFiles{cert: filepath.Join(dir, "d.crt"), key: filepath.Join(dir, "d.key"), name: name}
	if err := ensureDefaultCert(c, discardLogger()); err != nil {
		t.Fatal(err)
	}
	if err := c.reload(); err != nil {
		t.Fatal(err)
	}
	return c, c.cur.Load().Leaf
}

// The default certificate goes to anyone who connects without the cover
// name. It must not tell them the machine's hostname.
func TestDefaultCertDoesNotNameTheMachine(t *testing.T) {
	c, leaf := newDefaultCert(t, "")
	if leaf.Subject.CommonName != "localhost" || !slices.Equal(leaf.DNSNames, []string{"localhost"}) || len(leaf.IPAddresses) != 0 {
		t.Fatalf("subject %q, DNS names %q, addresses %v; want localhost", leaf.Subject.CommonName, leaf.DNSNames, leaf.IPAddresses)
	}
	if leaf.Issuer.CommonName != leaf.Subject.CommonName {
		t.Fatalf("issuer %q: not self-signed under the same name", leaf.Issuer.CommonName)
	}
	host, _ := os.Hostname()
	if host == "" || strings.EqualFold(host, "localhost") {
		t.Skip("this machine's hostname says nothing")
	}
	if bytes.Contains(bytes.ToLower(leaf.Raw), []byte(strings.ToLower(host))) {
		t.Fatalf("the certificate contains this machine's hostname, %q", host)
	}
	if c.names(host) {
		t.Fatalf("names(%q) is true of a certificate called localhost", host)
	}
}

func TestDefaultCertName(t *testing.T) {
	_, leaf := newDefaultCert(t, "www.example.net")
	if leaf.Subject.CommonName != "www.example.net" || !slices.Equal(leaf.DNSNames, []string{"www.example.net"}) || len(leaf.IPAddresses) != 0 {
		t.Fatalf("subject %q, DNS names %q, addresses %v", leaf.Subject.CommonName, leaf.DNSNames, leaf.IPAddresses)
	}
	// An address goes in as an address, not as a DNS name.
	_, leaf = newDefaultCert(t, "192.0.2.7")
	if leaf.Subject.CommonName != "192.0.2.7" || len(leaf.DNSNames) != 0 ||
		len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.IPv4(192, 0, 2, 7)) {
		t.Fatalf("subject %q, DNS names %q, addresses %v", leaf.Subject.CommonName, leaf.DNSNames, leaf.IPAddresses)
	}
}

// Clients pin the default certificate, so one that exists is never
// rewritten, whatever name is asked for now.
func TestDefaultCertNameLeavesAnExistingCertificateAlone(t *testing.T) {
	c, _ := newDefaultCert(t, "old-name.example")
	pin := c.pin()
	certPEM, _ := os.ReadFile(c.cert)
	keyPEM, _ := os.ReadFile(c.key)

	c.name = "new-name.example"
	if err := ensureDefaultCert(c, discardLogger()); err != nil {
		t.Fatal(err)
	}
	if err := c.reload(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(c.cert); !bytes.Equal(got, certPEM) {
		t.Fatal("the certificate file was rewritten")
	}
	if got, _ := os.ReadFile(c.key); !bytes.Equal(got, keyPEM) {
		t.Fatal("the key file was rewritten")
	}
	if c.pin() != pin || c.cur.Load().Leaf.Subject.CommonName != "old-name.example" {
		t.Fatalf("pin %s, subject %q: the certificate changed", c.pin(), c.cur.Load().Leaf.Subject.CommonName)
	}
}

// names is how serve notices a certificate from before, which was called
// after the machine.
func TestCertNamesTheMachine(t *testing.T) {
	c, _ := newDefaultCert(t, "node-17.internal")
	for host, want := range map[string]bool{
		"node-17.internal": true,
		"NODE-17.Internal": true,
		"node-17":          false,
		"localhost":        false,
		"":                 false,
	} {
		if got := c.names(host); got != want {
			t.Errorf("names(%q) = %v, want %v", host, got, want)
		}
	}
	if (&certFiles{}).names("node-17.internal") {
		t.Error("names is true with no certificate loaded")
	}
}

// What a probe that sends no server name is shown, with and without
// -default-cert-name.
func TestServeDefaultCertNameFlag(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "localhost"},
		{[]string{"-default-cert-name", "www.example.net"}, "www.example.net"},
	} {
		dir := t.TempDir()
		secret := filepath.Join(dir, "node_secret")
		os.WriteFile(secret, []byte("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"), 0o600)
		addr := freePort(t)
		done := make(chan error, 1)
		go func() {
			done <- serve(append([]string{
				"-listen", addr, "-secret-file", secret,
				"-default-cert", filepath.Join(dir, "default.crt"), "-default-key", filepath.Join(dir, "default.key"),
				"-cover-dir", dir, "-wireguard", "127.0.0.1:9", "-log-level", "error",
			}, tc.args...))
		}()
		var conn *tls.Conn
		deadline := time.Now().Add(5 * time.Second)
		for {
			var err error
			if conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}); err == nil {
				break
			}
			select {
			case err := <-done:
				t.Fatalf("serve returned %v", err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("server never answered: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		leaf := conn.ConnectionState().PeerCertificates[0]
		conn.Close()
		if leaf.Subject.CommonName != tc.want || !slices.Equal(leaf.DNSNames, []string{tc.want}) {
			t.Errorf("%v: the probe was shown subject %q, DNS names %q; want %q", tc.args, leaf.Subject.CommonName, leaf.DNSNames, tc.want)
		}
		syscall.Kill(os.Getpid(), syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("serve returned %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("serve did not stop on SIGTERM")
		}
	}
}
