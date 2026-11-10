package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic"
)

// capture runs f with os.Stdout redirected and returns what it printed.
func capture(t *testing.T, f func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	ferr := f()
	os.Stdout = old
	w.Close()
	out, _ := io.ReadAll(r)
	if ferr != nil {
		t.Fatal(ferr)
	}
	return string(out)
}

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestServeIssuePin(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "node_secret")
	os.WriteFile(secret, []byte("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"), 0o600)
	site := filepath.Join(dir, "site")
	os.Mkdir(site, 0o755)
	os.WriteFile(filepath.Join(site, "index.html"), []byte("<h1>Bakery</h1>"), 0o644)

	// A stand-in for the node's WireGuard: echo every datagram.
	wg, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := wg.ReadFromUDP(buf)
			if err != nil {
				return
			}
			wg.WriteToUDP(buf[:n], a)
		}
	}()

	addr := freePort(t)
	defCert := filepath.Join(dir, "default.crt")
	done := make(chan error, 1)
	go func() {
		done <- serve([]string{
			"-listen", addr, "-secret-file", secret,
			"-default-cert", defCert, "-default-key", filepath.Join(dir, "default.key"),
			"-cover-dir", site, "-wireguard", wg.LocalAddr().String(), "-log-level", "error",
		})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server never listened")
		}
		time.Sleep(10 * time.Millisecond)
	}

	pinOut := strings.TrimSpace(capture(t, func() error { return pin([]string{"-cert", defCert}) }))
	if len(pinOut) != 44 {
		t.Fatalf("pin = %q", pinOut)
	}
	issued := capture(t, func() error {
		return issue([]string{"-secret-file", secret, "-days", "3", "-node", addr, "-pin", pinOut})
	})
	p, err := tectonic.ParseProfile([]byte(issued))
	if err != nil {
		t.Fatalf("issue printed %q: %v", issued, err)
	}

	// A client with nothing but the issued profile: no cover domain, so
	// Borrowed or None mode, checked by the pin.
	p.BorrowedSNI = []string{"www.example.com"}
	c, err := tectonic.Dial(context.Background(), tectonic.Config{Profile: p})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.WriteTo([]byte("hello node"), nil)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	n, _, err := c.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "hello node" {
		t.Fatalf("echo: %q %v", buf[:n], err)
	}

	// Everyone else sees the cover website.
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := hc.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "<h1>Bakery</h1>" {
		t.Fatalf("cover site served %q", body)
	}

	// SIGHUP reloads; SIGTERM shuts down cleanly.
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	time.Sleep(50 * time.Millisecond)
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

func TestReadSecret(t *testing.T) {
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		content string
		want    int
		ok      bool
	}{
		"hex":   {"00112233445566778899aabbccddeeff\n", 16, true},
		"raw":   {"a long raw secret string", 24, true},
		"short": {"short", 0, false},
	} {
		f := filepath.Join(dir, name)
		os.WriteFile(f, []byte(tc.content), 0o600)
		b, err := readSecret(f)
		if (err == nil) != tc.ok || (tc.ok && len(b) != tc.want) {
			t.Errorf("%s: %d bytes, %v", name, len(b), err)
		}
	}
	if _, err := readSecret(""); err == nil {
		t.Error("empty path accepted")
	}
}

func TestDefaultCertIsNeverSilentlyReplaced(t *testing.T) {
	dir := t.TempDir()
	c := &certFiles{cert: filepath.Join(dir, "d.crt"), key: filepath.Join(dir, "d.key")}
	log := discardLogger()
	if err := ensureDefaultCert(c, log); err != nil {
		t.Fatal(err)
	}
	if err := c.reload(); err != nil {
		t.Fatal(err)
	}
	first := c.pin()
	if err := ensureDefaultCert(c, log); err != nil {
		t.Fatal(err)
	}
	c.reload()
	if c.pin() != first {
		t.Fatal("pin changed although both files existed")
	}
	os.Remove(c.key)
	if err := ensureDefaultCert(c, log); err == nil {
		t.Fatal("regenerated with only the certificate present")
	}
}

func TestIssueOutputIsAProfile(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "s")
	os.WriteFile(secret, []byte("0123456789abcdef0123456789abcdef"), 0o600)
	out := capture(t, func() error { return issue([]string{"-secret-file", secret}) })
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil || m["key_id"] == nil || m["device_key"] == nil {
		t.Fatalf("issue printed %q", out)
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
