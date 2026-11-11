package lane

import (
	"context"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// sentHello dials a listener that reads the first TLS record, the
// ClientHello, and hangs up, and returns that record.
func sentHello(t *testing.T) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err != nil {
			got <- nil
			return
		}
		body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
		if _, err := io.ReadFull(c, body); err != nil {
			got <- nil
			return
		}
		got <- append(hdr, body...)
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go handshake(ctx, raw, DialConfig{Addr: ln.Addr().String(), ServerName: "n1.cover.test", SNIMode: SNIOwn})
	hello := <-got
	if hello == nil {
		t.Fatal("no ClientHello arrived")
	}
	return hello
}

// sigAlgs returns the signature_algorithms a ClientHello offers.
func sigAlgs(t *testing.T, hello []byte) []utls.SignatureScheme {
	t.Helper()
	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range spec.Extensions {
		if e, ok := ext.(*utls.SignatureAlgorithmsExtension); ok {
			return e.SupportedSignatureAlgorithms
		}
	}
	t.Fatal("ClientHello has no signature_algorithms")
	return nil
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func TestHelloOffersChromesSignatureAlgorithms(t *testing.T) {
	// What Brave 1.99 (Chromium 157) sends, after a GREASE value.
	want := []utls.SignatureScheme{
		0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
	}
	grease := map[uint16]bool{}
	for range 8 {
		got := sigAlgs(t, sentHello(t))
		if len(got) == 0 || !isGREASE(uint16(got[0])) {
			t.Fatalf("signature_algorithms %04x: want a GREASE value first", got)
		}
		if !slices.Equal(got[1:], want) {
			t.Fatalf("signature_algorithms %04x, want GREASE then %04x", got, want)
		}
		grease[uint16(got[0])] = true
	}
	// Chrome draws the value for each connection. Eight alike would happen
	// one time in 16^7.
	if len(grease) < 2 {
		t.Fatalf("every ClientHello offered the same GREASE value: %v", grease)
	}
}

func TestWebSocketHelloOffersTheSameSignatureAlgorithms(t *testing.T) {
	for _, h2 := range []bool{true, false} {
		spec, err := chromeSpec(h2)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, ext := range spec.Extensions {
			if e, ok := ext.(*utls.SignatureAlgorithmsExtension); ok {
				found = len(e.SupportedSignatureAlgorithms) == 12 && e.SupportedSignatureAlgorithms[1] == sigMLDSA44
			}
		}
		if !found {
			t.Fatalf("h2 %v: ClientHello lacks Chrome's signature_algorithms", h2)
		}
	}
}
