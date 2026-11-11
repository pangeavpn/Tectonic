package lane

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"testing/iotest"
	"time"

	"github.com/pangeavpn/tectonic/wire"
)

// h2Settings is an HTTP/2 SETTINGS frame like the one a Go web server opens
// a connection with: six settings on stream 0.
func h2Settings() []byte {
	f := []byte{0, 0, 36, 0x4, 0, 0, 0, 0, 0}
	for id := byte(1); id <= 6; id++ {
		f = append(f, 0, id, 0, 0, 0x10, 0)
	}
	return f
}

func TestPastSettings(t *testing.T) {
	frames := wire.AppendFrame(nil, wire.TypeWelcome, bytes.Repeat([]byte{7}, 40))
	frames = wire.AppendFrame(frames, wire.TypeData, []byte("a datagram"))
	for name, tc := range map[string]struct {
		in   []byte
		want []byte
		err  error
	}{
		"settings first":     {in: append(h2Settings(), frames...), want: frames},
		"empty settings":     {in: append([]byte{0, 0, 0, 0x4, 0, 0, 0, 0, 0}, frames...), want: frames},
		"no settings":        {in: frames, want: frames},
		"settings only":      {in: h2Settings()},
		"nothing":            {},
		"another frame":      {in: []byte{0, 0, 8, 0x7, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}, err: errNotSettings},
		"an acknowledgement": {in: []byte{0, 0, 0, 0x4, 0x1, 0, 0, 0, 0}, err: errNotSettings},
		"cut in the header":  {in: h2Settings()[:5], err: io.ErrUnexpectedEOF},
		"cut in the frame":   {in: h2Settings()[:20], err: io.ErrUnexpectedEOF},
	} {
		for _, oneByte := range []bool{false, true} {
			var src io.Reader = bytes.NewReader(tc.in)
			if oneByte {
				src = iotest.OneByteReader(src)
			}
			got, err := io.ReadAll(&pastSettings{r: src})
			if !errors.Is(err, tc.err) || !bytes.Equal(got, tc.want) {
				t.Errorf("%s (one byte at a time: %v): read %d bytes, err %v; want %d bytes, err %v",
					name, oneByte, len(got), err, len(tc.want), tc.err)
			}
		}
	}
}

// A node is a web server until the client logs in, so on HTTP/2 its first
// bytes are a SETTINGS frame. The lane reads past it, and Dial does not
// wait for it.
func TestDialReadsPastTheServersSettings(t *testing.T) {
	n := newTestNode(t, nil) // for its certificates, credentials and login
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	release := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		tc := tls.Server(c, n.tlsConfig())
		if err := tc.Handshake(); err != nil {
			c.Close()
			return
		}
		<-release // Dial has returned before the server says anything
		tc.Write(h2Settings())
		cs := tc.ConnectionState()
		exp, err := cs.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
		if err != nil {
			c.Close()
			return
		}
		n.login(tc, bufio.NewReader(tc), exp, c)
	}()

	cfg := n.dialConfig(t, SNIOwn)
	cfg.Addr = ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	close(release)
	if w := waitWelcome(t, l); w.SessionID[0] != 0x42 {
		t.Fatalf("WELCOME = %+v", w)
	}
	sl := n.acceptLane(t)
	if !sl.Send([]byte("down")) {
		t.Fatal("server Send refused")
	}
}
