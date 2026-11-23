package lane

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestLaneThatHearsNothingBecomesSuspect(t *testing.T) {
	a, b := net.Pipe()
	go io.Copy(io.Discard, b) // a path that swallows everything, as a dead one does
	l := New(a, nil, Options{Role: Server, InitialRTT: 10 * time.Millisecond})
	t.Cleanup(func() { l.Close(); b.Close() })
	if err := l.Start(nil); err != nil {
		t.Fatal(err)
	}
	if l.Suspect() {
		t.Fatal("suspect before its PING could be answered")
	}
	time.Sleep(suspectMin + 100*time.Millisecond)
	if !l.Suspect() {
		t.Fatalf("not suspect after %v without a PONG", suspectMin)
	}
	if eta := l.ETA(100); eta < suspectMin {
		t.Fatalf("ETA %v on a lane that has heard nothing for over %v", eta, suspectMin)
	}
}

func TestLanesThatAnswerAreNotSuspect(t *testing.T) {
	a, b := tcpPair(t)
	la := New(a, nil, Options{Role: Server, InitialRTT: 10 * time.Millisecond})
	lb := New(b, nil, Options{Role: Server, InitialRTT: 10 * time.Millisecond})
	t.Cleanup(func() { la.Close(); lb.Close() })
	if err := lb.Start(nil); err != nil {
		t.Fatal(err)
	}
	if err := la.Start(nil); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(suspectMin + 200*time.Millisecond); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		la.Send(make([]byte, 1400))
		if la.Suspect() {
			t.Fatal("a lane whose PINGs are answered became suspect")
		}
	}
}
