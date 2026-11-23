package lane

import (
	"io"
	"net"
	"testing"
)

func TestWindowsReportsTheConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			io.Copy(io.Discard, c)
			c.Close()
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for range 64 {
		if _, err := c.Write(make([]byte, 16<<10)); err != nil {
			t.Fatal(err)
		}
	}
	rc, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	ti, ok := readTCPInfo(rc)
	if !ok {
		t.Fatal("SIO_TCP_INFO said nothing")
	}
	if ti.mss <= 0 || ti.cwnd <= 0 || ti.rtt <= 0 || ti.minRTT <= 0 || ti.minRTT > ti.rtt {
		t.Fatalf("SIO_TCP_INFO reported %+v", ti)
	}
}
