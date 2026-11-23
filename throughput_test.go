package tectonic_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/pangeavpn/tectonic"
)

// BenchmarkTunnel moves full-size packets through WireGuard and Tectonic over loopback, where what
// each packet costs in the process, not the path, decides how many get through.
func BenchmarkTunnel(b *testing.B) {
	for _, via := range []string{"relay", "bind"} {
		for _, dir := range []string{"up", "down"} {
			b.Run(via+"/"+dir, func(b *testing.B) { benchTunnel(b, via == "bind", dir == "up") })
		}
	}
}

func benchTunnel(b *testing.B, direct, up bool) {
	cPriv, cPub := wgKey(b)
	sPriv, sPub := wgKey(b)
	srv := newWG(b, fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s/32\n", sPriv, cPub, clientIP))
	n := startNode(b, fmt.Sprintf("127.0.0.1:%d", srv.port(b)), nil)
	c, err := tectonic.Dial(context.Background(), tectonic.Config{Profile: n.profile(b), RootCAs: certs().roots,
		SNIMode: tectonic.SNIOwn, Network: "bench"})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { c.Close() })
	var bind conn.Bind = conn.NewStdNetBind()
	endpoint := "tectonic:443"
	if direct {
		bind = tectonic.NewBind(c)
	} else {
		endpoint = bridge(b, c).String()
	}
	ct := tuntest.NewChannelTUN()
	dev := device.NewDevice(ct.TUN(), bind, device.NewLogger(device.LogLevelSilent, ""))
	b.Cleanup(dev.Close)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s/32\nendpoint=%s\n",
		cPriv, sPub, serverIP, endpoint)); err != nil {
		b.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		b.Fatal(err)
	}
	client := &wgPeer{dev: dev, tun: ct}

	from, to, src, dst := client, srv, clientIP, serverIP
	if !up {
		from, to, src, dst = srv, client, serverIP, clientIP
	}
	// The handshake: until a packet makes it across, nothing is measured.
	ready := false
	for deadline := time.Now().Add(15 * time.Second); !ready && time.Now().Before(deadline); {
		client.tun.Outbound <- udpPacket(clientIP, serverIP, 100)
		select {
		case <-srv.tun.Inbound:
			ready = true
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !ready {
		b.Fatal("the tunnel never came up")
	}
	pkt := udpPacket(src, dst, 1380) // a full packet at WireGuard's MTU of 1420
	got := make(chan struct{}, 1)
	done := make(chan struct{})
	defer close(done)
	var recvd atomic.Int64
	go func() {
		for {
			select {
			case <-to.tun.Inbound:
				recvd.Add(1)
				select {
				case got <- struct{}{}:
				default:
				}
			case <-done:
				return
			}
		}
	}()
	const window = 512
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	sent, delivered := 0, 0
	for delivered < b.N {
		for sent-delivered < window && sent < b.N+window {
			from.tun.Outbound <- pkt
			sent++
		}
		select {
		case <-got:
		case <-time.After(100 * time.Millisecond):
			sent = delivered // what is still out after this long is lost
		}
		delivered = int(recvd.Load())
	}
	b.StopTimer()
}

// udpPacket is an IPv4 UDP packet of size bytes from src to dst.
func udpPacket(src, dst netip.Addr, size int) []byte {
	p := make([]byte, size)
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:], uint16(size))
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	binary.BigEndian.PutUint16(p[10:], ^uint16(sum+sum>>16))
	binary.BigEndian.PutUint16(p[20:], 9)
	binary.BigEndian.PutUint16(p[22:], 9)
	binary.BigEndian.PutUint16(p[24:], uint16(size-20))
	return p
}
