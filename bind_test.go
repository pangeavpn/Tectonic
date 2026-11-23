package tectonic_test

import (
	"context"
	"fmt"
	"testing"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/pangeavpn/tectonic"
)

func TestWireGuardThroughABind(t *testing.T) {
	cPriv, cPub := wgKey(t)
	sPriv, sPub := wgKey(t)
	srv := newWG(t, fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s/32\n", sPriv, cPub, clientIP))
	n := startNode(t, fmt.Sprintf("127.0.0.1:%d", srv.port(t)), nil)
	c, err := tectonic.Dial(context.Background(), tectonic.Config{Profile: n.profile(t), RootCAs: certs().roots, SNIMode: tectonic.SNIOwn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ct := tuntest.NewChannelTUN()
	dev := device.NewDevice(ct.TUN(), tectonic.NewBind(c), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\nallowed_ip=%s/32\nendpoint=node:443\n", cPriv, sPub, serverIP)); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	ping := tuntest.Ping(serverIP, clientIP)
	ct.Outbound <- ping // WireGuard handshakes through the bind, then sends it
	expectPacket(t, srv.tun.Inbound, ping)
	pong := tuntest.Ping(clientIP, serverIP)
	srv.tun.Outbound <- pong
	expectPacket(t, ct.Inbound, pong)
}
