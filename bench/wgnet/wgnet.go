// Package wgnet runs a pair of in-process WireGuard peers whose tunnel
// interfaces are userspace gVisor stacks.
//
// Traffic between the two inner stacks (Peer.Net) is real WireGuard: it is
// encrypted by wireguard-go and leaves through each device's conn.Bind as UDP
// datagrams. Plugging a different Bind into either side puts any datagram
// transport underneath the tunnel: real loopback UDP (conn.NewStdNetBind),
// a bench/link socket, or a transport's net.PacketConn via PacketConnBind.
package wgnet

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/pangeavpn/tectonic/bench/internal/stacktune"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Inner tunnel addresses.
var (
	ClientAddr = netip.MustParseAddr("192.168.77.1")
	ServerAddr = netip.MustParseAddr("192.168.77.2")
)

// DefaultMTU is the tunnel MTU when PairConfig.MTU is zero, the usual
// WireGuard MTU for a 1500-byte path.
const DefaultMTU = 1420

// Peer is one WireGuard device and the userspace network behind it.
type Peer struct {
	Device *device.Device
	// Net opens sockets inside the tunnel (DialContextTCPAddrPort,
	// ListenTCPAddrPort, ListenUDPAddrPort, ...). Nil when PairConfig.TUN
	// supplied the device.
	Net *netstack.Net
	// Stack is the gVisor stack behind Net: CUBIC, SACK, RACK and 4 MiB
	// socket buffers (see internal/stacktune). Change protocol options here
	// before opening the sockets they should apply to.
	Stack *stack.Stack
	// Addr is the peer's tunnel address.
	Addr netip.Addr
	// PublicKey is the peer's WireGuard public key.
	PublicKey [32]byte
}

// PairConfig describes a client/server pair of peers.
type PairConfig struct {
	// ClientBind carries the client's encrypted datagrams. Nil means a
	// conn.NewStdNetBind on a random real UDP port.
	ClientBind conn.Bind
	// ServerBind carries the server's. Nil means a conn.NewStdNetBind on
	// ServerListenPort, which is what a Tectonic server forwards to on
	// loopback.
	ServerBind conn.Bind
	// ServerListenPort is the server's listen_port; 0 picks one at random.
	// Read the result back with Peer.ListenPort.
	ServerListenPort uint16
	// ServerEndpoint is the address the client sends to, as parsed by
	// ClientBind.ParseEndpoint. Empty means "127.0.0.1:<server port>",
	// which suits a StdNetBind server. A client whose bind ignores the
	// destination (a transport's PacketConn) can use any valid "ip:port".
	ServerEndpoint string
	// MTU is the tunnel MTU of both peers. Zero means DefaultMTU.
	MTU int
	// PersistentKeepalive is the client's keepalive interval in seconds;
	// zero disables it.
	PersistentKeepalive int
	// Logger receives wireguard-go's log; nil discards it.
	Logger *device.Logger
	// TUN, if set, supplies each peer's tunnel device in place of a gVisor
	// netstack: a real kernel TUN, for instance, so that the TCP inside the
	// tunnel is the kernel's. server reports which peer is asking. Peers
	// made this way have no Net or Stack; open sockets through whatever
	// owns the device.
	TUN func(server bool, addr netip.Addr, mtu int) (tun.Device, error)
}

// NewPair creates, configures and starts a server peer and then a client
// peer pointed at it. The server has no endpoint configured and learns the
// client's from its first handshake. The tunnel comes up on the client's
// first packet (or first keepalive).
func NewPair(cfg PairConfig) (client, server *Peer, err error) {
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.Logger == nil {
		cfg.Logger = device.NewLogger(device.LogLevelSilent, "")
	}
	if cfg.ServerBind == nil {
		cfg.ServerBind = conn.NewStdNetBind()
	}
	if cfg.ClientBind == nil {
		cfg.ClientBind = conn.NewStdNetBind()
	}
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	server, err = newPeer(ServerAddr, cfg.MTU, cfg.ServerBind, cfg.Logger, serverKey, cfg.TUN, true)
	if err != nil {
		return nil, nil, fmt.Errorf("wgnet: server: %w", err)
	}
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", hex.EncodeToString(serverKey.Bytes()))
	fmt.Fprintf(&uapi, "listen_port=%d\n", cfg.ServerListenPort)
	fmt.Fprintf(&uapi, "public_key=%s\n", hex.EncodeToString(clientKey.PublicKey().Bytes()))
	fmt.Fprintf(&uapi, "allowed_ip=%s/32\n", ClientAddr)
	if err := server.configure(uapi.String()); err != nil {
		server.Close()
		return nil, nil, fmt.Errorf("wgnet: server: %w", err)
	}

	endpoint := cfg.ServerEndpoint
	if endpoint == "" {
		port, err := server.ListenPort()
		if err != nil {
			server.Close()
			return nil, nil, fmt.Errorf("wgnet: server: %w", err)
		}
		endpoint = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port).String()
	}

	client, err = newPeer(ClientAddr, cfg.MTU, cfg.ClientBind, cfg.Logger, clientKey, cfg.TUN, false)
	if err != nil {
		server.Close()
		return nil, nil, fmt.Errorf("wgnet: client: %w", err)
	}
	uapi.Reset()
	fmt.Fprintf(&uapi, "private_key=%s\n", hex.EncodeToString(clientKey.Bytes()))
	fmt.Fprintf(&uapi, "public_key=%s\n", hex.EncodeToString(serverKey.PublicKey().Bytes()))
	fmt.Fprintf(&uapi, "endpoint=%s\n", endpoint)
	fmt.Fprintf(&uapi, "allowed_ip=%s/32\n", ServerAddr)
	fmt.Fprintf(&uapi, "persistent_keepalive_interval=%d\n", cfg.PersistentKeepalive)
	if err := client.configure(uapi.String()); err != nil {
		client.Close()
		server.Close()
		return nil, nil, fmt.Errorf("wgnet: client: %w", err)
	}
	return client, server, nil
}

func newPeer(addr netip.Addr, mtu int, bind conn.Bind, log *device.Logger, key *ecdh.PrivateKey,
	mkTUN func(bool, netip.Addr, int) (tun.Device, error), server bool) (*Peer, error) {
	if mkTUN != nil {
		dev, err := mkTUN(server, addr, mtu)
		if err != nil {
			return nil, err
		}
		p := &Peer{Device: device.NewDevice(dev, bind, log), Addr: addr}
		copy(p.PublicKey[:], key.PublicKey().Bytes())
		return p, nil
	}
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, mtu)
	if err != nil {
		return nil, err
	}
	s, err := netstackStack(tnet)
	if err != nil {
		tunDev.Close()
		return nil, err
	}
	// Unlike the outer link, the tunnel may see reordering (Tectonic's
	// lanes deliver unordered), so keep gVisor's default RACK loss
	// detection, as real client OSes do.
	if err := stacktune.Tune(s, true); err != nil {
		tunDev.Close()
		return nil, err
	}
	p := &Peer{
		Device: device.NewDevice(tunDev, bind, log),
		Net:    tnet,
		Stack:  s,
		Addr:   addr,
	}
	copy(p.PublicKey[:], key.PublicKey().Bytes())
	return p, nil
}

func (p *Peer) configure(uapi string) error {
	if err := p.Device.IpcSet(uapi); err != nil {
		return err
	}
	return p.Device.Up()
}

// ListenPort reports the UDP port the peer's bind is listening on: the real
// port for a StdNetBind, or whatever a custom bind's Open returned.
func (p *Peer) ListenPort() (uint16, error) {
	cfg, err := p.Device.IpcGet()
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(cfg, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err := strconv.ParseUint(v, 10, 16)
			return uint16(port), err
		}
	}
	return 0, errors.New("wgnet: device reports no listen_port")
}

// Close shuts the device down, which closes its bind and its tunnel stack.
// It does not close a PacketConn behind a PacketConnBind.
func (p *Peer) Close() {
	p.Device.Close()
}

// netstackStack digs the *stack.Stack out of a netstack.Net, which does not
// export it, so the inner TCP can be tuned like the outer stacks. It relies
// on the field name in the pinned wireguard-go version and fails loudly if
// that ever changes.
func netstackStack(n *netstack.Net) (*stack.Stack, error) {
	f := reflect.ValueOf(n).Elem().FieldByName("stack")
	if !f.IsValid() || f.Type() != reflect.TypeFor[*stack.Stack]() {
		return nil, errors.New("wgnet: netstack.Net has no stack field; update netstackStack for this wireguard-go version")
	}
	return *(**stack.Stack)(unsafe.Pointer(f.UnsafeAddr())), nil
}
