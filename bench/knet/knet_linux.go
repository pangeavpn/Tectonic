//go:build linux

package knet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/pangeavpn/tectonic/bench/link"
)

// envMarker tells the re-executed process that it is already inside the
// bench's namespaces.
const envMarker = "TECTONIC_BENCH_NETNS"

// Supported reports whether this platform can build a kernel path.
func Supported() error { return nil }

// InNamespace reports whether this process is the one Reexec started.
func InNamespace() bool { return os.Getenv(envMarker) != "" }

// Reexec runs this program again, with the same arguments, in a new user
// namespace (where the caller is root) and a new network namespace, and
// returns its exit code. It does nothing and returns ran=false when called
// from the re-executed process.
func Reexec() (code int, ran bool, err error) {
	if InNamespace() {
		return 0, false, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return 0, false, err
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), envMarker+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		Pdeathsig:   syscall.SIGKILL,
	}
	// Ctrl-C reaches the child too (same process group); let it finish.
	signal.Ignore(os.Interrupt)
	defer signal.Reset(os.Interrupt)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), true, nil
		}
		return 0, false, fmt.Errorf("knet: re-exec in a user namespace: %w (are unprivileged user namespaces enabled?)", err)
	}
	return 0, true, nil
}

// --- network namespaces ---

// netNS is one network namespace, pinned open by a file.
type netNS struct {
	name string
	f    *os.File
	self bool // the process's own namespace: no need to switch
}

func selfNS() (*netNS, error) {
	f, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return nil, err
	}
	return &netNS{name: "server", f: f, self: true}, nil
}

// newNS creates a network namespace. The thread that creates it is
// discarded afterwards: its goroutine exits still locked.
func newNS(name string) (*netNS, error) {
	type res struct {
		f   *os.File
		err error
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread exits with us
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ch <- res{err: fmt.Errorf("knet: unshare %s: %w", name, err)}
			return
		}
		f, err := os.Open("/proc/thread-self/ns/net")
		ch <- res{f, err}
	}()
	r := <-ch
	if r.err != nil {
		return nil, r.err
	}
	return &netNS{name: name, f: r.f}, nil
}

// do runs f on an OS thread in n. Sockets f opens stay in n for life;
// goroutines f starts do not run in n.
func (n *netNS) do(f func() error) error {
	if n.self {
		return f()
	}
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: a switched thread must not be reused
		if err := unix.Setns(int(n.f.Fd()), unix.CLONE_NEWNET); err != nil {
			errc <- fmt.Errorf("knet: enter %s: %w", n.name, err)
			return
		}
		errc <- f()
	}()
	return <-errc
}

// run runs a command in n. extra become the command's fds 3, 4, ...
func (n *netNS) run(extra []*os.File, args ...string) (string, error) {
	var out []byte
	err := n.do(func() error {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.ExtraFiles = extra
		var err error
		out, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("knet: %s: %s: %v: %s", n.name, strings.Join(args, " "), err, bytes.TrimSpace(out))
		}
		return nil
	})
	return string(out), err
}

func (n *netNS) sysctl(key, val string) error {
	return n.do(func() error {
		return os.WriteFile("/proc/sys/"+strings.ReplaceAll(key, ".", "/"), []byte(val), 0)
	})
}

// --- the topology ---

// Interface names: router side and end-host side of each veth pair.
const (
	devRouterClient = "rc" // router → client: the down direction
	devRouterServer = "rs" // router → server: the up direction
	devClient       = "c0"
	devServer       = "s0"

	routerClientAddr = "10.0.1.254"
	routerServerAddr = "10.0.2.254"

	macClient       = "02:00:0a:00:01:01"
	macRouterClient = "02:00:0a:00:01:fe"
	macServer       = "02:00:0a:00:02:01"
	macRouterServer = "02:00:0a:00:02:fe"

	ethHeader = 14 // veth counts and tbf meters Ethernet frames
)

// Topology is a client, a router and a server joined by veths. Its
// impairments are set with Configure; one configuration is live at a time.
type Topology struct {
	// ServerCC, if set, is the congestion control (e.g. "bbr") of TCP
	// connections accepted by Server's listeners: the outer connections
	// the node sends on. The TCP inside the tunnel keeps the default.
	ServerCC string

	srv, rtr, cli *netNS

	mu   sync.Mutex
	cfg  link.Config
	base [2]devCounters // up, down at the last Configure
}

// New builds the topology. The process must be the one Reexec started.
func New() (*Topology, error) {
	if !InNamespace() {
		return nil, errors.New("knet: not inside the bench's namespace; call Reexec first")
	}
	srv, err := selfNS()
	if err != nil {
		return nil, err
	}
	t := &Topology{srv: srv}
	if t.rtr, err = newNS("router"); err != nil {
		t.Close()
		return nil, err
	}
	if t.cli, err = newNS("client"); err != nil {
		t.Close()
		return nil, err
	}
	type step struct {
		ns    *netNS
		extra []*os.File
		args  string
	}
	noOffload := func(dev string) string { return "ethtool -K " + dev + " tso off gso off gro off" }
	steps := []step{
		{t.srv, nil, "ip link set lo up"},
		{t.rtr, nil, "ip link set lo up"},
		{t.cli, nil, "ip link set lo up"},
		{t.rtr, []*os.File{t.srv.f}, "ip link add " + devRouterServer + " address " + macRouterServer + " type veth peer name " + devServer + " address " + macServer + " netns /proc/self/fd/3"},
		{t.rtr, []*os.File{t.cli.f}, "ip link add " + devRouterClient + " address " + macRouterClient + " type veth peer name " + devClient + " address " + macClient + " netns /proc/self/fd/3"},
		{t.rtr, nil, "ip addr add " + routerServerAddr + "/24 dev " + devRouterServer},
		{t.rtr, nil, "ip addr add " + routerClientAddr + "/24 dev " + devRouterClient},
		{t.rtr, nil, noOffload(devRouterServer)},
		{t.rtr, nil, noOffload(devRouterClient)},
		{t.rtr, nil, "ip link set " + devRouterServer + " up"},
		{t.rtr, nil, "ip link set " + devRouterClient + " up"},
		{t.srv, nil, "ip addr add " + ServerAddr.String() + "/24 dev " + devServer},
		{t.srv, nil, noOffload(devServer)},
		{t.srv, nil, "ip link set " + devServer + " up"},
		{t.srv, nil, "ip route add default via " + routerServerAddr},
		{t.cli, nil, "ip addr add " + ClientAddr.String() + "/24 dev " + devClient},
		{t.cli, nil, noOffload(devClient)},
		{t.cli, nil, "ip link set " + devClient + " up"},
		{t.cli, nil, "ip route add default via " + routerClientAddr},
		// Fixed neighbours: ARP would cross the delay too, and add a
		// round trip to the first packet of each measurement.
		{t.rtr, nil, "ip neigh replace " + ServerAddr.String() + " lladdr " + macServer + " dev " + devRouterServer + " nud permanent"},
		{t.rtr, nil, "ip neigh replace " + ClientAddr.String() + " lladdr " + macClient + " dev " + devRouterClient + " nud permanent"},
		{t.srv, nil, "ip neigh replace " + routerServerAddr + " lladdr " + macRouterServer + " dev " + devServer + " nud permanent"},
		{t.cli, nil, "ip neigh replace " + routerClientAddr + " lladdr " + macRouterClient + " dev " + devClient + " nud permanent"},
		// The end hosts' own egress: what a Linux host has by default.
		// It never queues here (the veth is far faster than the path).
		{t.srv, nil, "tc qdisc replace dev " + devServer + " root fq_codel"},
		{t.cli, nil, "tc qdisc replace dev " + devClient + " root fq_codel"},
	}
	for _, s := range steps {
		if _, err := s.ns.run(s.extra, strings.Fields(s.args)...); err != nil {
			t.Close()
			return nil, err
		}
	}
	if err := t.rtr.sysctl("net.ipv4.ip_forward", "1"); err != nil {
		t.Close()
		return nil, err
	}
	// Linux caches ssthresh and RTT per destination; each measurement must
	// start from a cold connection as it would on a fresh path.
	for _, n := range []*netNS{t.srv, t.cli} {
		if err := n.sysctl("net.ipv4.tcp_no_metrics_save", "1"); err != nil {
			t.Close()
			return nil, err
		}
	}
	return t, nil
}

// Close tears the topology down. The namespaces, and with them every
// interface and socket in them, go when the last reference does.
func (t *Topology) Close() {
	for _, n := range []*netNS{t.cli, t.rtr, t.srv} {
		if n != nil {
			n.f.Close()
		}
	}
}

// Configure replaces the path's impairments with cfg, which means what it
// means to bench/link. Connections open across the change keep running.
func (t *Topology) Configure(cfg link.Config) error {
	if cfg.MTU == 0 {
		cfg.MTU = link.DefaultMTU
	}
	if cfg.QueueBytes == 0 && cfg.Bandwidth > 0 {
		cfg.QueueBytes = max(int(float64(cfg.Bandwidth)*cfg.RTT.Seconds()/8), link.MinQueueBytes)
	}
	for _, d := range []struct {
		ns  *netNS
		dev string
	}{{t.rtr, devRouterClient}, {t.rtr, devRouterServer}, {t.cli, devClient}, {t.srv, devServer}} {
		if _, err := d.ns.run(nil, "ip", "link", "set", d.dev, "mtu", strconv.Itoa(cfg.MTU)); err != nil {
			return err
		}
	}
	for _, dev := range []string{devRouterClient, devRouterServer} {
		t.rtr.run(nil, "tc", "qdisc", "del", "dev", dev, "root") // none yet is fine
		for _, args := range qdiscs(dev, cfg) {
			if _, err := t.rtr.run(nil, args...); err != nil {
				return err
			}
		}
	}
	up, down, err := t.counters()
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.cfg, t.base = cfg, [2]devCounters{up, down}
	t.mu.Unlock()
	return nil
}

// qdiscs is the tc commands that impose cfg on one egress interface.
func qdiscs(dev string, cfg link.Config) [][]string {
	pct := func(p float64) string { return strconv.FormatFloat(p*100, 'f', -1, 64) + "%" }
	netem := []string{"tc", "qdisc", "add", "dev", dev, "root", "handle", "1:", "netem",
		"limit", "1000000", "delay", fmt.Sprintf("%dus", (cfg.RTT / 2).Microseconds())}
	switch b := cfg.Burst; {
	case b != nil:
		// Gilbert–Elliott: p, r, loss in bad (1-h), loss in good (1-k).
		netem = append(netem, "loss", "gemodel", pct(b.PGoodToBad), pct(b.PBadToGood), pct(b.LossBad), pct(cfg.Loss))
	case cfg.Loss > 0:
		netem = append(netem, "loss", "random", pct(cfg.Loss))
	}
	if cfg.Seed != 0 {
		netem = append(netem, "seed", strconv.FormatInt(cfg.Seed, 10))
	}
	cmds := [][]string{netem}
	parent := "1:1"
	if cfg.Bandwidth > 0 {
		frame := cfg.MTU + ethHeader
		burst := max(2*frame, int(cfg.Bandwidth/8/1000)) // a millisecond at the rate
		cmds = append(cmds, []string{"tc", "qdisc", "add", "dev", dev, "parent", parent, "handle", "10:", "tbf",
			"rate", strconv.FormatInt(cfg.Bandwidth, 10) + "bit", "burst", strconv.Itoa(burst),
			"limit", strconv.Itoa(cfg.QueueBytes)})
		parent = "10:1"
	}
	if r := cfg.PerConnRate; r > 0 {
		// The same per-flow backlog bench/link allows: 50 ms at the
		// capped rate, at least four full packets.
		queue := max(int(float64(r)*0.05/8), 4*cfg.MTU)
		flowLimit := int(math.Ceil(float64(queue) / float64(cfg.MTU)))
		q := strconv.Itoa(2 * (cfg.MTU + ethHeader))
		cmds = append(cmds, []string{"tc", "qdisc", "add", "dev", dev, "parent", parent, "handle", "20:", "fq",
			"maxrate", strconv.FormatInt(r, 10) + "bit", "flow_limit", strconv.Itoa(flowLimit),
			"quantum", q, "initial_quantum", q, "orphan_mask", "1023"})
	}
	return cmds
}

// --- statistics ---

type devCounters struct{ bytes, packets uint64 }

// counters reads what the router has sent towards the server (up) and
// towards the client (down).
func (t *Topology) counters() (up, down devCounters, err error) {
	var raw []byte
	err = t.rtr.do(func() error {
		var err error
		raw, err = os.ReadFile("/proc/thread-self/net/dev")
		return err
	})
	if err != nil {
		return up, down, err
	}
	found := 0
	for line := range strings.SplitSeq(string(raw), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 10 {
			continue
		}
		b, _ := strconv.ParseUint(f[8], 10, 64)
		p, _ := strconv.ParseUint(f[9], 10, 64)
		switch strings.TrimSpace(name) {
		case devRouterServer:
			up, found = devCounters{b, p}, found+1
		case devRouterClient:
			down, found = devCounters{b, p}, found+1
		}
	}
	if found != 2 {
		return up, down, errors.New("knet: router interfaces missing from /proc/net/dev")
	}
	return up, down, nil
}

// qdiscDrops reads the drop counters of the qdiscs on dev, by kind.
func (t *Topology) qdiscDrops(dev string) (map[string]uint64, error) {
	out, err := t.rtr.run(nil, "tc", "-s", "-j", "qdisc", "show", "dev", dev)
	if err != nil {
		return nil, err
	}
	var qs []struct {
		Kind  string `json:"kind"`
		Drops uint64 `json:"drops"`
	}
	if err := json.Unmarshal([]byte(out), &qs); err != nil {
		return nil, fmt.Errorf("knet: parse tc stats: %w", err)
	}
	m := map[string]uint64{}
	for _, q := range qs {
		m[q.Kind] += q.Drops
	}
	return m, nil
}

// Stats reports what the path delivered since the last Configure, in each
// direction (up is client→server), as bench/link counts it: IP bytes, and
// drops by cause. A parent qdisc counts its children's drops as its own,
// so each cause is the difference.
func (t *Topology) Stats() (up, down link.DirStats) {
	t.mu.Lock()
	base := t.base
	t.mu.Unlock()
	u, d, err := t.counters()
	if err != nil {
		return
	}
	fill := func(dev string, now, was devCounters) link.DirStats {
		s := link.DirStats{Packets: now.packets - was.packets}
		s.Bytes = now.bytes - was.bytes - ethHeader*s.Packets
		if q, err := t.qdiscDrops(dev); err == nil {
			sub := func(a, b uint64) uint64 { return a - min(a, b) }
			child := q["tbf"]
			if child == 0 {
				child = q["fq"]
			}
			s.DroppedLoss = sub(q["netem"], child)
			s.DroppedQueue = sub(q["tbf"], q["fq"])
			s.DroppedCap = q["fq"]
		}
		return s
	}
	return fill(devRouterServer, u, base[0]), fill(devRouterClient, d, base[1])
}

// --- flows ---

// TCPFlows lists the client's established TCP connections to port on the
// server, oriented client→server.
func (t *Topology) TCPFlows(port uint16) ([]link.Flow, error) {
	out, err := t.cli.run(nil, "ss", "-tnH", "state", "established")
	if err != nil {
		return nil, err
	}
	var flows []link.Flow
	for line := range strings.SplitSeq(out, "\n") {
		var aps []netip.AddrPort
		for _, f := range strings.Fields(line) {
			if ap, err := netip.ParseAddrPort(f); err == nil {
				aps = append(aps, ap)
			}
		}
		if len(aps) == 2 && aps[1].Port() == port && aps[1].Addr() == ServerAddr {
			flows = append(flows, link.Flow{Proto: link.ProtoTCP, Src: aps[0], Dst: aps[1]})
		}
	}
	return flows, nil
}

// ResetFlow kills a client TCP connection the way a forged reset would: the
// client's socket is aborted (sock_destroy), which sends the server a RST.
func (t *Topology) ResetFlow(f link.Flow) error {
	out, err := t.cli.run(nil, "ss", "-K", "-tnH", "src", f.Src.String(), "dst", f.Dst.String())
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) == "" {
		return fmt.Errorf("knet: no connection %v to reset", f)
	}
	return nil
}

// SS returns `ss -tinH` for the client's or server's established TCP
// connections with the given remote (client) or local (server) port: their
// congestion control, cwnd, RTT and unsent bytes, for logs.
func (t *Topology) SS(server bool, port uint16) string {
	n, filter := t.cli, "dport = :"+strconv.Itoa(int(port))
	if server {
		n, filter = t.srv, "sport = :"+strconv.Itoa(int(port))
	}
	out, err := n.run(nil, append([]string{"ss", "-tinH", "state", "established"}, strings.Fields(filter)...)...)
	if err != nil {
		return err.Error()
	}
	return strings.TrimSpace(out)
}

// --- hosts ---

// Host opens sockets on one end of the path, in that end's namespace.
type Host struct {
	ns   *netNS
	addr netip.Addr
	cc   string
}

// Client is the client end of the outer path.
func (t *Topology) Client() *Host { return &Host{ns: t.cli, addr: ClientAddr} }

// Server is the server end of the outer path. Its listeners use ServerCC.
func (t *Topology) Server() *Host { return &Host{ns: t.srv, addr: ServerAddr, cc: t.ServerCC} }

// ClientTunnel and ServerTunnel open sockets on either end with addr, the
// end's tunnel address, as the default local address: the TCP inside the
// tunnel, with the kernel's default congestion control.
func (t *Topology) ClientTunnel(addr netip.Addr) *Host { return &Host{ns: t.cli, addr: addr} }
func (t *Topology) ServerTunnel(addr netip.Addr) *Host { return &Host{ns: t.srv, addr: addr} }

// Addr is the host's address.
func (h *Host) Addr() netip.Addr { return h.addr }

func (h *Host) control(_, _ string, c syscall.RawConn) error {
	if h.cc == "" {
		return nil
	}
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, h.cc)
	}); err != nil {
		return err
	}
	if serr != nil {
		return fmt.Errorf("knet: congestion control %q: %w (is its module loaded?)", h.cc, serr)
	}
	return nil
}

// DialTCP connects to dst from the host.
func (h *Host) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	var c net.Conn
	err := h.ns.do(func() error {
		var err error
		d := net.Dialer{Control: h.control}
		c, err = d.DialContext(ctx, "tcp4", dst.String())
		return err
	})
	return c, err
}

// ListenTCP listens on the host's address.
func (h *Host) ListenTCP(port uint16) (net.Listener, error) {
	return h.ListenTCPAddrPort(netip.AddrPortFrom(h.addr, port))
}

// ListenTCPAddrPort listens on ap.
func (h *Host) ListenTCPAddrPort(ap netip.AddrPort) (net.Listener, error) {
	var l net.Listener
	err := h.ns.do(func() error {
		var err error
		lc := net.ListenConfig{Control: h.control}
		l, err = lc.Listen(context.Background(), "tcp4", ap.String())
		return err
	})
	return l, err
}

// ListenUDP opens a UDP socket on the host's address.
func (h *Host) ListenUDP(port uint16) (net.PacketConn, error) {
	return h.ListenUDPAddrPort(netip.AddrPortFrom(h.addr, port))
}

// ListenUDPAddrPort opens a UDP socket on ap.
func (h *Host) ListenUDPAddrPort(ap netip.AddrPort) (net.PacketConn, error) {
	var c net.PacketConn
	err := h.ns.do(func() error {
		var err error
		c, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(ap))
		return err
	})
	return c, err
}

// DialUDP opens a connected UDP socket to dst.
func (h *Host) DialUDP(dst netip.AddrPort) (net.Conn, error) {
	var c net.Conn
	err := h.ns.do(func() error {
		var err error
		c, err = net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(dst))
		return err
	})
	return c, err
}

// --- tunnel devices ---

// TUN creates a kernel TUN device on the client or the server end, gives it
// addr/24 and brings it up. Its signature fits wgnet.PairConfig.TUN.
func (t *Topology) TUN(server bool, addr netip.Addr, mtu int) (tun.Device, error) {
	n, name := t.cli, "tkc"
	if server {
		n, name = t.srv, "tks"
	}
	var dev tun.Device
	err := n.do(func() error {
		var err error
		dev, err = tun.CreateTUN(name, mtu)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("knet: create %s on %s: %w", name, n.name, err)
	}
	for _, args := range [][]string{
		{"ip", "addr", "add", addr.String() + "/24", "dev", name},
		{"ip", "link", "set", name, "up"},
	} {
		if _, err := n.run(nil, args...); err != nil {
			dev.Close()
			return nil, err
		}
	}
	return fixedMTU{dev, mtu}, nil
}

// fixedMTU reports the MTU the device was made with. wireguard-go re-reads
// it by interface name on whichever thread handles a link event, and that
// thread is not in the device's namespace; the failed lookup would make it
// skip the event.
type fixedMTU struct {
	tun.Device
	mtu int
}

func (f fixedMTU) MTU() (int, error) { return f.mtu, nil }

// WaitGone waits until neither TUN device exists, so the next pair can
// reuse the names.
func (t *Topology) WaitGone(timeout time.Duration) {
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		_, e1 := t.cli.run(nil, "ip", "link", "show", "tkc")
		_, e2 := t.srv.run(nil, "ip", "link", "show", "tks")
		if e1 != nil && e2 != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
