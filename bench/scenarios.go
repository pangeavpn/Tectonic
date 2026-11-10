package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/pangeavpn/tectonic/bench/link"
	"github.com/pangeavpn/tectonic/bench/wgnet"
)

// row is one line of the results table.
type row struct {
	measurement string
	target      string
	result      string
	pass        *bool // nil when the row is for information
}

func verdict(ok bool) *bool { return &ok }

func mbps(bps float64) string { return fmt.Sprintf("%.1f Mbit/s", bps/1e6) }

type opts struct {
	dur      time.Duration // one throughput measurement
	warm     time.Duration // let slow start and the lane pool settle first
	capDur   time.Duration // how long the per-connection-cap run lasts
	trials   int
	logf     func(format string, args ...any)
	selected func(transport) bool
}

type scenario struct {
	name string
	desc string
	run  func(ctx context.Context, o opts) []row
}

var scenarios = []scenario{
	{"ttfp", "time to first WireGuard packet", scTTFP},
	{"clean", "throughput and bulk overhead on a clean 100 Mbit/s, 50 ms link", scClean},
	{"loss", "throughput with 1% random loss", scLoss},
	{"cap", "throughput under a 4 Mbit/s per-connection cap", scCap},
	{"latency", "ping inside the tunnel during a saturating download", scLatency},
	{"reset", "recovery from a reset lane", scReset},
	{"interactive", "bandwidth overhead during interactive use", scInteractive},
}

// --- Time to first WireGuard packet: ≤ 2 RTT ---

func scTTFP(ctx context.Context, o opts) []row {
	const rtt = 50 * time.Millisecond
	L, err := link.New(link.Config{Bandwidth: 100e6, RTT: rtt})
	if err != nil {
		return failed("Time to first WireGuard packet", err)
	}
	defer L.Close()

	// Calibrate: what one round trip costs on this link in this process,
	// timer jitter included, measured as a plain TCP connect.
	ln, err := L.Server.ListenTCP(1999)
	if err != nil {
		return failed("Time to first WireGuard packet", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	var rtts []time.Duration
	for range 5 {
		t0 := time.Now()
		c, err := L.Client.DialTCP(ctx, netip.AddrPortFrom(link.ServerAddr, 1999))
		if err != nil {
			return failed("Time to first WireGuard packet", err)
		}
		rtts = append(rtts, time.Since(t0))
		c.Close()
	}
	ln.Close()
	measured := percentile(rtts, 0.5)
	o.logf("ttfp: one round trip measures %v on a %v link", measured, rtt)

	var sent []float64
	for i := range o.trials {
		// A stand-in for WireGuard that notes when the packet lands.
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return failed("Time to first WireGuard packet", err)
		}
		initiation := make([]byte, 148)
		initiation[0] = 1
		start := time.Now()
		c, srv, err := startTectonic(ctx, L, uint16(2000+i), udp.LocalAddr().String())
		if err != nil {
			udp.Close()
			return failed("Time to first WireGuard packet", err)
		}
		c.WriteTo(initiation, nil)
		udp.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, _, err = udp.ReadFrom(make([]byte, 2048))
		arrived := time.Since(start)
		c.Close()
		srv.Close()
		udp.Close()
		if err != nil {
			return failed("Time to first WireGuard packet", err)
		}
		// The design counts round trips until the packet leaves the
		// client; it then takes half a round trip to arrive.
		s := (arrived - measured/2).Seconds() / measured.Seconds()
		sent = append(sent, s)
		o.logf("ttfp trial %d: arrived after %v; sent after %.2f round trips", i+1, arrived.Round(time.Millisecond), s)
	}
	slices.Sort(sent)
	med := sent[len(sent)/2]
	return []row{{
		measurement: "Time to first WireGuard packet",
		target:      "≤ 2 RTT",
		result: fmt.Sprintf("%.2f RTT (median of %d, in measured round trips of %v on a %v link)",
			med, len(sent), measured.Round(100*time.Microsecond), rtt),
		pass: verdict(med <= 2.1), // allow the few ms TLS and HELLO take to compute
	}}
}

// --- Throughput and bulk overhead on a clean link ---

type bulkResult struct {
	tr       transport
	bps      float64
	perInner float64 // link bytes per inner payload byte
	err      error
}

func measureBulk(ctx context.Context, o opts, tr transport, lc link.Config) bulkResult {
	e, err := newEnv(ctx, tr, lc)
	if err != nil {
		return bulkResult{tr: tr, err: err}
	}
	defer e.Close()
	t, err := startDownload(ctx, e)
	if err != nil {
		return bulkResult{tr: tr, err: err}
	}
	defer t.Stop()
	time.Sleep(o.warm)
	b0, l0 := t.bytes.Load(), linkBytes(e.L)
	u0, d0 := e.L.Stats()
	bps := t.rate(ctx, o.dur)
	db, dl := t.bytes.Load()-b0, linkBytes(e.L)-l0
	u1, d1 := e.L.Stats()
	if db > 0 {
		o.logf("%s: per payload byte: down %.4f (%d pkts), up %.4f (%d pkts)", tr,
			float64(d1.Bytes-d0.Bytes)/float64(db), d1.Packets-d0.Packets,
			float64(u1.Bytes-u0.Bytes)/float64(db), u1.Packets-u0.Packets)
	}
	if t.err != nil {
		return bulkResult{tr: tr, err: fmt.Errorf("transfer failed: %w", t.err)}
	}
	r := bulkResult{tr: tr, bps: bps}
	if db > 0 {
		r.perInner = float64(dl) / float64(db)
	}
	o.logf("%s: %s, %.4f link bytes per payload byte", tr, mbps(bps), r.perInner)
	if e.conn != nil {
		st := e.conn.Stats()
		up, down := e.L.Stats()
		o.logf("%s: lanes %d, sent %d, dropped %d, dupes %d; received: held %d, skipped %d, late %d; link up %d pkts, down %d pkts, queue drops %d/%d",
			tr, st.Lanes, st.Sent, st.Dropped, st.Dupes, st.Held, st.Skipped, st.Late,
			up.Packets, down.Packets, up.DroppedQueue, down.DroppedQueue)
	}
	return r
}

func runBulk(ctx context.Context, o opts, lc link.Config) map[transport]bulkResult {
	out := map[transport]bulkResult{}
	for _, tr := range allTransports {
		if o.selected(tr) {
			out[tr] = measureBulk(ctx, o, tr, lc)
		}
	}
	return out
}

func bulkRows(name string, res map[transport]bulkResult) []row {
	var rows []row
	for _, tr := range allTransports {
		r, ok := res[tr]
		if !ok {
			continue
		}
		val := mbps(r.bps)
		if r.err != nil {
			val = "error: " + r.err.Error()
		}
		rows = append(rows, row{measurement: fmt.Sprintf("%s: %s", name, tr), result: val})
	}
	return rows
}

func scClean(ctx context.Context, o opts) []row {
	res := runBulk(ctx, o, link.Config{Bandwidth: 100e6, RTT: 50 * time.Millisecond})
	rows := bulkRows("Clean link", res)
	wg, tt := res[tWireGuard], res[tTectonic]
	if wg.err == nil && tt.err == nil && wg.bps > 0 {
		ratio := tt.bps / wg.bps
		rows = append(rows, row{
			measurement: "Throughput on a clean link (100 Mbit/s, 50 ms)",
			target:      "≥ 90% of plain WireGuard over UDP",
			result:      fmt.Sprintf("%.0f%% (%s vs %s)", ratio*100, mbps(tt.bps), mbps(wg.bps)),
			pass:        verdict(ratio >= 0.9),
		})
		if wg.perInner > 0 && tt.perInner > 0 {
			over := tt.perInner/wg.perInner - 1
			rows = append(rows, row{
				measurement: "Bandwidth overhead, bulk transfer",
				target:      "≤ 3%",
				result:      fmt.Sprintf("%.1f%% more link bytes than WireGuard over UDP", over*100),
				pass:        verdict(over <= 0.03),
			})
		}
	}
	return rows
}

// --- 1% random loss: clearly above REALITY and AnyTLS ---

func scLoss(ctx context.Context, o opts) []row {
	res := runBulk(ctx, o, link.Config{Bandwidth: 100e6, RTT: 50 * time.Millisecond, Loss: 0.01, Seed: 7})
	rows := bulkRows("1% loss", res)
	tt := res[tTectonic]
	best := 0.0
	for _, tr := range []transport{tReality, tAnyTLS} {
		if r, ok := res[tr]; ok && r.err == nil {
			best = max(best, r.bps)
		}
	}
	if tt.err == nil && best > 0 {
		ratio := tt.bps / best
		rows = append(rows, row{
			measurement: "Throughput with 1% random loss",
			target:      "Clearly above REALITY and AnyTLS",
			result:      fmt.Sprintf("%.1f× the better of the two (%s vs %s)", ratio, mbps(tt.bps), mbps(best)),
			pass:        verdict(ratio >= 1.25),
		})
	}
	return rows
}

// --- Per-connection cap: throughput rises with lanes, up to max_lanes ---

func scCap(ctx context.Context, o opts) []row {
	const capBps = 4e6
	lc := link.Config{Bandwidth: 100e6, RTT: 50 * time.Millisecond, PerConnRate: capBps}
	var rows []row
	if o.selected(tReality) {
		r := measureBulk(ctx, o, tReality, lc)
		rows = append(rows, row{measurement: "4 Mbit/s per-connection cap: reality", result: mbps(r.bps)})
	}
	if !o.selected(tTectonic) {
		return rows
	}
	e, err := newEnv(ctx, tTectonic, lc)
	if err != nil {
		return append(rows, failed("Per-connection cap", err)...)
	}
	defer e.Close()
	t, err := startDownload(ctx, e)
	if err != nil {
		return append(rows, failed("Per-connection cap", err)...)
	}
	defer t.Stop()
	step := 5 * time.Second
	var trace []string
	var last float64
	lanes, maxLanesSeen := 0, 0
	for elapsed := time.Duration(0); elapsed < o.capDur; elapsed += step {
		last = t.rate(ctx, step)
		lanes = e.conn.Stats().Lanes
		maxLanesSeen = max(maxLanesSeen, lanes)
		trace = append(trace, fmt.Sprintf("%ds: %d lanes %.1f", int((elapsed+step).Seconds()), lanes, last/1e6))
		o.logf("cap: %s", trace[len(trace)-1])
	}
	o.logf("cap trace (Mbit/s): %s", strings.Join(trace, ", "))
	return append(rows, row{
		measurement: "Throughput under a 4 Mbit/s per-connection cap",
		target:      "Rises with the number of lanes, up to max_lanes",
		result:      fmt.Sprintf("%s with %d lanes after %v (most lanes seen: %d)", mbps(last), lanes, o.capDur, maxLanesSeen),
		pass:        verdict(maxLanesSeen > 2 && last >= capBps*float64(lanes)*0.6),
	})
}

// --- Latency under load: within 2× idle RTT ---

func scLatency(ctx context.Context, o opts) []row {
	lc := link.Config{Bandwidth: 20e6, RTT: 50 * time.Millisecond}
	var rows []row
	for _, tr := range []transport{tWireGuard, tTectonic, tReality} {
		if !o.selected(tr) {
			continue
		}
		idle, loaded, err := measureLatency(ctx, o, tr, lc)
		if err != nil {
			rows = append(rows, failed("Latency under load: "+string(tr), err)...)
			continue
		}
		p50, p95 := percentile(loaded, 0.5), percentile(loaded, 0.95)
		res := fmt.Sprintf("idle %v; loaded p50 %v, p95 %v (%.1f× idle)", idle.Round(time.Millisecond),
			p50.Round(time.Millisecond), p95.Round(time.Millisecond), p95.Seconds()/idle.Seconds())
		r := row{measurement: "Latency under load: " + string(tr), result: res}
		if tr == tTectonic {
			r.measurement = "Latency under load (20 Mbit/s, 50 ms)"
			r.target = "Ping stays within 2× idle RTT"
			r.pass = verdict(p95 <= 2*idle)
		}
		rows = append(rows, r)
	}
	return rows
}

func measureLatency(ctx context.Context, o opts, tr transport, lc link.Config) (time.Duration, []time.Duration, error) {
	e, err := newEnv(ctx, tr, lc)
	if err != nil {
		return 0, nil, err
	}
	defer e.Close()
	p, err := newPinger(e)
	if err != nil {
		return 0, nil, err
	}
	defer p.Close()
	var idle []time.Duration
	for range 20 {
		if d, err := p.ping(ctx, 2*time.Second); err == nil {
			idle = append(idle, d)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(idle) == 0 {
		return 0, nil, fmt.Errorf("no idle pings answered")
	}
	t, err := startDownload(ctx, e)
	if err != nil {
		return 0, nil, err
	}
	defer t.Stop()
	time.Sleep(o.warm)
	var loaded []time.Duration
	lost := 0
	end := time.Now().Add(o.dur)
	for time.Now().Before(end) {
		d, err := p.ping(ctx, 2*time.Second)
		if err != nil {
			lost++
			d = 2 * time.Second
		}
		loaded = append(loaded, d)
		time.Sleep(100 * time.Millisecond)
	}
	o.logf("%s latency: idle p50 %v, loaded p50 %v p95 %v, %d lost, download %s", tr,
		percentile(idle, 0.5), percentile(loaded, 0.5), percentile(loaded, 0.95), lost,
		mbps(float64(t.bytes.Load())*8/time.Since(t.started).Seconds()))
	return percentile(idle, 0.5), loaded, nil
}

// --- Recovery from a reset lane: no visible stall ---

func scReset(ctx context.Context, o opts) []row {
	const rtt = 50 * time.Millisecond
	lc := link.Config{Bandwidth: 50e6, RTT: rtt}
	var rows []row
	for _, tr := range []transport{tTectonic, tReality} {
		if !o.selected(tr) {
			continue
		}
		before, after, rate, err := measureReset(ctx, o, tr, lc)
		r := row{measurement: "Reset during a transfer: " + string(tr)}
		switch {
		case err != nil:
			r.result = err.Error()
		default:
			r.result = fmt.Sprintf("longest stall %v after the reset (%v before); %s afterwards",
				after.Round(time.Millisecond), before.Round(time.Millisecond), mbps(rate))
		}
		if tr == tTectonic {
			r.measurement = "Recovery from a reset lane"
			r.target = "No visible stall in a TCP transfer inside the tunnel"
			r.pass = verdict(err == nil && after <= max(4*rtt, 2*before) && rate > 0)
		}
		rows = append(rows, r)
	}
	return rows
}

func measureReset(ctx context.Context, o opts, tr transport, lc link.Config) (before, after time.Duration, rate float64, err error) {
	e, err := newEnv(ctx, tr, lc)
	if err != nil {
		return 0, 0, 0, err
	}
	defer e.Close()
	t, err := startDownload(ctx, e)
	if err != nil {
		return 0, 0, 0, err
	}
	defer t.Stop()
	time.Sleep(o.warm + 2*time.Second)
	port := uint16(tectonicPort)
	if tr != tTectonic {
		port = baselinePort
	}
	var victim *link.Flow
	for _, f := range e.L.Flows() {
		if f.Proto == link.ProtoTCP && (f.Dst.Port() == port || f.Src.Port() == port) {
			victim = &f
			break
		}
	}
	if victim == nil {
		return 0, 0, 0, fmt.Errorf("no lane to reset")
	}
	resetAt := time.Now()
	window := 3 * time.Second
	if err := e.L.ResetFlow(*victim); err != nil {
		return 0, 0, 0, err
	}
	o.logf("%s: reset %v", tr, victim)
	rate = t.rate(ctx, window)
	before = t.maxGap(resetAt.Add(-window), resetAt)
	after = t.maxGap(resetAt, time.Now())
	if rate == 0 {
		return before, time.Since(resetAt), 0, fmt.Errorf("transfer stopped: the tunnel did not survive the reset")
	}
	return before, after, rate, nil
}

// --- Interactive overhead: ≤ 15% ---

func scInteractive(ctx context.Context, o opts) []row {
	lc := link.Config{Bandwidth: 100e6, RTT: 50 * time.Millisecond}
	per := map[transport]float64{}
	var rows []row
	for _, tr := range []transport{tWireGuard, tTectonic} {
		ratio, err := measureInteractive(ctx, o, tr, lc)
		if err != nil {
			return append(rows, failed("Interactive overhead: "+string(tr), err)...)
		}
		per[tr] = ratio
	}
	over := per[tTectonic]/per[tWireGuard] - 1
	return append(rows, row{
		measurement: "Bandwidth overhead, interactive use",
		target:      "≤ 15%",
		result:      fmt.Sprintf("%.1f%% more link bytes than WireGuard over UDP", over*100),
		pass:        verdict(over <= 0.15),
	})
}

// measureInteractive runs a browsing-like exchange inside the tunnel: small
// requests, replies of a few to tens of kilobytes, and pauses between them.
// It returns link bytes per payload byte.
func measureInteractive(ctx context.Context, o opts, tr transport, lc link.Config) (float64, error) {
	e, err := newEnv(ctx, tr, lc)
	if err != nil {
		return 0, err
	}
	defer e.Close()
	ln, err := e.server.Net.ListenTCPAddrPort(netip.AddrPortFrom(wgnet.ServerAddr, 8080))
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req := make([]byte, 4)
		for {
			if _, err := readFull(c, req); err != nil {
				return
			}
			n := int(req[0])<<16 | int(req[1])<<8 | int(req[2])
			if _, err := c.Write(make([]byte, n)); err != nil {
				return
			}
		}
	}()
	c, err := e.client.Net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(wgnet.ServerAddr, 8080))
	if err != nil {
		return 0, err
	}
	defer c.Close()
	rng := rand.New(rand.NewPCG(1, 2))
	l0 := linkBytes(e.L)
	var payload int64
	end := time.Now().Add(o.dur)
	buf := make([]byte, 64<<10)
	for time.Now().Before(end) {
		n := 2<<10 + rng.IntN(40<<10)
		req := make([]byte, 300) // a request, headers and all
		req[0], req[1], req[2] = byte(n>>16), byte(n>>8), byte(n)
		if _, err := c.Write(req[:4]); err != nil {
			return 0, err
		}
		if _, err := c.Write(req[4:]); err != nil {
			return 0, err
		}
		if _, err := readFull(c, buf[:n]); err != nil {
			return 0, err
		}
		payload += int64(n + len(req))
		time.Sleep(time.Duration(100+rng.IntN(400)) * time.Millisecond) // reading the page
	}
	ratio := float64(linkBytes(e.L)-l0) / float64(payload)
	o.logf("%s interactive: %.3f link bytes per payload byte", tr, ratio)
	return ratio, nil
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func failed(name string, err error) []row {
	return []row{{measurement: name, result: "error: " + err.Error(), pass: verdict(false)}}
}
