package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pangeavpn/tectonic"
	"github.com/pangeavpn/tectonic/bench/link"
)

// changeWindow is how long a path change is watched: long enough for a lane that never hears back
// to time out (15 s) and a dial that hangs to be given up on (20 s).
const changeWindow = 40 * time.Second

// scPathChange silences every lane mid-download while new connections still get through: what a
// phone sees when it leaves Wi-Fi, or a NAT forgets its connections.
func scPathChange(ctx context.Context, o opts) []row {
	if !o.selected(tTectonic) {
		return nil
	}
	lc := link.Config{Bandwidth: 50e6, RTT: 50 * time.Millisecond}
	cases := []struct {
		name      string
		announced bool
		hang      int32
	}{
		{"unannounced", false, 0},
		{"announced (SetNetwork)", true, 0},
		{"announced, and the first dial after it hangs", true, 1},
	}
	var rows []row
	for _, c := range cases {
		name := "Path change, " + c.name
		stall, after, err := measurePathChange(ctx, o, lc, c.announced, c.hang)
		if err != nil {
			rows = append(rows, failed(name, err)...)
			continue
		}
		rows = append(rows, row{measurement: name, result: fmt.Sprintf("download stalled %v; %s in the last 5 s",
			stall.Round(10*time.Millisecond), mbps(after))})
	}
	return rows
}

func measurePathChange(ctx context.Context, o opts, lc link.Config, announced bool, hang int32) (time.Duration, float64, error) {
	e, err := newEnv(ctx, tTectonic, lc)
	if err != nil {
		return 0, 0, err
	}
	defer e.Close()
	t, err := startDownload(ctx, e)
	if err != nil {
		return 0, 0, err
	}
	defer t.Stop()
	time.Sleep(o.warm + 2*time.Second)
	flows := e.P.tcpFlows(tectonicPort)
	if len(flows) == 0 {
		return 0, 0, fmt.Errorf("no lane to silence")
	}
	at := time.Now()
	dialHang.Store(hang)
	defer dialHang.Store(0)
	for _, f := range flows {
		if err := e.P.blackholeFlow(f); err != nil {
			return 0, 0, err
		}
	}
	if announced {
		e.conn.SetNetwork("bench-after-change", false)
	}
	o.logf("path change: silenced %d lanes (announced %v, hanging dials %d)", len(flows), announced, hang)
	time.Sleep(changeWindow - 5*time.Second)
	after := t.rate(ctx, 5*time.Second)
	stall := max(t.maxGap(at, time.Now()), time.Since(t.lastRead()))
	if after == 0 {
		return changeWindow, 0, nil
	}
	o.logf("path change: stall %v, then %s; lanes %d", stall.Round(time.Millisecond), mbps(after), e.conn.Stats().Lanes)
	return stall, after, nil
}

// scDeadAddr connects on a network the client hasn't seen, finding the SNI mode, with the
// profile's first node address unreachable: its SYNs vanish, as a null-routed address's do.
func scDeadAddr(ctx context.Context, o opts) []row {
	if !o.selected(tTectonic) {
		return nil
	}
	const wait = 30 * time.Second
	L, err := newPath(link.Config{Bandwidth: 100e6, RTT: 50 * time.Millisecond})
	if err != nil {
		return failed("Session with a dead first address", err)
	}
	defer L.close()
	var took []time.Duration
	for i := range o.trials {
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return failed("Session with a dead first address", err)
		}
		start := time.Now()
		c, srv, err := startTectonic(ctx, L, uint16(2100+i), udp.LocalAddr().String(), func(cfg *tectonic.Config) {
			cfg.Profile.Nodes = []string{cfg.Profile.Node}
			cfg.Profile.Node = deadNode
			cfg.SNIMode = tectonic.SNIAuto
			cfg.Network = fmt.Sprintf("bench-unseen-%d", i)
		})
		if err != nil {
			udp.Close()
			return failed("Session with a dead first address", err)
		}
		err = c.WaitForSession(ctx, wait)
		d := time.Since(start)
		c.Close()
		srv.Close()
		udp.Close()
		if err != nil {
			d = wait
		}
		took = append(took, d)
		o.logf("deadaddr trial %d: session after %v (err %v)", i+1, d.Round(time.Millisecond), err)
	}
	return []row{{
		measurement: "Session on an unseen network with a dead first node address",
		result: fmt.Sprintf("median %v, worst %v (of %d; %v means none)", percentile(took, 0.5).Round(time.Millisecond),
			percentile(took, 1).Round(time.Millisecond), len(took), wait),
	}}
}
