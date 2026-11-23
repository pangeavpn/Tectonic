package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/pangeavpn/tectonic/bench/link"
)

const gamePort = 9

func scGame(ctx context.Context, o opts) []row { return gameRows(ctx, o, false) }

// scGameLoad is scGame beside a bulk download in the same tunnel, as when a
// game runs while something else on the device downloads.
func scGameLoad(ctx context.Context, o opts) []row { return gameRows(ctx, o, true) }

func gameRows(ctx context.Context, o opts, load bool) []row {
	lc := link.Config{Bandwidth: 50e6, RTT: 10 * time.Millisecond, Loss: 0.01, Seed: 7}
	name := "Game stream (1% loss, 10 ms): "
	if load {
		name = "Game stream beside a download (1% loss, 10 ms): "
	}
	var rows []row
	for _, tr := range []transport{tWireGuard, tTectonic, tReality} {
		if !o.selected(tr) {
			continue
		}
		rtts, lost, bulk, err := measureGame(ctx, o, tr, lc, load)
		if err != nil {
			rows = append(rows, failed(name+string(tr), err)...)
			continue
		}
		spikes := 0
		for _, d := range rtts {
			if d > 50*time.Millisecond {
				spikes++
			}
		}
		n := len(rtts) + lost
		res := fmt.Sprintf("p50 %v, p99 %v, max %v; >50ms %.2f%%, lost %.2f%%",
			percentile(rtts, 0.5).Round(time.Millisecond), percentile(rtts, 0.99).Round(time.Millisecond),
			percentile(rtts, 1).Round(time.Millisecond), 100*float64(spikes)/float64(n), 100*float64(lost)/float64(n))
		if load {
			res += "; download " + mbps(bulk)
		}
		rows = append(rows, row{measurement: name + string(tr), result: res})
	}
	return rows
}

// measureGame sends 400-byte datagrams at 60 Hz and times each echo, so a stall shows up as
// every packet queued behind it arriving late; with load, a download runs throughout.
func measureGame(ctx context.Context, o opts, tr transport, lc link.Config, load bool) ([]time.Duration, int, float64, error) {
	e, err := newEnv(ctx, tr, lc)
	if err != nil {
		return nil, 0, 0, err
	}
	defer e.Close()
	var bulk *transfer
	if load {
		if bulk, err = startDownload(ctx, e); err != nil {
			return nil, 0, 0, err
		}
		defer bulk.Stop()
	}
	s, err := e.srv.listenUDP(netip.AddrPortFrom(e.srvAddr, gamePort))
	if err != nil {
		return nil, 0, 0, err
	}
	defer s.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := s.ReadFrom(buf)
			if err != nil {
				return
			}
			s.WriteTo(buf[:n], a)
		}
	}()
	c, err := e.cli.dialUDP(netip.AddrPortFrom(e.srvAddr, gamePort))
	if err != nil {
		return nil, 0, 0, err
	}
	defer c.Close()

	var mu sync.Mutex
	sent := map[uint32]time.Time{}
	var rtts []time.Duration
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			if n < 4 {
				continue
			}
			seq := binary.BigEndian.Uint32(buf)
			mu.Lock()
			if at, ok := sent[seq]; ok {
				rtts = append(rtts, time.Since(at))
				delete(sent, seq)
			}
			mu.Unlock()
		}
	}()

	msg := make([]byte, 400)
	send := func(seq uint32, record bool) {
		binary.BigEndian.PutUint32(msg, seq)
		mu.Lock()
		if record {
			sent[seq] = time.Now()
		}
		mu.Unlock()
		c.Write(msg)
	}
	tick := time.NewTicker(time.Second / 60)
	defer tick.Stop()
	var seq uint32
	warmEnd := time.Now().Add(o.warm)
	end := warmEnd.Add(3 * o.dur)
	var b0 int64
	for now := range tick.C {
		if now.After(end) {
			break
		}
		if bulk != nil && b0 == 0 && now.After(warmEnd) {
			b0 = max(bulk.bytes.Load(), 1)
		}
		seq++
		send(seq, now.After(warmEnd))
	}
	var rate float64
	if bulk != nil {
		rate = float64(bulk.bytes.Load()-b0) * 8 / (3 * o.dur).Seconds()
	}
	time.Sleep(2 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	o.logf("%s game: %d echoed, %d lost", tr, len(rtts), len(sent))
	if e.conn != nil {
		st := e.conn.Stats()
		o.logf("%s game: lanes %d, dupes %d; received: held %d, skipped %d, late %d", tr, st.Lanes, st.Dupes, st.Held, st.Skipped, st.Late)
	}
	return append([]time.Duration(nil), rtts...), len(sent), rate, nil
}
