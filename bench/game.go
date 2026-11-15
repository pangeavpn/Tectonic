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

func scGame(ctx context.Context, o opts) []row {
	lc := link.Config{Bandwidth: 50e6, RTT: 10 * time.Millisecond, Loss: 0.01, Seed: 7}
	var rows []row
	for _, tr := range []transport{tWireGuard, tTectonic, tReality} {
		if !o.selected(tr) {
			continue
		}
		rtts, lost, err := measureGame(ctx, o, tr, lc)
		if err != nil {
			rows = append(rows, failed("Game stream: "+string(tr), err)...)
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
		rows = append(rows, row{measurement: "Game stream (1% loss, 10 ms): " + string(tr), result: res})
	}
	return rows
}

// measureGame sends 400-byte datagrams at 60 Hz and times each echo, so a
// stall shows up as every packet queued behind it arriving late.
func measureGame(ctx context.Context, o opts, tr transport, lc link.Config) ([]time.Duration, int, error) {
	e, err := newEnv(ctx, tr, lc)
	if err != nil {
		return nil, 0, err
	}
	defer e.Close()
	s, err := e.srv.listenUDP(netip.AddrPortFrom(e.srvAddr, gamePort))
	if err != nil {
		return nil, 0, err
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
		return nil, 0, err
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
	for now := range tick.C {
		if now.After(end) {
			break
		}
		seq++
		send(seq, now.After(warmEnd))
	}
	time.Sleep(2 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	o.logf("%s game: %d echoed, %d lost", tr, len(rtts), len(sent))
	return append([]time.Duration(nil), rtts...), len(sent), nil
}
