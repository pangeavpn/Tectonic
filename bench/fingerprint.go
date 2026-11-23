package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"

	"github.com/pangeavpn/tectonic/bench/link"
)

// scFingerprint measures what tells a session from a browser's: a browser holds one connection per
// address, and sends 0.5 to 1.5 records per MB upstream while downloading (design §8, §9).
func scFingerprint(ctx context.Context, o opts) []row {
	if !o.selected(tTectonic) {
		return nil
	}
	lc := link.Config{Bandwidth: 100e6, RTT: 50 * time.Millisecond}
	var rows []row
	for _, use := range []string{"browsing", "downloading"} {
		name := "Fingerprint while " + use
		res, err := measureFingerprint(ctx, o, lc, use == "downloading")
		if err != nil {
			rows = append(rows, failed(name, err)...)
			continue
		}
		rows = append(rows, row{measurement: name, result: res})
	}
	return rows
}

func measureFingerprint(ctx context.Context, o opts, lc link.Config, download bool) (string, error) {
	e, err := newEnv(ctx, tTectonic, lc)
	if err != nil {
		return "", err
	}
	defer e.Close()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var bulk *transfer
	if download {
		if bulk, err = startDownload(ctx, e); err != nil {
			return "", err
		}
		defer bulk.Stop()
	} else {
		ln, err := e.srv.listenTCP(netip.AddrPortFrom(e.srvAddr, 8081))
		if err != nil {
			return "", err
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			req := make([]byte, 3)
			for {
				if _, err := readFull(c, req); err != nil {
					return
				}
				if _, err := c.Write(make([]byte, int(req[0])<<16|int(req[1])<<8|int(req[2]))); err != nil {
					return
				}
			}
		}()
		c, err := e.cli.dialTCP(ctx, netip.AddrPortFrom(e.srvAddr, 8081))
		if err != nil {
			return "", err
		}
		defer c.Close()
		wg.Go(func() {
			rng := rand.New(rand.NewPCG(3, 4))
			buf := make([]byte, 64<<10)
			for {
				select {
				case <-stop:
					return
				default:
				}
				n := 2<<10 + rng.IntN(40<<10)
				if _, err := c.Write([]byte{byte(n >> 16), byte(n >> 8), byte(n)}); err != nil {
					return
				}
				if _, err := readFull(c, buf[:n]); err != nil {
					return
				}
				time.Sleep(time.Duration(100+rng.IntN(1900)) * time.Millisecond) // reading the page
			}
		})
	}
	time.Sleep(o.warm)
	r0, b0 := e.conn.Stats().Records, int64(0)
	if bulk != nil {
		b0 = bulk.bytes.Load()
	}
	var samples, more int
	for end := time.Now().Add(3 * o.dur); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		samples++
		if e.conn.Stats().Lanes > 1 {
			more++
		}
	}
	close(stop)
	wg.Wait()
	res := fmt.Sprintf("more than one connection open %.0f%% of the time", 100*float64(more)/float64(samples))
	if bulk != nil {
		mb := float64(bulk.bytes.Load()-b0) / (1 << 20)
		res += fmt.Sprintf("; %.1f client records per MB downloaded", float64(e.conn.Stats().Records-r0)/mb)
	}
	return res, nil
}
