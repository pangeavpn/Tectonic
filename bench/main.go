// Command bench measures Tectonic against the targets in design §13.
//
// It runs the client and server in one process over a simulated link whose
// bandwidth, RTT, random and burst loss, and per-connection rate cap can
// all be set, with real WireGuard on either side, and compares Tectonic
// with plain WireGuard over UDP and with single-connection models of
// REALITY and AnyTLS under identical conditions.
//
//	go run .                      # every scenario
//	go run . -run 'clean|loss'    # some of them
//	go run . -quick               # shorter measurements
//
// Numbers depend on the machine: everything, TCP stacks included, runs in
// this process. Run on an idle machine and compare transports within one
// run rather than across runs.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
)

func main() {
	runRe := flag.String("run", "", "regexp selecting scenarios by name (default all)")
	only := flag.String("transports", "", "comma-separated transports to include (default all)")
	quick := flag.Bool("quick", false, "shorter measurements")
	dur := flag.Duration("duration", 10*time.Second, "length of each throughput measurement")
	verbose := flag.Bool("v", false, "log progress")
	list := flag.Bool("list", false, "list scenarios and exit")
	flag.BoolVar(&innerRACK, "inner-rack", false, "use RACK loss detection in the TCP inside the tunnel (gVisor's can stall on RTOs)")
	flag.Parse()

	if *list {
		for _, s := range scenarios {
			fmt.Printf("%-12s %s\n", s.name, s.desc)
		}
		return
	}
	re, err := regexp.Compile(*runRe)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(2)
	}
	o := opts{dur: *dur, warm: 3 * time.Second, capDur: 45 * time.Second, trials: 5}
	if *quick {
		o.dur, o.warm, o.capDur, o.trials = 4*time.Second, 2*time.Second, 30*time.Second, 3
	}
	o.logf = func(string, ...any) {}
	if *verbose {
		start := time.Now()
		o.logf = func(f string, a ...any) {
			fmt.Fprintf(os.Stderr, "[%6.1fs] %s\n", time.Since(start).Seconds(), fmt.Sprintf(f, a...))
		}
	}
	want := map[transport]bool{}
	for _, t := range strings.Split(*only, ",") {
		if t = strings.TrimSpace(t); t != "" {
			want[transport(t)] = true
		}
	}
	o.selected = func(t transport) bool { return len(want) == 0 || want[t] || t == tWireGuard && want[tTectonic] }

	ctx := context.Background()
	fmt.Printf("# Tectonic benchmarks\n\n%s, %s/%s, GOMAXPROCS=%d, %s per measurement, inner TCP RACK %v\n\n",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.GOMAXPROCS(0), o.dur, innerRACK)
	fmt.Println("| Measurement | Target | Result | |")
	fmt.Println("|---|---|---|---|")
	failures := 0
	for _, s := range scenarios {
		if !re.MatchString(s.name) {
			continue
		}
		o.logf("scenario %s: %s", s.name, s.desc)
		for _, r := range s.run(ctx, o) {
			mark := ""
			if r.pass != nil {
				mark = "✅"
				if !*r.pass {
					mark = "❌"
					failures++
				}
			}
			fmt.Printf("| %s | %s | %s | %s |\n", r.measurement, r.target, r.result, mark)
		}
	}
	if failures > 0 {
		fmt.Printf("\n%d target(s) missed.\n", failures)
	}
}
