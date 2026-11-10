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
//	go run . -kernel              # over a kernel path (Linux; see bench/knet)
//
// Numbers depend on the machine: on the simulated link everything, TCP
// stacks included, runs in this process. Run on an idle machine and compare
// transports within one run rather than across runs.
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

	"github.com/pangeavpn/tectonic/bench/knet"
)

func main() {
	runRe := flag.String("run", "", "regexp selecting scenarios by name (default all)")
	only := flag.String("transports", "", "comma-separated transports to include (default all)")
	quick := flag.Bool("quick", false, "shorter measurements")
	dur := flag.Duration("duration", 10*time.Second, "length of each throughput measurement")
	verbose := flag.Bool("v", false, "log progress")
	list := flag.Bool("list", false, "list scenarios and exit")
	flag.BoolVar(&innerRACK, "inner-rack", false, "use RACK loss detection in the TCP inside the tunnel (gVisor's can stall on RTOs)")
	useKernel := flag.Bool("kernel", false, "run over a kernel path: network namespaces, veth and netem/tbf/fq, with Linux TCP (Linux only; needs the modules listed in bench/knet)")
	inner := flag.String("inner", "kernel", "with -kernel, the TCP inside the tunnel: kernel (TUN devices) or gvisor")
	serverCC := flag.String("server-cc", "", "with -kernel, congestion control for the node's outer TCP connections, e.g. bbr (default: the kernel's, cubic)")
	flag.Parse()

	if *useKernel {
		code, ran, err := knet.Reexec()
		if ran {
			os.Exit(code)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "bench:", err)
			os.Exit(1)
		}
		if kernel, err = knet.New(); err != nil {
			fmt.Fprintln(os.Stderr, "bench:", err)
			os.Exit(1)
		}
		defer kernel.Close()
		kernel.ServerCC = *serverCC
		switch *inner {
		case "kernel":
			kernelInner = true
		case "gvisor":
		default:
			fmt.Fprintf(os.Stderr, "bench: -inner %q: want kernel or gvisor\n", *inner)
			os.Exit(2)
		}
	}

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
	fmt.Printf("# Tectonic benchmarks\n\n%s, %s/%s, GOMAXPROCS=%d, %s per measurement\n\n%s\n\n",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.GOMAXPROCS(0), o.dur, describePath())
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
