# Benchmark results

**Bottom line:** on this simulator Tectonic meets three of the eight §13
targets and misses five, most by a wide margin. Per design §13 it isn't called
faster until the numbers exist, and they don't yet. Read the caveats below
before drawing conclusions about real platforms.

## Latest full run

`go run .` at the commit that added this file. Go 1.27.3, darwin/amd64,
4 cores, inner TCP without RACK. The machine was **not idle**: the load
average was 12.6 when the run started. Transports within the run share the
same conditions.

| Measurement | Target | Result | |
|---|---|---|---|
| Time to first WireGuard packet | ≤ 2 RTT | 2.06 RTT (median of 5, in measured round trips of 52 ms on a 50 ms link) | ✅ |
| Clean link: wireguard | | 83.8 Mbit/s | |
| Clean link: tectonic | | 14.2 Mbit/s | |
| Clean link: reality | | 85.2 Mbit/s | |
| Clean link: anytls | | 78.8 Mbit/s | |
| Throughput on a clean link (100 Mbit/s, 50 ms) | ≥ 90% of plain WireGuard over UDP | 17% (14.2 vs 83.8 Mbit/s) | ❌ |
| Bandwidth overhead, bulk transfer | ≤ 3% | 9.4% more link bytes than WireGuard over UDP | ❌ |
| 1% loss: wireguard | | 2.2 Mbit/s | |
| 1% loss: tectonic | | 1.4 Mbit/s | |
| 1% loss: reality | | 1.0 Mbit/s | |
| 1% loss: anytls | | 1.0 Mbit/s | |
| Throughput with 1% random loss | Clearly above REALITY and AnyTLS | 1.4× the better of the two | ✅ |
| 4 Mbit/s per-connection cap: reality | | 3.3 Mbit/s | |
| Throughput under a 4 Mbit/s per-connection cap | Rises with the number of lanes, up to max_lanes | 2.7 Mbit/s with 3 lanes after 45 s | ❌ |
| Latency under load: wireguard | | idle 53 ms; loaded p50 73 ms, p95 92 ms (1.8× idle) | |
| Latency under load (20 Mbit/s, 50 ms) | Ping stays within 2× idle RTT | idle 52 ms; loaded p50 95 ms, p95 150 ms (2.9× idle) | ❌ |
| Latency under load: reality | | idle 53 ms; loaded p50 80 ms, p95 267 ms (5.1× idle) | |
| Recovery from a reset lane | No visible stall in a TCP transfer inside the tunnel | longest stall 282 ms after the reset (282 ms before it); 10.2 Mbit/s afterwards | ✅ |
| Reset during a transfer: reality | | transfer stopped: the tunnel did not survive the reset | |
| Bandwidth overhead, interactive use | ≤ 15% | 29.2% more link bytes than WireGuard over UDP | ❌ |

## What the misses come from

**Clean-link throughput (17%).** This is the important miss, and the numbers
vary widely. Runs of nearly the same code gave Tectonic anywhere from 14 to
64 Mbit/s on this link. The mechanism is reordering between lanes, which the
TCP inside the tunnel reads as loss:

- One lane on its own does fine. A bare lane over this link reaches 96 Mbit/s.
  With the node capped at one lane (`BENCH_MAXLANES=1`), the full stack
  reached 68 Mbit/s, against 24 Mbit/s with two lanes before the fallback
  window existed. Neither run dropped a packet.
- With two lanes, the inner TCP logs a few dozen spurious recoveries early in
  the transfer. That timing varies from run to run, and so does the
  throughput.
- Two things in the simulator make this much worse than it would be on the
  platforms Tectonic targets:
  1. The simulated hosts are gVisor stacks with no `TCP_NOTSENT_LOWAT` or
     `TCP_INFO`, so every lane here runs the PING/PONG fallback, which only
     Windows uses in production. That fallback lets up to one
     bandwidth-delay product wait unsent in the kernel per lane. With the
     real option the kernel holds 32 KB, about 3 ms at 100 Mbit/s.
  2. The inner TCP is also gVisor's. With RACK it can stall on timeouts for
     seconds after spurious recoveries; one full run saw the AnyTLS model
     collapse to 5.6 Mbit/s that way. Without RACK, three duplicate ACKs
     trigger a retransmit. Linux's TCP adapts its reordering window instead.

**Bulk overhead (9.4%).** Bulk records are packed up to 16 KB only while a
lane is busy. In runs where throughput was high, the overhead was 3–4%, and
0.8% in one. At 14 Mbit/s, many records are still small and padded.

**Per-connection cap.** The pool probed a third lane and kept two. Throughput
was about 3 Mbit/s against the 8 Mbit/s two capped lanes could carry, so the
cap wasn't the limit: the inner TCP was, as above. Throttle detection
correctly saw no payoff from more lanes.

**Latency under load (2.9×).** Again the fallback: up to about one
bandwidth-delay product waits in each lane's TCP stack. Lanes with
`TCP_NOTSENT_LOWAT` keep that queue in the scheduler, where it is bounded to
about one round trip.

**Interactive overhead (29%).** Small records pay for TLS and TCP headers,
and are padded up to the default profile's buckets. Those buckets are
placeholders until real Chrome sessions are recorded (milestone M5).

## What would settle it

The production path for Linux, Android, macOS and iOS is lanes with
`TCP_NOTSENT_LOWAT` and `TCP_INFO`, carrying a kernel TCP inside the tunnel.
Measuring that path needs a link simulator built from kernel parts: on Linux,
network namespaces joined by veth pairs with `tc netem` and `tbf` shaping,
which needs root. This macOS machine can't run that, so these numbers measure
the fallback path under a reordering-sensitive inner TCP.

The fallback path itself (Windows clients) needs more work before it meets
the targets. The open question is how to bound kernel backlog without also
capping the TCP connection's in-flight data. Windows' `SIO_TCP_INFO` would
give it the in-flight and congestion-window figures it currently has to
infer from PONGs.
