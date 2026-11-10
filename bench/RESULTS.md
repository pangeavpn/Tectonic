# Benchmark results

**Bottom line:** on this simulator Tectonic now meets six of the eight §13
targets, where the first run met three. On a clean link it carries 88–100% of
what plain WireGuard does, against 17% before. It still misses the interactive
overhead target, and sits on the line for bulk overhead. Per design §13 it
isn't called faster until the numbers exist on real networks, and the bench
measures only one of the two paths a lane can take; see
[What this doesn't measure](#what-this-doesnt-measure).

## Latest full run

`go run .` at the commit that added this version of the file. Go 1.27.3,
darwin/amd64, 4 cores, inner TCP without RACK. The machine was **not idle**
during this run: plain WireGuard reached 48 Mbit/s on the clean link, where
it reaches 87–90 on a quiet machine. Transports within the run share the same
conditions, so the comparisons hold, but for clean-link throughput and bulk
overhead read the five quieter runs in the next section.

| Measurement | Target | Result | |
|---|---|---|---|
| Time to first WireGuard packet | ≤ 2 RTT | 2.06 RTT (median of 5, in measured round trips of 53.5 ms on a 50 ms link) | ✅ |
| Clean link: wireguard | | 48.4 Mbit/s | |
| Clean link: tectonic | | 52.4 Mbit/s | |
| Clean link: reality | | 51.6 Mbit/s | |
| Clean link: anytls | | 29.4 Mbit/s | |
| Throughput on a clean link (100 Mbit/s, 50 ms) | ≥ 90% of plain WireGuard over UDP | 108% (52.4 vs 48.4 Mbit/s) | ✅ |
| Bandwidth overhead, bulk transfer | ≤ 3% | 4.8% more link bytes than WireGuard over UDP | ❌ |
| 1% loss: wireguard | | 2.0 Mbit/s | |
| 1% loss: tectonic | | 1.4 Mbit/s | |
| 1% loss: reality | | 0.9 Mbit/s | |
| 1% loss: anytls | | 1.0 Mbit/s | |
| Throughput with 1% random loss | Clearly above REALITY and AnyTLS | 1.5× the better of the two | ✅ |
| 4 Mbit/s per-connection cap: reality | | 3.3 Mbit/s | |
| Throughput under a 4 Mbit/s per-connection cap | Rises with the number of lanes, up to max_lanes | 5.8 Mbit/s with 2 lanes after 45 s (most lanes seen: 3) | ✅ |
| Latency under load: wireguard | | idle 52 ms; loaded p50 76 ms, p95 87 ms (1.7× idle) | |
| Latency under load (20 Mbit/s, 50 ms) | Ping stays within 2× idle RTT | idle 53 ms; loaded p50 82 ms, p95 97 ms (1.8× idle) | ✅ |
| Latency under load: reality | | idle 53 ms; loaded p50 154 ms, p95 276 ms (5.2× idle) | |
| Recovery from a reset lane | No visible stall in a TCP transfer inside the tunnel | longest stall 37 ms after the reset (40 ms before); 39.5 Mbit/s afterwards | ✅ |
| Reset during a transfer: reality | | transfer stopped: the tunnel did not survive the reset | |
| Bandwidth overhead, interactive use | ≤ 15% | 27.1% more link bytes than WireGuard over UDP | ❌ |

## Clean link, five runs on a quieter machine

`go run . -run clean -transports tectonic`, back to back.

| Run | WireGuard | Tectonic | Ratio | Bulk overhead |
|---|---|---|---|---|
| 1 | 86.9 Mbit/s | 87.1 Mbit/s | 100% | 1.9% |
| 2 | 90.0 Mbit/s | 86.7 Mbit/s | 96% | 3.0% |
| 3 | 89.7 Mbit/s | 78.6 Mbit/s | 88% | 3.5% |
| 4 | 89.7 Mbit/s | 81.4 Mbit/s | 91% | 2.3% |
| 5 | 87.2 Mbit/s | 82.9 Mbit/s | 95% | 3.6% |

Four of the five meet the 90% target; the mean is 83.3 against 88.7 Mbit/s,
94%. Bulk overhead is at the 3% target, on either side of it from run to run.

## Why it was slow, and what changed

The first version of this file put the clean-link result (17% of WireGuard)
down to the simulator. That was wrong. Tracing the TCP connection inside the
tunnel showed where the time went: after the first second nothing was being
dropped or reordered and the lanes had almost nothing queued. The flow was
simply growing, a few Mbit/s per second, from a very small congestion window.
**Tectonic had ended its slow start early**, and a TCP flow on a 100 Mbit/s,
50 ms path that leaves slow start at a tenth of capacity needs far longer than
a ten-second measurement to climb the rest. Plain WireGuard never does that to
it: the flow runs straight up to what the link carries.

Four things did the damage, and each has been changed:

1. **Packets arrived out of order.** The scheduler sent each packet on the lane
   with the earliest estimate, so consecutive packets alternated between lanes
   and 12–25% arrived late. The inner TCP read each as a loss.
   - The receiver now merges the lanes back into order. Each lane is itself
     an ordered stream, so a missing packet is known to be lost, not late, as
     soon as every lane has delivered something beyond it; nothing has to
     guess with a short timer.
   - The scheduler keeps traffic on one lane while one lane is enough, and
     spills to the next only once the first is behind.
2. **Packets were dropped while a lane was still warming up.** A lane's queue
   was limited to a round trip's worth at its estimated rate, and while a
   connection is in slow start that estimate is two to four times too low.
   The limit now goes by how long the oldest queued packet has waited.
3. **Lanes held the tunnel back.** Without `TCP_NOTSENT_LOWAT` a lane limits
   what it writes to a multiple of its measured rate. That measure trailed a
   connection that doubles every round trip, so the lane delayed traffic its
   own connection could have carried, and the inner TCP's HyStart takes a rise
   of a few milliseconds in round-trip time as its cue to stop growing. The
   window is now wider while the lane's rate is still rising.
4. **Every lane hand-over cost a loss.** At 100 Mbit/s the byte budget replaces
   a lane every few seconds. The replacement got no traffic until the old lane
   retired, then got all of it at once on a cold connection.
   - A replacement is now preferred from the moment it joins, and is offered
     only a little more than it has been seen to carry, so it takes the
     traffic over as fast as its connection really grows.
   - The old lane stays until the traffic has moved off it.
   - A lane at capacity paces its writes, and keeps what it can't send in its
     own queue. Before, a burst from the tunnel went straight to TCP, the
     queue on the link overflowed, and the lane stalled on a retransmission.

Small packets (pings, ACKs) also go out ahead of queued bulk data now, which
is what brought latency under load from 2.9× to 1.8× of idle.

## What the misses and the variation come from

**Clean link, run to run (88–100%).** Start-up is now clean in nearly every
run: no loss and nothing late. What varies is where the inner TCP itself
leaves slow start. gVisor's HyStart stops at the first rise of about 6 ms in
round-trip time. When that happens near the link's capacity the flow sits at
87–89 Mbit/s from the first second, level with WireGuard. When jitter trips
it at half of capacity, the flow spends the measurement climbing. The other
cost is hand-over on a saturated link: a new TCP connection next to a busy one
grows slowly whatever Tectonic does, and until it has grown the stream runs a
few milliseconds later than it otherwise would.

**Bulk overhead (1.9–3.6%, target 3%).** PINGs and their PONGs, several per
round trip on this path, plus TLS and TCP headers on records that go out
before they fill. It was 9.4%; most of that was padding on the small records
of a slow transfer.

**1% loss (1.5× here, 1.0–1.5× over several runs).** Every transport manages
1–2 Mbit/s on this link, so the ratio moves with the noise and should not be
read as settled. A lost segment stalls its lane for 100–300 ms on this TCP
stack, which is longer than the receiver can wait without the inner TCP
timing out, so the inner TCP still sees most outer losses as reordering.
Tectonic does not yet turn several lossy lanes into several times the
throughput.

**Latency under load (1.8× here).** Two other runs of this scenario gave
1.6× and 2.2×, so it is on the line, not clear of it. Plain WireGuard measures
1.7–1.8× on the same link. What is left is the queue below the lane: a lane
at capacity keeps up to half a round trip's worth of data outstanding beyond
what the path carries at once, and a ping waits behind that.

**Per-connection cap (5.8 Mbit/s over two lanes).** Above the 4 Mbit/s one
connection gets, and the pool probed a third lane. The pass mark is lenient;
two capped lanes could carry 8.

**Interactive overhead (27%).** Small records pay for TLS and TCP headers,
and are padded up to the default profile's buckets. Those buckets are
placeholders until real Chrome sessions are recorded (milestone M5). Nothing
in this round of changes was aimed at it.

## What this doesn't measure

The simulated hosts are gVisor stacks with no `TCP_NOTSENT_LOWAT` or
`TCP_INFO`. Every lane here therefore estimates its rate from PING/PONG, caps
what it has written and paces itself. Most of the lane changes above are to
that path, which in production only Windows takes.

Linux, Android, macOS and iOS take the other path: the kernel holds at most
32 KB unsent, and rate and RTT come from `TCP_INFO`. The receiver's merge, the
scheduler, the queue limit, small-packet priority and hand-over are shared
and apply there too, but **that path has not been measured**. One thing to
check on it: a lane that has just opened can still hide up to 32 KB in the
kernel, which is several round trips' worth for a cold connection, and the
scheduler does not see it.

Measuring that path needs a link simulator built from kernel parts: on Linux,
network namespaces joined by veth pairs with `tc netem` and `tbf` shaping,
which needs root. This macOS machine can't run that.

The inner TCP is also gVisor's. A kernel TCP adapts its reordering window
and adds 200 ms to its round trip before it times out, where gVisor's floor
is 200 ms in all, so it should be more forgiving of the short waits the merge
introduces. That is untested as well.
