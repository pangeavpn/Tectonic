# Benchmark results

**Bottom line:** on this simulator Tectonic now meets seven of the eight §13
targets in the latest full run, where the first run met three. On a clean
link it carries 81–101% of what plain WireGuard does (92% on average over
eleven runs), against 17% before. Interactive overhead is 9%, against 29%.
Latency under load is the target still in doubt: it lands on either side of
the line from run to run. Per design §13 Tectonic isn't called faster until
the numbers exist on real networks, and the bench measures only one of the two
paths a lane can take; see [What this doesn't measure](#what-this-doesnt-measure).

## Latest full run

`go run .` at the commit that added this version of the file. Go 1.27.3,
darwin/amd64, 4 cores, inner TCP without RACK, on a machine that was nearly
idle (load average 2.5–5.5).

| Measurement | Target | Result | |
|---|---|---|---|
| Time to first WireGuard packet | ≤ 2 RTT | 2.08 RTT (median of 5, in measured round trips of 51.3 ms on a 50 ms link) | ✅ |
| Clean link: wireguard | | 86.5 Mbit/s | |
| Clean link: tectonic | | 87.2 Mbit/s | |
| Clean link: reality | | 85.1 Mbit/s | |
| Clean link: anytls | | 84.7 Mbit/s | |
| Throughput on a clean link (100 Mbit/s, 50 ms) | ≥ 90% of plain WireGuard over UDP | 101% (87.2 vs 86.5 Mbit/s) | ✅ |
| Bandwidth overhead, bulk transfer | ≤ 3% | 0.6% more link bytes than WireGuard over UDP | ✅ |
| 1% loss: wireguard | | 2.1 Mbit/s | |
| 1% loss: tectonic | | 1.6 Mbit/s | |
| 1% loss: reality | | 1.0 Mbit/s | |
| 1% loss: anytls | | 1.0 Mbit/s | |
| Throughput with 1% random loss | Clearly above REALITY and AnyTLS | 1.6× the better of the two | ✅ |
| 4 Mbit/s per-connection cap: reality | | 3.3 Mbit/s | |
| Throughput under a 4 Mbit/s per-connection cap | Rises with the number of lanes, up to max_lanes | 9.7 Mbit/s with 3 lanes after 45 s (most lanes seen: 3) | ✅ |
| Latency under load: wireguard | | idle 53 ms; loaded p50 73 ms, p95 91 ms (1.7× idle) | |
| Latency under load (20 Mbit/s, 50 ms) | Ping stays within 2× idle RTT | idle 56 ms; loaded p50 83 ms, p95 115 ms (2.1× idle) | ❌ |
| Latency under load: reality | | idle 54 ms; loaded p50 86 ms, p95 267 ms (5.0× idle) | |
| Recovery from a reset lane | No visible stall in a TCP transfer inside the tunnel | longest stall 79 ms after the reset (none before); 35.6 Mbit/s afterwards | ✅ |
| Reset during a transfer: reality | | the transfer carried nothing after the reset | |
| Bandwidth overhead, interactive use | ≤ 15% | 8.8% more link bytes than WireGuard over UDP | ✅ |

## Clean link, eleven runs

The full run above and ten of `go run . -run clean -transports tectonic`, all
at the same commit.

| Run | WireGuard | Tectonic | Ratio |
|---|---|---|---|
| 1 (the full run) | 86.5 Mbit/s | 87.2 Mbit/s | 101% |
| 2 | 79.4 Mbit/s | 76.4 Mbit/s | 96% |
| 3 | 88.2 Mbit/s | 78.1 Mbit/s | 89% |
| 4 | 86.6 Mbit/s | 80.3 Mbit/s | 93% |
| 5 | 89.0 Mbit/s | 72.1 Mbit/s | 81% |
| 6 | 88.0 Mbit/s | 79.2 Mbit/s | 90% |
| 7 | 88.2 Mbit/s | 80.2 Mbit/s | 91% |
| 8 | 87.1 Mbit/s | 82.1 Mbit/s | 94% |
| 9 | 88.1 Mbit/s | 81.5 Mbit/s | 93% |
| 10 | 86.7 Mbit/s | 87.8 Mbit/s | 101% |
| 11 | 88.0 Mbit/s | 72.8 Mbit/s | 83% |

The mean is 92%. Seven of the eleven are at or above 90%, and run 6 misses
it by a rounding. So the target is met more often than not, and not every
time. Bulk overhead in runs 1–6 was 0.6%, 0.0%, 1.6%, 2.3%, 3.7% and 0.8%.

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
is what brought latency under load from 2.9× of idle to about 2×.

## Interactive overhead: from 29% to 9%

Counting where the bytes went showed that padding was the largest single
cost, but not for the reason first given. Nearly every packet was going out
as a record of its own:

| Share of payload, both directions | Before | After |
|---|---|---|
| What plain WireGuard puts on the link | 115% | 115% |
| What Tectonic puts on the link | 149% | 124% |
| of which padding | 19% | 3% |
| of which TCP/IP headers and TCP's own ACKs | 16% | 10% |
| of which TLS framing | 2% | 1% |
| Link packets, for 740–820 WireGuard packets | 1882 | 1192 |

Packets inside the tunnel come in trains: the segments of a reply, the ACKs
that answer them. One to a record, each was padded up to a bucket by itself,
paid for its own TLS framing and, being slightly larger than one TCP segment
with them, went out as two. Two changes:

- **A record waits up to a millisecond to fill** (less on a short path: a
  sixteenth of the round trip). That alone took the overhead to about 10.5%.
  Shorter waits save less: 13% at 250 µs and 10.5% at 500 µs with both
  changes in, against 9% at 1 ms; 2 ms gains nothing more.
- **A few packets that would need a lot of padding together are divided
  between two records.** Three full-size packets pad from 4.4 KB to the 6144
  bucket as one record; as two and one they pad by 250 bytes in all, and
  every record still comes out at a bucket's size. Over five pairs of runs
  this was worth 1.7 points (8.9% against 10.6%).

Seventeen runs of the final code gave 8.1–9.7%. The wait also packs the ACKs
of a bulk download, which is why bulk overhead, 2–4% before, is now under the
3% target in five runs of six. It costs latency: an idle ping inside the
tunnel measures 54–56 ms where it measured 52–53.

About 6 of the 9 points left are TCP's own: a 52-byte header where UDP has
28, and an ACK for every other segment. Another 2.5 are padding, which the
profile's bucket table sets; the buckets in the default profile are
placeholders until real Chrome sessions are recorded (milestone M5), and a
finer table would pad less at the price of hiding sizes less well.

## What the misses and the variation come from

**Clean link, run to run (81–101%).** Start-up is now clean in nearly every
run: no loss and nothing late. What varies is where the inner TCP itself
leaves slow start. gVisor's HyStart stops at the first rise of about 6 ms in
round-trip time. When that happens near the link's capacity the flow sits at
87–89 Mbit/s from the first second, level with WireGuard. When jitter trips
it at half of capacity, the flow spends the measurement climbing. The other
cost is hand-over on a saturated link: a new TCP connection next to a busy one
grows slowly whatever Tectonic does, and now and then a queue on the path
still overflows during one, which stalls a lane.

**Latency under load (2.1× here; 1.7–2.1× over four runs).** On the line, not
clear of it. Plain WireGuard measures 1.7–1.8× on the same link. What is left
is the queue below the lane: a lane at capacity keeps up to half a round
trip's worth of data outstanding beyond what the path carries at once, and a
ping waits behind that. The millisecond a record waits adds a little to both
the idle and the loaded figure.

**1% loss (1.6× here, 1.0–1.6× over several runs).** Every transport manages
1–2 Mbit/s on this link, so the ratio moves with the noise and should not be
read as settled. A lost segment stalls its lane for 100–300 ms on this TCP
stack, which is longer than the receiver can wait without the inner TCP
timing out, so the inner TCP still sees most outer losses as reordering.
Tectonic does not yet turn several lossy lanes into several times the
throughput.

**Per-connection cap (9.7 Mbit/s over three lanes).** Well above the
4 Mbit/s one connection gets, and the pool grew to a third lane and kept it.
Three capped lanes could carry 12. An earlier run of the same scenario gave
5.8 Mbit/s over two lanes.

## What this doesn't measure

The simulated hosts are gVisor stacks with no `TCP_NOTSENT_LOWAT` or
`TCP_INFO`. Every lane here therefore estimates its rate from PING/PONG, caps
what it has written and paces itself. Most of the lane changes above are to
that path, which in production only Windows takes.

Linux, Android, macOS and iOS take the other path: the kernel holds at most
32 KB unsent, and rate and RTT come from `TCP_INFO`. The receiver's merge, the
scheduler, the queue limit, small-packet priority, the way records are filled
and hand-over are shared and apply there too, but **that path has not been measured**. One thing to
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
