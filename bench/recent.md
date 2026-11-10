# Recent results: the kernel path

**Bottom line:** Tectonic was behind the REALITY and AnyTLS models for four
reasons, none of them the path's fault, and all four are fixed. It now
carries as much as the better of the two or more in ten of twelve cases, and
is level within the spread between runs in the other two. With a cubic
node it carries 2.2–3.5× as much on every lossy path and the same on clean
ones. With a BBR node, where it was behind on every path (0.24–0.93×), it
carries 1.2–1.6× as much on three lossy paths and is level (0.98–1.02×) on
LTE and the two clean ones. One thing found is not fixed: on a BBR node
Tectonic's lanes retransmit about a quarter of what they send on a clean
link, twice what one connection does (see [Still open](#still-open)).

Measured 2026-11-10 at `eecbecd` plus uncommitted changes, on Go 1.27.3,
linux/amd64, 20 cores, Linux 7.3.3. Three passes per node setting on the
kernel path and two on the simulator; figures are means, with the range in
brackets.

## What was run

| Pass | Command | Times |
|---|---|---|
| Kernel path, node on cubic | `go run . -kernel -v` | 3 |
| Kernel path, node on BBR | `go run . -kernel -server-cc bbr -v` | 3 |
| Simulator on this machine | `go run . -v` | 2 |

The kernel path is three network namespaces, client ↔ router ↔ server,
joined by veth pairs. The router has netem (delay and loss), tbf (the
bottleneck and a one-BDP queue) and fq `maxrate` (the per-connection cap) on
each egress interface. Lanes and the REALITY/AnyTLS models run on Linux TCP.
WireGuard is wireguard-go on real TUN devices, so the TCP inside the tunnel
is Linux cubic. This is the path Linux, Android, macOS and iOS lanes take in
production (`TCP_NOTSENT_LOWAT` and `TCP_INFO`), which the simulator can't
exercise.

"Before" is the first run on this path, earlier the same day: one pass per
node setting. Where a row says so, the binary from before the changes was
run again three times, so that before and after are like for like.

## Throughput (Mbit/s)

### Node on cubic

| Path | WireGuard | Tectonic | REALITY | AnyTLS | Tectonic vs the better model | Before |
|---|---|---|---|---|---|---|
| Clean (100 Mbit/s, 50 ms) | 91.6 | 87.9 (85.6–89.0) | 87.8 | 87.4 | 1.00× | 0.99× |
| 1% loss (100 Mbit/s, 50 ms) | 2.4 | 8.7 (7.9–10.1) | 2.5 (2.4–2.5) | 2.5 (2.4–2.6) | **3.5×** | 1.8× |
| Fibre (200 Mbit/s, 15 ms) | 183.1 | 178.6 (177.7–179.1) | 175.8 | 174.9 | 1.02× | 1.00× |
| Another continent (50 Mbit/s, 150 ms, 0.1% loss) | 7.3 | 18.9 (14.4–23.4) | 8.6 (8.0–9.9) | 6.3 (4.0–7.6) | **2.2×** | 1.76× |
| LTE (30 Mbit/s, 70 ms, bursty 0.4% loss) | 4.4 | 9.9 (8.6–10.8) | 4.1 (3.4–4.5) | 4.2 (3.4–4.7) | **2.3×** | 1.86× |
| Lossy international (20 Mbit/s, 200 ms, 2% loss) | 0.5 | 1.5 (1.1–1.9) | 0.5 (0.4–0.7) | 0.5 (0.4–0.7) | **2.8×** | 1.62× |

### Node on BBR

| Path | WireGuard | Tectonic | REALITY | AnyTLS | Tectonic vs the better model | Before |
|---|---|---|---|---|---|---|
| Clean (100 Mbit/s, 50 ms) | 91.6 | 82.1 (79.3–84.3) | 83.6 (82.5–84.3) | 83.7 (83.5–84.1) | 0.98× | 0.93× |
| 1% loss (100 Mbit/s, 50 ms) | 2.4 | 75.8 (71.3–80.3) | 50.1 (48.7–52.3) | 52.1 (49.3–54.9) | **1.45×** | 0.54× |
| Fibre (200 Mbit/s, 15 ms) | 183.1 | 170.7 (164.0–176.7) | 172.4 (172.0–173.2) | 171.9 (171.4–172.6) | 0.99× | 0.79× |
| Another continent (50 Mbit/s, 150 ms, 0.1% loss) | 7.2 | 39.2 (38.1–40.6) | 31.5 (30.9–32.1) | 32.0 (29.6–34.2) | **1.22×** | 0.24× |
| LTE (30 Mbit/s, 70 ms, bursty 0.4% loss) | 5.3 | 23.9 (22.9–25.5) | 23.4 (22.4–24.2) | 22.2 (21.6–22.6) | 1.02× | 0.88× |
| Lossy international (20 Mbit/s, 200 ms, 2% loss) | 0.5 | 9.0 (6.0–11.7) | 5.7 (5.6–5.9) | 5.7 (5.1–6.6) | **1.56×** | 0.34× |

The two cases under 1.00× are inside the spread between Tectonic's own runs
(79.3–84.3 and 164.0–176.7), which is wider than the models'. An earlier
set of three passes of nearly the same code gave 0.99× and 0.98× for them,
so they are level, not ahead.

WireGuard's column barely moves between the two tables because it runs over
UDP: `-server-cc` changes only the node's outer TCP connections.

## §13 targets

Ranges over the passes. A mark needs every pass to meet the target.

| Target | Simulator | Kernel, node on cubic | Kernel, node on BBR |
|---|---|---|---|
| Time to first packet ≤ 2 RTT | 2.05–2.06 ✅ | 2.03–2.06 ✅ | 2.03–2.05 ✅ |
| Clean link ≥ 90% of WireGuard | 102–113% ✅ (was 83%) | 93–97% ✅ (was 95%) | 87–92% ❌, two passes of three (was 86%) |
| Bulk overhead ≤ 3% | 3.0–3.8% ❌ | 2.8–3.1% ❌, two of three (was 3.1%) | 2.3–5.0% ❌, one of three (was 3.2%) |
| 1% loss: clearly above REALITY and AnyTLS | 2.5–2.8× ✅ (was 1.7×) | 3.0–4.1× ✅ (was 1.8×) | 1.3–1.5× ✅ (was 0.5×) |
| Rises with lanes under a 4 Mbit/s cap | 18–24 Mbit/s ✅ (was 4.8) | 23–25 Mbit/s ✅ (was 16.6) | 17–27 Mbit/s ✅ (was 7.3) |
| Latency under load ≤ 2× idle | 2.0–2.1× ❌ (was 1.8–1.9×) | 2.8–3.5× ❌ (was 2.6–3.7×) | 4.1–4.6× ❌ (was 4.4–5.9×) |
| No visible stall after a lane reset | 81–85 ms ✅ | 117–154 ms ✅ (was 126–158) | 146–249 ms ✅ (was 106–122) |
| Interactive overhead ≤ 15% | 5.4–5.7% ✅ | 3.8–4.8% ✅ (was 6.5–6.6%) | 12.8–13.0% ✅ (was 6.6–7.5%) |

The kernel "was" figures for latency, reset and interactive overhead are
three runs of the binary from before the changes; the others are the single
earlier pass. The simulator's "was" for latency is three runs of that binary
too. Under the cap the client ran six to eight lanes, counting ones being
replaced.

### Latency under load (20 Mbit/s, 50 ms), p95 against idle

| | Node on cubic | Node on BBR |
|---|---|---|
| WireGuard | 2.0× | 1.9–2.0× |
| Tectonic | 2.8–3.5× | 4.1–4.6× |
| REALITY | 12.6–12.8× | 12.7–16.1× |

## Why it was slower

The first run on this path (same day, before these changes) had Tectonic
behind both models on every path with a BBR node, and level with them on
clean links with a cubic one. That run put it down to the receiver giving up
on packets that were only late, untested. That was one cause of four. Each
was found by logging the TCP connection inside the tunnel while it ran
(`BENCH_TRACE`, see the README), and each is fixed.

### 1. The receiver gave up on packets that were only late

A lane is a TCP connection, so a packet put on one arrives unless the lane
dies. The merge waited one and a half round trips for a missing packet and
then handed on the ones behind it. A fast retransmission takes more than
one round trip, and more again while a queue on the path is full, so the
wait ran out before the packet arrived. The TCP inside the tunnel saw loss,
sent the stretch again and slowed down.

With the node's socket fixed (cause 2) and nothing else changed, on 1% loss
with a BBR node, three runs each:

| Wait | Throughput | Given up on, of which arrived later |
|---|---|---|
| 1.5 round trips, 20–150 ms (as it was) | 27–33 Mbit/s | 371–831, all |
| 3 round trips, 60–400 ms | 70 Mbit/s | 967–1556, nearly all |
| 5 round trips, 100 ms–1 s | 69–72 Mbit/s | 101–941, nearly all |
| 10 round trips, 200 ms–3 s | 68–71 Mbit/s | 255–1046 |

The wait is now four round trips plus 200 ms, at most a second: long enough
for a retransmission after a timeout, which takes the round trip plus at
least 200 ms. Across eight cases, two runs each, it carried as much as
shorter and longer waits and gave up on far fewer packets than the shorter
ones.

### 2. The node's socket to WireGuard dropped WireGuard's bursts

With the longer wait, most packets the client gave up on never arrived at
all, and the node's scheduler had dropped none. They were lost before
Tectonic saw them. Each session reads WireGuard's packets from a UDP socket
with the default 208 KB buffer, and WireGuard hands over a few hundred
packets at once when the TCP inside the tunnel gets a run of ACKs. The
kernel's count of packets dropped at that socket matched the gaps in
WireGuard's counters exactly, in three runs: 282 and 282, 190 and 190, 109
and 109.

The REALITY and AnyTLS models set a 4 MB buffer on theirs, so this was also
the bench treating the transports differently. The node now asks for 7 MB,
as wireguard-go does for its own sockets, and warns if the system's limit
gets in the way. **A node needs `net.core.rmem_max` raised** (see the main
README); this machine's is already 7.5 MB.

### 3. The scheduler couldn't see what the kernel was holding

With both of those fixed, on the 150 ms path with a BBR node nothing was
lost or given up on, and Tectonic still carried less than half of what
REALITY did (14.8 against 32.7 Mbit/s). The trace showed why:
the TCP inside the tunnel left slow start at 29 packets under Tectonic and
at 464 under REALITY, and spent the measurement climbing from there.

A connection that has just opened may send ten segments, then nothing until
they are acknowledged. The kernel takes up to 32 KB beyond that. The
scheduler counted only the lane's own queue, over a rate that started at a
default of 8.4 Mbit/s and could only rise, so a new lane looked empty and
fast. Packets given to it waited a round trip in the kernel, the merge held
everything behind them, and the inner connection saw its round trip jump
and stopped growing (HyStart allows an eighth).

The estimate now reads the connection's window, what is in flight, what is
unsent and the pacing rate from `TCP_INFO`: whenever the lane writes, and
at most every millisecond while anything is in flight. In the next run
the connection left slow start at 101 packets and carried 26.9 Mbit/s.

### 4. Records were too large for a slow lane

101 was still not 464. Nothing in a TLS record can be used until all of it
has arrived, and a lane packed up to 16 KB into one. A new BBR connection
on that path paces at about 275 KB/s, so a full record took 58 ms and every
packet in it was that late.

A record on a connection that paces now holds no more than the connection
sends in a thirty-second of the round trip (1 to 4 ms), and at least one
packet. At 100 Mbit/s that is still a full record. The inner connection
then ran its slow start to about 1300 packets, and the path went from 0.24×
the better model to 1.22×.

### Two more, found on the way

- **The merge waited for packets the sender had dropped.** A full queue
  drops, which is how the TCP inside is told to slow down. The receiver
  only knew such a packet was gone once every lane had delivered something
  beyond it, and a stalled lane says nothing, so it waited out the timer:
  about 100 of 151 drops in one run on 1% loss. The sender now reports what
  it drops, and what never reached it from WireGuard, in a new `LOST` frame
  on the lane that takes the next packet. In eight cases afterwards the
  client's count of reported packets equalled the node's count of drops
  exactly, and none was waited for.
- **The client's own buffer overflowed.** When a late packet arrives the
  merge hands on everything it held at once. The buffer between it and
  WireGuard held 1024 packets and dropped the rest: 624 in one clean-link
  run. It holds 16384 now.

### Two things the fixes got wrong at first

Both showed up in the full passes, not in the throughput cases the fixes
were made for.

- **The longer wait applied to idle lanes too.** After a lane was reset, the
  transfer stalled for 500–600 ms in two runs of six, where it had been
  under 160 ms. What the dead lane carried is gone, and a lane that happens
  to be idle can't show that it doesn't hold it. The long wait is now only
  for a lane that was delivering when the gap appeared, which is what a
  lane recovering from a loss looks like. If every lane that could still
  deliver the packet had been quiet for two round trips, the wait is one and
  a half round trips, as before.
- **Small records on connections that didn't need them.** The kernel
  reports a pacing rate for every connection and enforces it for some. A
  cubic connection on these hosts sends whatever its window has room for at
  once, so one packet to a record only cost framing, padding and a short
  TCP segment each: interactive overhead rose from 6.5% to about 10% on a
  cubic node. A lane now takes its connection to pace only if it runs BBR or has
  been seen holding back segments its window had room for.

## What changed

- `sched`: the merge waits four round trips plus 200 ms (at most a second)
  for a lane that was delivering when a gap appeared, and one and a half
  round trips for lanes that were already quiet. It takes the sender's word
  for packets that were dropped. The scheduler follows WireGuard's counters
  and reports what it drops or never received.
- `wire`, `lane`: a `LOST` frame (type `0x08`) carries those reports. Peers
  that don't know it skip it.
- `lane`: the delivery estimate for a lane with `TCP_NOTSENT_LOWAT` is made
  from the connection's window, flight, unsent bytes and pacing rate; a
  record is no larger than a paced connection sends in a thirty-second of
  the round trip.
- `server`: 7 MB buffers on the UDP socket to WireGuard, with a warning
  when the system's limit prevents it.
- client: room for 16384 packets between the merge and WireGuard.
- `bench`: `BENCH_TRACE` logs the inner TCP connection and the merge during
  a download, and `BENCH_PATHS` picks paths.

Two of these are visible from outside and worth a second look. `LOST` is a
new frame type. And a slow lane that paces now sends records smaller than
16 KB during a bulk transfer, which changes what an observer can measure.

## Still open

- **On a BBR node, Tectonic's lanes overdrive the path.** On the clean link
  the node retransmitted 24–30% of what Tectonic sent, against 10–14% for
  the single-connection models (BBR itself overruns a queue of one
  bandwidth-delay product) and under 1% for either on a cubic node. These
  are counted over the connections open at the end of the measurement.

  BBR leaves its start-up phase, where it sends at 2.89 times what it has
  measured, only after several round trips with data always waiting to be
  sent. An ACK-clocked TCP inside the tunnel rarely offers a lane more than
  it is carrying, so a lane tends to stay there: at the end of the bulk
  measurements 43 of Tectonic's 55 node connections were still in start-up,
  against 17 of the models' 39. A lane in start-up passes on whatever the
  inner TCP sends, and nothing between that and the path's queue slows it
  down. The drops cost bandwidth at the node and stall lanes, and they are
  the likely reason the two clean-link cases on a BBR node are level and
  not ahead.

  The same stalls now show as longer pauses. In the three seconds before
  the reset scenario's reset, on a clean 50 Mbit/s link, the longest pause
  in the transfer was 171–345 ms on a BBR node, where the binary from
  before the changes paused for 102–136 ms. On a cubic node it was
  35–136 ms against 30–171 ms. The merge now waits for a lane that has
  stalled where it used to give up, and on a BBR node lanes stall for
  longer.

  The fix is a limit of Tectonic's own on what a session offers its lanes.
  A limit driven by delay starves next to traffic that fills the queue, so
  it wants its own design and was left out of this change.
- **Latency under load is still over the target on this path:** 2.8–3.5×
  idle on a cubic node and 4.1–4.6× on a BBR one, much as before. The wait
  in the merge is not what sets it: with the old wait and the new on
  otherwise identical code, three runs each, the p95 was 161–185 ms and
  172–192 ms on a cubic node. Most likely pings wait behind the path's own
  queue, which cubic and BBR both fill, and behind the 32 KB a lane's
  kernel may hold; that has not been taken apart.
- **The simulator's latency under load went from 1.8–1.9× to 2.0–2.1×**
  (p95 95–100 ms to 109–111 ms), and that is the longer wait: before the
  short wait for quiet lanes was added, the old wait gave 97–102 ms on the
  same code and the new one 117–131 ms. gVisor's TCP takes 100–300 ms to
  repair a loss (see RESULTS.md), so its lanes stall for longer than the
  kernel's, and what the merge releases at the end comes as a larger burst.
- **Interactive overhead roughly doubled on a BBR node** (12.8–13.0%, from
  6.6–7.5%), still under the target. It is the price of small records on a
  paced connection: each carries its own TLS framing and often a short TCP
  segment.
- **A lane that was idle, takes a burst and loses the first segment of it**
  looks quiet to the merge and gets the short wait. Linux and Darwin say
  how much a connection has received out of order, which would settle it.
- **Bulk overhead sits on the 3% line** (2.8–3.1% on a cubic node, 2.3–5.0%
  on a BBR one), as before.
- **More lanes on a lossy path.** With a cubic node each lane carries what
  one lossy connection can, and the pool mostly stays at two to four of the
  six it may open. Opening more when lanes are held back by loss, as the
  throttle check does under a per-connection cap, should carry more.
  Untested.

## Caveats

- REALITY and AnyTLS are still the bench's single-connection models
  (`bench/baseline`), not real Xray or sing-box servers.
- The realistic paths use typical figures, not measurements. netem's random
  loss is not caused by congestion, which is the loss BBR ignores best; real
  lossy paths often look like that, but not always.
- Three passes per node setting. The low-throughput loss figures move a lot
  from run to run, and so does anything measured over ten seconds that
  depends on where a connection left slow start.
- All eight passes ran at once on 20 cores. WireGuard's clean-link reference
  read 91.6 Mbit/s in every kernel pass, as it does alone. The simulator is
  more sensitive to load; its WireGuard reference read 78–87.
- The bottleneck rate counts Ethernet headers (about 1% at full-size
  packets). fq hashes flows into 1024 buckets, so two lanes can rarely share
  a cap. A reset aborts the client's socket (`ss -K`) rather than forging a
  RST to each end.
- macOS, iOS and Android take the same lane path as Linux, but only Linux
  was run. The Darwin code that reads the connection's window compiles and
  is untested.

## Reproducing

Load the modules once per boot, as root, in a real terminal:

```sh
sudo modprobe -a veth sch_netem sch_tbf sch_fq tcp_bbr inet_diag tcp_diag
```

Then, with no root needed:

```sh
cd bench
go test ./knet              # checks the path itself
go run . -kernel -v
go run . -kernel -server-cc bbr -v
BENCH_TRACE=250ms go run . -kernel -run '^loss$' -transports tectonic -v
```

Each full pass takes about 8 minutes. Independent passes can run in
parallel: each gets its own namespaces.
