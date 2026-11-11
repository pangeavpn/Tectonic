# Recent results: the kernel path

**Bottom line:** Tectonic was behind the REALITY and AnyTLS models for four
reasons, none of them the path's fault, and all four are fixed. It now
carries as much as the better of the two or more in eleven of twelve cases.
In the twelfth, the clean link with a BBR node, it is 1% behind REALITY and
level with AnyTLS. With a cubic node it carries 2.2–3.4× as much on every
lossy path and the same on clean ones. With a BBR node, where it was behind
on every path (0.24–0.93×), it carries 1.1–1.5× as much on three lossy
paths and is level on LTE and the two clean ones.

A fifth problem, found while fixing those, is fixed too: on a BBR node the
lanes overdrove the path and retransmitted a quarter of what they sent on a
clean link. They now retransmit 0.3–2.2%, against 10–14% for the
single-connection models (see [The send limit](#the-send-limit)). That fix
costs something under a per-connection cap with a BBR node (see
[Still open](#still-open)).

Measured 2026-11-10 with the code at `853c24a`, on Go 1.27.3, linux/amd64,
20 cores, Linux 7.3.3. Three passes per node setting on the kernel path and
two on the simulator; figures are means, with the range in brackets.

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
run again three times, so that before and after are like for like. "Before
the limit" is three passes of the code as committed at `a44b0b2`.

## Throughput (Mbit/s)

### Node on cubic

| Path | WireGuard | Tectonic | REALITY | AnyTLS | Tectonic vs the better model | Before |
|---|---|---|---|---|---|---|
| Clean (100 Mbit/s, 50 ms) | 91.6 | 88.1 (86.6–89.0) | 87.8 | 87.4 | 1.00× | 0.99× |
| 1% loss (100 Mbit/s, 50 ms) | 2.4 | 8.4 (8.0–8.7) | 2.5 (2.3–2.6) | 2.3 (2.2–2.5) | **3.4×** | 1.8× |
| Fibre (200 Mbit/s, 15 ms) | 183.1 | 178.7 (178.1–179.0) | 175.8 | 175.0 | 1.02× | 1.00× |
| Another continent (50 Mbit/s, 150 ms, 0.1% loss) | 7.2 | 16.6 (15.7–17.7) | 7.6 (6.2–8.4) | 7.5 (7.1–8.2) | **2.2×** | 1.76× |
| LTE (30 Mbit/s, 70 ms, bursty 0.4% loss) | 3.7 | 10.3 (8.8–12.5) | 4.1 (3.4–4.5) | 4.1 (3.4–4.5) | **2.5×** | 1.86× |
| Lossy international (20 Mbit/s, 200 ms, 2% loss) | 0.5 | 1.6 (1.4–1.8) | 0.4 (0.4–0.5) | 0.5 (0.4–0.5) | **3.4×** | 1.62× |

### Node on BBR

| Path | WireGuard | Tectonic | REALITY | AnyTLS | Tectonic vs the better model | Before |
|---|---|---|---|---|---|---|
| Clean (100 Mbit/s, 50 ms) | 91.6 | 83.4 (83.3–83.6) | 84.3 (83.8–85.0) | 83.7 (83.4–83.8) | 0.99× | 0.93× |
| 1% loss (100 Mbit/s, 50 ms) | 2.4 | 79.2 (76.7–81.6) | 52.9 (51.7–53.8) | 54.1 (53.3–54.6) | **1.46×** | 0.54× |
| Fibre (200 Mbit/s, 15 ms) | 183.1 | 172.5 (169.3–174.4) | 172.1 (171.8–172.5) | 171.6 (171.0–172.5) | 1.00× | 0.79× |
| Another continent (50 Mbit/s, 150 ms, 0.1% loss) | 7.3 | 37.4 (36.4–39.2) | 32.3 (30.4–33.4) | 31.6 (30.0–34.0) | **1.16×** | 0.24× |
| LTE (30 Mbit/s, 70 ms, bursty 0.4% loss) | 5.7 | 22.2 (19.5–24.0) | 22.2 (21.7–22.8) | 22.0 (21.2–22.5) | 1.00× | 0.88× |
| Lossy international (20 Mbit/s, 200 ms, 2% loss) | 0.6 | 6.7 (6.5–6.9) | 6.0 (4.8–7.1) | 5.8 (5.0–6.2) | **1.12×** | 0.34× |

The clean link with a BBR node reads 0.99×: 83.4 against 84.3 for REALITY
and 83.7 for AnyTLS. The 1% to REALITY is small but there in every pass
(83.3–83.6 against 83.8–85.0); AnyTLS's passes overlap Tectonic's. BBR
itself gives up about 9% of the link there for every transport (WireGuard
over UDP carries 91.6).

WireGuard's column barely moves between the two tables because it runs over
UDP: `-server-cc` changes only the node's outer TCP connections.

## §13 targets

Ranges over the passes. A mark needs every pass to meet the target.

| Target | Simulator | Kernel, node on cubic | Kernel, node on BBR |
|---|---|---|---|
| Time to first packet ≤ 2 RTT | 2.05–2.07 ✅ | 2.03–2.08 ✅ | 2.03–2.04 ✅ |
| Clean link ≥ 90% of WireGuard | 99–114% ✅ (was 83%) | 95–97% ✅ (was 95%) | 91% in all three ✅ (was 86%) |
| Bulk overhead ≤ 3% | 3.0% ❌, one pass of two | 2.7–3.1% ❌, one of three (was 3.1%) | 2.9–3.3% ❌, two of three (was 3.2%) |
| 1% loss: clearly above REALITY and AnyTLS | 2.9–3.9× ✅ (was 1.7×) | 3.1–3.7× ✅ (was 1.8×) | 1.4–1.5× ✅ (was 0.5×) |
| Rises with lanes under a 4 Mbit/s cap | 21–29 Mbit/s ✅ (was 4.8) | 19–24 Mbit/s ✅ (was 16.6) | 10–17 Mbit/s ✅ (was 7.3; 17–27 before the limit) |
| Latency under load ≤ 2× idle | 2.0–2.9× ❌ (was 1.8–1.9×) | 2.5–3.2× ❌ (was 2.6–3.7×) | 2.5–3.3× ❌ (was 4.4–5.9×) |
| No visible stall after a lane reset | 76 ms or less ✅ | 107–139 ms ✅ (was 126–158) | 102–130 ms ✅ (was 106–122) |
| Interactive overhead ≤ 15% | 5.7–5.8% ✅ | 4.5–5.1% ✅ (was 6.5–6.6%) | 12.3–13.0% ✅ (was 6.6–7.5%) |

The kernel "was" figures for latency, reset and interactive overhead are
three runs of the binary from before the changes; the others are the single
earlier pass. The simulator's "was" for latency is three runs of that binary
too. Under the cap the client ran three to eight lanes, counting ones being
replaced.

### Latency under load (20 Mbit/s, 50 ms), p95 against idle

| | Node on cubic | Node on BBR |
|---|---|---|
| WireGuard | 2.0× | 1.9–2.0× |
| Tectonic | 2.5–3.2× | 2.5–3.3× |
| REALITY | 12.2–12.8× | 13.2–16.7× |

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

## The send limit

With the four causes fixed, one thing was still wrong on a BBR node, and it
did not show in the throughput tables. On the clean link the node
retransmitted 24–30% of what Tectonic sent, where the single-connection
models retransmitted 10–14% (BBR itself overruns a queue of one
bandwidth-delay product) and either did under 1% on a cubic node.

The lanes rely on their connections' congestion control to say what the
path carries: a connection sending all it may takes no more, its lane's
queue fills, and a full queue drops. BBR starts a connection at 2.89 times
the rate it has measured, and leaves that phase only after several round
trips with data always waiting to be sent. An ACK-clocked TCP inside the
tunnel rarely offers a lane more than it is carrying, so a lane stays
there: at the end of the bulk measurements 43 of Tectonic's 55 node
connections were still in start-up, against 17 of the models' 39. A lane in
start-up passes on whatever the inner TCP sends, and nothing between that
and the path's queue slowed it down.

A session now has a send limit of its own, shared by its lanes. It stays off
until the lanes' connections show the path is overloaded: for two stretches
of two round trips in a row they retransmitted more than 5% of what they
sent while their round trips had risen. Loss without a queue on the path
does not count, so random loss leaves it off. Once on, the session writes no
faster than the path has been delivering, and what the tunnel offers beyond
that waits in the lanes' queues, where a full queue drops. The rate then
follows the path a percent or two at a time.

Node on BBR, three passes each, before the limit and with it:

| | Before the limit | With it | The models |
|---|---|---|---|
| Retransmitted on the clean link | 24–30% | 0.3–2.2% | 10–14% |
| Clean link | 82.1 Mbit/s (79.3–84.3) | 83.4 (83.3–83.6) | 84.3 and 83.7 |
| Fibre | 170.7 Mbit/s (164.0–176.7) | 172.5 (169.3–174.4) | 172.1 and 171.6 |
| 1% loss | 75.8 Mbit/s | 79.2 | 52.9 and 54.1 |
| Latency under load, p95 against idle | 4.1–4.6× | 2.5–3.3× | 13–17× (REALITY) |
| Longest stall after a lane reset | 146–249 ms | 102–130 ms | |
| Longest pause in the 3 s before it | 171–345 ms | 97–127 ms | |
| Under a 4 Mbit/s per-connection cap | 17–27 Mbit/s | 10–17 Mbit/s | |

The retransmitted shares are counted over the connections open at the end
of the measurement; the models' range is over all six passes, since the
limit doesn't touch them. On a cubic node the limit never came on in the bulk
cases (cubic backs off by itself by the second stretch), and its figures
are unchanged.

Getting the rate to follow the path smoothly mattered more than anything
else about it. The first version let the rate fall by 5% or more each time
the path was found overloaded, about once a second. Each fall filled the
lanes' queues, which dropped, and a TCP connection made to back off every
second never gets back to what the path carries: the clean link came out
at 72–86 Mbit/s. It also measured what the path delivered wrongly at
first, 10–40% low, by throwing away deliveries seen when a lane had sent
nothing new.

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
- `sched`, `lane`: a send limit shared by a session's lanes (`Limiter`),
  fed by what each lane's connection reports through `TCP_INFO`, and a
  lane's estimate now counts a queue that the limit is holding.
- `bench`: `BENCH_TRACE` logs the inner TCP connection and the merge during
  a download, and `BENCH_PATHS` picks paths.

Two of these are visible from outside and worth a second look. `LOST` is a
new frame type. And a slow lane that paces now sends records smaller than
16 KB during a bulk transfer, which changes what an observer can measure.

## Still open

- **Under a per-connection cap with a BBR node, the send limit costs
  throughput:** 10–17 Mbit/s over three to six lanes after 45 s, where the
  lanes carried 17–27 without it (the target, that throughput rises with
  the number of lanes, is still met in every pass). On such a path a lane
  given more than its connection may carry loses the excess while another
  lane has room, so the session delivers less than it could, and a limit
  set from what it delivers holds it there. The limit stands down if its
  rate falls under 70% of the highest it has been, which catches a
  collapse; here it stalls instead. What it needs is a ceiling for each
  lane beside the one for the session. Four ways of doing that were tried:
  each got some of the cap case back, to 15–20 Mbit/s, and each cost
  2–10% on paths the lanes share or added more machinery than it was
  worth. With a cubic node the cap case is unchanged (19–24 Mbit/s).
- **Latency under load is still over the target on this path:** 2.5–3.2×
  idle on a cubic node and 2.5–3.3× on a BBR one. The wait in the merge is
  not what sets it: with the old wait and the new on otherwise identical
  code, three runs each, the p95 was 161–185 ms and 172–192 ms on a cubic
  node. Most likely pings wait behind the path's own queue, which cubic
  fills, and behind the 32 KB a lane's kernel may hold; that has not been
  taken apart.
- **The simulator's latency under load went from 1.8–1.9× to 2.0–2.9×,**
  and that is the longer wait: before the short wait for quiet lanes was
  added, the old wait gave 97–102 ms p95 on the same code and the new one
  117–131 ms. gVisor's TCP takes 100–300 ms to repair a loss (see
  RESULTS.md), so its lanes stall for longer than the kernel's, and what
  the merge releases at the end comes as a larger burst.
- **Interactive overhead roughly doubled on a BBR node** (12.3–13.0%, from
  6.6–7.5%), still under the target. It is the price of small records on a
  paced connection: each carries its own TLS framing and often a short TCP
  segment.
- **A lane that was idle, takes a burst and loses the first segment of it**
  looks quiet to the merge and gets the short wait. Linux and Darwin say
  how much a connection has received out of order, which would settle it.
- **Bulk overhead sits on the 3% line** (2.7–3.1% on a cubic node, 2.9–3.3%
  on a BBR one), as before.
- **More lanes on a lossy path.** With a cubic node each lane carries what
  one lossy connection can, and the pool mostly stays at two to four of the
  six it may open. Opening more when lanes are held back by loss, as the
  throttle check does under a per-connection cap, should carry more.
  Untested.
- **The send limit reads Linux's `TCP_INFO`.** Where a lane has no such
  figures it stays off. That is every client platform but Linux and
  Android today, which matters only for uploads through a client whose own
  TCP doesn't back off.

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
  more sensitive to load; its WireGuard reference read 78–83.
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
