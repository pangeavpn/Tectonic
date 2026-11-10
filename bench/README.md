# Tectonic benchmarks

`bench/` measures Tectonic against the targets in
[design §13](../docs/design.md#13-measuring-speed). It runs the client and
server in a single process over a simulated link where bandwidth, RTT, random
and burst loss, and a per-connection rate cap can all be set. Real WireGuard
(wireguard-go) runs on both sides, and the test traffic is TCP inside the
tunnel. Every transport runs under identical conditions:

| Transport | What it is |
|---|---|
| `wireguard` | WireGuard straight over UDP: the reference |
| `tectonic` | WireGuard over Tectonic lanes, client and server from this repository |
| `reality` | A model of VLESS + REALITY: one Chrome-fingerprinted TLS 1.3 connection carrying every datagram in order |
| `anytls` | A model of AnyTLS: the same single connection, with anytls-go's session framing and default padding |

The REALITY and AnyTLS servers can't be linked in-process here, so `baseline/`
models what drives their speed: one TCP connection carrying every datagram in
order. See `baseline/` for exactly what is and isn't modelled.

```sh
go run .                          # every scenario, about five minutes
go run . -list                    # what each scenario measures
go run . -run 'clean|loss' -v     # some scenarios, with progress
go run . -quick                   # shorter measurements
go run . -transports tectonic     # Tectonic and the WireGuard reference only
go run . -kernel                  # over a kernel path instead (Linux, below)
```

The output is a Markdown table of measurement, target and result.

## The kernel path (`-kernel`, Linux)

By default every host is a gVisor netstack in this process. `-kernel` runs
the same scenarios over a path built from Linux parts instead (`knet/`):
three network namespaces, client ↔ router ↔ server, joined by veth pairs,
with the impairments on the router's two egress interfaces (netem for
delay and loss, tbf for the bottleneck and its queue, fq `maxrate` for the
per-connection cap). Then:

- **the transports run on Linux TCP.** Tectonic's lanes set
  `TCP_NOTSENT_LOWAT` and read `TCP_INFO`, the path every platform but
  Windows takes in production and the simulator can't exercise; the
  REALITY and AnyTLS models get the kernel's send buffer, as their real
  servers do;
- **the TCP inside the tunnel is Linux's too:** wireguard-go runs on real
  TUN devices (`-inner gvisor` puts the gVisor stacks back);
- **`-server-cc bbr`** makes the node's outer connections BBR, as many
  REALITY and AnyTLS servers are configured.

The bench re-executes itself in a user namespace, so it runs without root.
The kernel modules have to be loaded once, as root, since an unprivileged
namespace can't load them:

```sh
sudo modprobe -a veth sch_netem sch_tbf sch_fq tcp_bbr inet_diag tcp_diag
```

Unprivileged user namespaces must be enabled (they are by default on most
distributions). `go test ./knet` checks the path itself: RTT, bandwidth,
the per-connection cap, loss, resets, BBR and TUN devices.

Differences from the simulated link, all small: the bottleneck rate counts
Ethernet headers (about 1% at full-size packets); the order is delay, then
the bottleneck queue, rather than queue then delay; fq hashes flows into
1024 buckets, so two connections can share a cap, rarely; a reset aborts
the client's socket (`ss -K`), which sends the node a RST, rather than
forging one to each end.

## Scenarios

| Name | Target (§13) | How it is measured |
|---|---|---|
| `ttfp` | Time to first WireGuard packet ≤ 2 RTT | Dial a fresh client, write a 148-byte handshake initiation at once, and time its arrival at the node's WireGuard. Expressed in round trips measured on the same link (a TCP connect), less the half round trip the packet spends travelling. |
| `clean` | ≥ 90% of plain WireGuard on 100 Mbit/s, 50 ms | A bulk TCP download inside the tunnel, after a warm-up. The same run gives the bulk-overhead figure: link bytes per payload byte relative to WireGuard over UDP (target ≤ 3%). |
| `loss` | Clearly above REALITY and AnyTLS with 1% random loss | The same download on a link losing 1% of packets. "Clearly" is taken as at least 1.25×. |
| `cap` | Rises with the number of lanes under a 4 Mbit/s per-connection cap | A 45 s download with every TCP and UDP flow capped at 4 Mbit/s; throughput and lane count every 5 s. |
| `latency` | Ping inside the tunnel within 2× idle RTT during a saturating download | 64-byte UDP echoes inside the tunnel, idle and then during a download on a 20 Mbit/s, 50 ms link (p95 under load against the idle median). |
| `reset` | No visible stall after a lane is reset | A download on 50 Mbit/s, 50 ms; one lane gets a forged TCP reset; the longest pause between reads in the next 3 s is compared with the 3 s before. |
| `interactive` | Overhead ≤ 15% during interactive use | Browsing-like exchanges (300-byte requests, 2–42 KB replies, 0.1–0.5 s pauses); link bytes per payload byte relative to WireGuard over UDP. |
| `paths` | (none: for comparison) | The bulk download on four typical paths: a nearby node on fibre (200 Mbit/s, 15 ms), another continent (50 Mbit/s, 150 ms, 0.1% loss), LTE (30 Mbit/s, 70 ms, bursty loss averaging 0.4%) and a lossy international path (20 Mbit/s, 200 ms, 2% loss). |

## Reading the numbers

- **Everything runs in one process,** TCP stacks included, so the numbers
  depend on the machine. Run on an otherwise idle machine and compare
  transports within one run, not across runs. Throughput can vary by tens of
  percent between runs.
- **The simulated hosts are gVisor netstacks, and gVisor has neither
  `TCP_NOTSENT_LOWAT` nor `TCP_INFO`.** Every lane in the bench therefore runs
  the path a lane takes without them: it estimates its rate from PING/PONG,
  caps what it has written but not seen confirmed, and paces itself (see
  [design §7](../docs/design.md#without-tcp_notsent_lowat)). In production
  only Windows takes that path. Linux, Android, macOS and iOS set the
  low-water mark and read `TCP_INFO`, and the bench says nothing about how
  those lanes behave.
- **The inner TCP is gVisor's too.** Two of its habits decide most of the
  clean-link number:
  1. It leaves slow start (HyStart) as soon as its round-trip time rises by a
     few milliseconds. Over plain WireGuard the link adds no delay until its
     queue fills, so the flow overshoots, loses a few hundred packets and
     settles at the link's capacity within two seconds. Through a tunnel that
     adds a little delay earlier, it can stop growing at a third or half of
     capacity and then needs ten seconds or more to climb the rest. Which
     happens varies from run to run.
  2. Its retransmission timeout has a floor of 200 ms on the whole round
     trip, where Linux adds 200 ms to it. A delay spike of 150 ms that a
     kernel TCP would ride out can send it back to one packet.
  With RACK (`-inner-rack`) it can also stall on timeouts for seconds after a
  burst of spurious recoveries, which hits the single-connection models too;
  without RACK (the default here), three duplicate ACKs trigger a retransmit.
- The link hosts use CUBIC without RACK; gVisor's Reno, and CUBIC with RACK,
  proved fragile under burst drops (see `internal/stacktune`).

## Debugging

`BENCH_DEBUG=1` prints Tectonic's own debug log (lane dials, retirements,
sessions). `BENCH_MAXLANES=n` caps the lanes the bench node allows, which
isolates cross-lane effects. `BENCH_PATHS=regexp` limits the `paths`
scenario to the paths whose names match.

`BENCH_TRACE=250ms` (any duration), with `-v`, logs every bulk download at
that interval: its rate; on the kernel path, what the kernel says about the
sending end of the TCP connection inside the tunnel (window, `ssthresh`,
round trip, retransmissions); and for Tectonic, the client's lane count and
what its merge has held back, given up on, seen arrive late and been told
was dropped. A throughput figure alone hides the two things that most often
decide it: where that connection left slow start (`ssthresh`), and whether
it is being made to retransmit. For example:

```sh
BENCH_TRACE=250ms BENCH_PATHS=continent go run . -kernel -server-cc bbr \
  -run '^paths$' -transports tectonic -v
```

## Results

See `RESULTS.md` for the simulator's full run and what it shows, and
`recent.md` for the kernel path: what was slow on it, why, and the figures
after the changes that followed.
