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
```

The output is a Markdown table of measurement, target and result.

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

## Reading the numbers

- **Everything runs in one process,** TCP stacks included, so the numbers
  depend on the machine. Run on an otherwise idle machine and compare
  transports within one run, not across runs. Throughput can vary by tens of
  percent between runs.
- **The simulated hosts are gVisor netstacks, and gVisor has neither
  `TCP_NOTSENT_LOWAT` nor `TCP_INFO`.** Every lane in the bench therefore runs
  Tectonic's fallback path: estimates from PING/PONG, and a PONG-paced window
  that keeps the backlog out of the TCP stack. In production only Windows takes
  that path; Linux, Android, macOS and iOS set the low-water mark and read
  `TCP_INFO`, which keeps unsent data in the kernel to 32 KB rather than up to
  a bandwidth-delay product. The bench is a pessimistic proxy for those
  platforms.
- **The inner TCP is gVisor's too,** and it tolerates reordering poorly.
  With RACK (`-inner-rack`), its reordering window is about a quarter of the
  minimum RTT, and after a burst of spurious recoveries a flow can stall on
  retransmission timeouts for seconds; this hits the single-connection models
  too. Without RACK (the default here), three duplicate ACKs trigger a
  retransmit. Either way, reordering between lanes, which Tectonic allows by
  design, costs far more here than with a kernel TCP inside the tunnel, which
  adapts its reordering window. Expect large run-to-run swings in Tectonic's
  throughput for this reason.
- The link hosts use CUBIC without RACK; gVisor's Reno, and CUBIC with RACK,
  proved fragile under burst drops (see `internal/stacktune`).

## Debugging

`BENCH_DEBUG=1` prints Tectonic's own debug log (lane dials, retirements,
sessions). `BENCH_MAXLANES=n` caps the lanes the bench node allows, which
isolates cross-lane effects.

## Results

See `RESULTS.md` for the latest full run and what it shows.
