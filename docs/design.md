<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/banner-dark.svg" />
  <img src="assets/banner-light.svg" alt="Tectonic: WireGuard across many short-lived TLS lanes. Fast, unordered, and unremarkable on the wire." width="100%" />
</picture>

<h3>Design methodology</h3>

![Status](https://img.shields.io/badge/status-draft-C3562B?style=flat-square)
[![License](https://img.shields.io/badge/license-GPL--3.0-434C59?style=flat-square)](../LICENSE)
![Language](https://img.shields.io/badge/language-Go-434C59?style=flat-square)
![Platforms](https://img.shields.io/badge/platforms-desktop%20%7C%20Android%20%7C%20iOS-434C59?style=flat-square)

[How it works](#3-how-it-works) · [Authentication](#5-authentication) · [Lanes](#7-lanes-and-the-scheduler) · [SNI modes](#9-sni-modes) · [Threat model](#11-threat-model) · [Milestones](#15-milestones)

</div>

---

> [!NOTE]
> **Status: draft.** This describes what we intend to build. Nothing here is implemented yet, and every number under [Measuring speed](#13-measuring-speed) is a target, not a result.

Tectonic carries WireGuard over a small pool of short-lived TLS 1.3 connections called **lanes**. Packets travel across the lanes unordered, so a stall on one lane never holds up the others. To anyone watching the network, each lane is Chrome loading an ordinary website.

It's written in Go and shares one codebase between client and server. The client links it into the PangeaVPN daemon on desktop, Android and iOS, and the server runs on the VPN nodes.

## Contents

1. [Goals and non-goals](#1-goals-and-non-goals)
2. [What makes it different](#2-what-makes-it-different)
3. [How it works](#3-how-it-works)
4. [Connecting, step by step](#4-connecting-step-by-step)
5. [Authentication](#5-authentication)
6. [Wire format](#6-wire-format)
7. [Lanes and the scheduler](#7-lanes-and-the-scheduler)
8. [Traffic shaping](#8-traffic-shaping)
9. [SNI modes](#9-sni-modes)
10. [Carriers](#10-carriers)
11. [Threat model](#11-threat-model)
12. [Compared with existing protocols](#12-compared-with-existing-protocols)
13. [Measuring speed](#13-measuring-speed)
14. [Code layout](#14-code-layout)
15. [Milestones](#15-milestones)
16. [Open questions](#16-open-questions)

---

## 1. Goals and non-goals

### Goals

- **Fast.** Good enough to be the default transport on ordinary networks. The first packet should flow within two round trips, throughput should stay close to plain WireGuard, and packet loss should hurt it much less than it hurts single-connection TCP transports.
- **Unremarkable on the wire.** Every lane looks like Chrome talking to an ordinary HTTPS server.
- **Resilient.** It keeps working through injected resets, per-connection throttling, long-connection heuristics, SNI allowlists, and a phone moving between Wi-Fi and mobile data.
- **One protocol, several routes.** The same core runs straight to the node, or through a CDN when the node's IP address is blocked.
- **No home-made cryptography.** Real TLS 1.3 on the outside and WireGuard on the inside. Tectonic adds only authentication, framing, scheduling and shaping, built from standard primitives (HMAC-SHA256, HKDF and TLS exporters).

### Non-goals

- **IP allowlists.** No protocol gets through a network that only lets traffic reach approved IP addresses. SNI allowlists are a different matter; [section 9](#9-sni-modes) covers them.
- **Secrecy.** The code is public under GPL-3.0, and nothing in the design depends on a censor not knowing how it works.
- **Replacing WireGuard.** Tectonic only carries WireGuard. WireGuard still provides the end-to-end encryption and keys.

---

## 2. What makes it different

Most of these ideas exist somewhere in some form. What's new is combining them, and designing every part around the fact that the payload is always WireGuard datagrams, never a byte stream.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/head-of-line-dark.svg" />
  <img src="assets/head-of-line-light.svg" alt="On one TCP connection, losing packet 2 holds packets 3 to 6 until it is retransmitted. With Tectonic lanes, only the lane that lost a packet waits; the others reach WireGuard immediately." width="100%" />
</picture>

| | Idea | What it does |
|---|---|---|
| 01 | **Unordered lanes** | WireGuard packets are spread across several TLS lanes and handed over the moment they arrive, in any order. A lost segment stalls only its own lane. |
| 02 | **Free deduplication** | WireGuard's anti-replay window already drops duplicate packets. That lets us send a small, urgent packet on two lanes without any bookkeeping on the receiving end. |
| 03 | **Lane churn** | Each lane lives from tens of seconds to a few minutes, and a replacement opens before the old one closes, the way a browser cycles connections. No single connection runs for hours or carries gigabytes. |
| 04 | **Throttle detection** | If adding a lane raises total throughput while each lane stays capped, the network is throttling per connection. Tectonic responds by adding lanes, up to a limit. |
| 05 | **Our own identity** | By default each node serves a real website on a domain we own, with a real certificate. SNI, IP address and certificate all agree. |
| 06 | **Channel-bound login** | The login is tied to its TLS session through a TLS exporter, so a captured login doesn't work on any other connection. A probe that fails it is served the website. |
| 07 | **Shaping budget** | Padding is added only when the real traffic would give WireGuard away: handshakes, keepalives and idle periods. A large download already looks like a download, so it gets no padding. |
| 08 | **Sessions outlive connections** | A session belongs to the device, not to a TCP connection. Every lane can drop during a network change, and the new lanes rejoin the same session. |
| 09 | **Any SNI, or none** | The login happens inside TLS, so the server accepts whatever name the network allows, or no name at all. |

---

## 3. How it works

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/lanes-dark.svg" />
  <img src="assets/lanes-light.svg" alt="WireGuard on the device sends to the Tectonic client on loopback. The client spreads packets, out of order, across several TLS lanes to the Tectonic server on the node, which hands them to WireGuard as they arrive. A firewall sees Chrome visiting a website; a probe that fails login gets the cover website." width="100%" />
</picture>

On the device, WireGuard sends to a loopback port, as it does with every other PangeaVPN transport. The Tectonic client spreads those packets across its lanes. The server passes each packet to the node's WireGuard as soon as it arrives, without putting them back in order.

From the daemon's point of view, Tectonic is one more transport. It brings up a loopback UDP listener and points WireGuard's endpoint at it.

---

## 4. Connecting, step by step

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/connect-dark.svg" />
  <img src="assets/connect-light.svg" alt="The client opens TCP, sends a Chrome ClientHello, and as soon as TLS finishes sends its login and the first WireGuard packet together, within two round trips. The node replies WELCOME or serves its website. A second lane joins with TLS resumption." width="100%" />
</picture>

1. **Provisioning.** When the user connects, the hub returns a `tectonic` profile block containing the node address, a cover domain, a `key_id` and a `device_key`, plus an optional CDN route.
2. **First lane.** The client opens TCP to the node and starts a TLS 1.3 handshake with Chrome's ClientHello (via uTLS), offering ALPN `h2`. The SNI depends on the [SNI mode](#9-sni-modes).
3. **Login in the first flight.** As soon as the TLS handshake completes, the client sends `HELLO`, padded to the size of Chrome's first HTTP/2 flight, without waiting for a reply. The first WireGuard packet goes out in the same write.
4. **The server decides.** The server buffers the client's first flight and checks the `HELLO`. If it passes, the server replies `WELCOME` and the lane carries tunnel traffic. If it fails, the buffered bytes go to the cover website's HTTP server, which answers as it would answer any visitor.
5. **More lanes.** A second lane opens straight away using TLS session resumption, the way a returning browser reconnects, and joins the same session.
6. **Steady state.** Lanes are retired and replaced on a browser-like schedule, and the pool grows if per-connection throttling is detected.
7. **Network change.** If every lane dies, the client reconnects with the same `session_id` within the resume window (60 s by default). WireGuard's session carries on without noticing.

> [!TIP]
> **Time to first packet** is one TCP round trip plus one TLS 1.3 round trip. Logging in adds nothing, because the client doesn't wait for `WELCOME` before it starts sending.

---

## 5. Authentication

### Keys without per-device sync

Each node, or each region, holds one secret, `node_secret`. The hub knows every node's secret and issues each device a credential for the node it's about to use:

```text
key_id     = 16 random bytes ‖ expiry (uint32, unix days)        // 20 bytes
device_key = HMAC-SHA256(node_secret, "tectonic device v1" ‖ key_id)
```

The node recomputes `device_key` from the `key_id`, so it needs no device database and nothing synced from the hub. A `key_id` can't be forged, and its expiry can't be extended, without knowing `node_secret`. The hub reissues credentials before they expire. To revoke one early, the hub pushes a short list of `key_id`s to deny.

### HELLO

```text
exporter = TLS-Exporter("EXPORTER-tectonic-hello", context = "", 32 bytes)
lane_key = HKDF-SHA256(ikm = device_key, salt = exporter, info = "tectonic lane v1")

HELLO
  version     1 byte    = 1
  flags       1 byte    bit 0: join an existing session
  key_id     20 bytes
  session_id 16 bytes   zeros for a new session
  timestamp   8 bytes   unix seconds
  tag        32 bytes   HMAC-SHA256(lane_key, all fields above)
```

- **Channel binding.** The exporter value is unique to each TLS connection, so a `HELLO` copied from one connection fails on every other. The ±120 s timestamp window is a second line of defence against replay.
- **Joining a session** requires the same `key_id` that created it, so a leaked `session_id` is useless on its own.
- **Constant-time checks.** Success and failure take the same time, so a probe learns nothing from how fast the server answers.

### When the login fails

The server never sends a Tectonic-specific error. Whatever bytes arrived go to the cover website's HTTP handler. A valid HTTP request gets the site, and anything else gets an ordinary `400 Bad Request` and the connection closed.

---

## 6. Wire format

Inside TLS, a lane carries a series of frames. Several frames can share one TLS record, and the shaper decides how big each record is.

```text
frame = type (1 byte) ‖ length (2 bytes, big-endian) ‖ body (length bytes)
```

| Type | Name | Direction | Body |
|---|---|---|---|
| `0x01` | `HELLO` | C → S | The login described above. Always the first frame on a lane. |
| `0x02` | `WELCOME` | S → C | `session_id`, `max_lanes`, `resume_window`, shaping profile ID |
| `0x03` | `DATA` | both | Exactly one WireGuard datagram. No sequence number, because WireGuard's own counters handle ordering and duplicates. |
| `0x04` | `PAD` | both | Zeros. Thrown away on receipt. |
| `0x05` | `PING` / `PONG` | both | An 8-byte token, used to measure each lane's round-trip time |
| `0x06` | `RETIRE` | both | "No new `DATA` on this lane." The lane finishes what it's sending, then closes with TLS `close_notify`. |
| `0x07` | `CLOSE` | both | Ends the whole session. 1-byte reason code. |

A receiver skips any frame type it doesn't recognise, using the length field, so new frame types can be added without breaking older clients.

---

## 7. Lanes and the scheduler

### Choosing a lane

For each outgoing WireGuard packet, the scheduler picks the lane with the earliest estimated delivery time:

```text
eta(lane) = queued_bytes(lane) / rate(lane) + srtt(lane) / 2
```

- **Shallow socket buffers.** Each lane sets `TCP_NOTSENT_LOWAT`, so the operating system holds only a little unsent data. The queue stays in Tectonic's scheduler, which can still steer packets to the fastest lane. This also keeps latency low while the tunnel is busy.
- **Rate and RTT** come from `TCP_INFO` where the platform provides it, and from `PING`/`PONG` otherwise.
- **Unordered delivery.** The receiver hands each `DATA` frame to WireGuard as soon as it arrives. TCP connections running *inside* the tunnel never wait on a retransmission happening in an unrelated lane.

### Duplicating small urgent packets

While any lane is retransmitting, packets of 128 bytes or less are also copied onto the next-best lane. That covers WireGuard handshakes, keepalives, and most TCP ACKs from inside the tunnel. Duplication is capped at 5% of bandwidth and removes most of the latency spikes that loss would otherwise cause. The receiver doesn't need any logic for this, because WireGuard silently drops the second copy.

### Lane churn

- Each lane's lifetime is drawn from a browser-like distribution (median about 90 s, range 20 s to 6 min), and its byte budget is drawn the same way (median about 40 MB).
- Shortly before a lane expires, a replacement opens with TLS resumption. Once the new lane is carrying traffic, the old one is sent `RETIRE`, finishes sending, and closes. The number of working lanes never drops during the switch.
- If the network kills a lane, for example with a forged reset or a middlebox timeout, traffic moves to the remaining lanes at once and a replacement opens.

### Lane count and throttle detection

- The pool starts with 2 lanes and can grow to `max_lanes`. The server sets that limit: 6 by default, and 3 on cellular.
- **Throttle check.** Under load, if every lane settles at about the same rate and adding a lane adds about that much more again, the network is limiting each connection separately. The client keeps adding lanes while each one pays off, and closes lanes once they stop helping.
- When the tunnel is idle, the pool shrinks to a single lane.

---

## 8. Traffic shaping

TLS hides what's inside the traffic, but WireGuard still has a recognisable shape: 148-byte and 92-byte handshakes, a fixed 32-byte keepalive on a regular timer, and MTU-sized data packets. Tectonic changes only what an observer can measure from outside, which is TLS record sizes and their timing.

| Traffic state | What Tectonic does | Overhead |
|---|---|---|
| Bulk transfer | Packs `DATA` frames into records of up to 16 KB, like a real download | ≈ 0% |
| Interactive | Rounds record sizes up to buckets taken from a recorded browsing profile | Small |
| Lane start | Pads the first flight in each direction to match Chrome loading a page over HTTP/2 | Once per lane |
| Idle | Absorbs WireGuard keepalives into browser-like idle behaviour, closes the lane, and opens a fresh one when traffic resumes | Tiny |

Shaping profiles are data, not code. `WELCOME` tells the client which profile to use, so new profiles can be rolled out from the hub without a protocol change.

> [!WARNING]
> **The limit of shaping.** Shaping makes classification harder and more expensive. It can't rule out a well-resourced censor running machine-learning classifiers over whole flows. That's why the rest of the PangeaVPN transport cascade stays in place behind Tectonic.

---

## 9. SNI modes

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/sni-modes-dark.svg" />
  <img src="assets/sni-modes-light.svg" alt="Three SNI modes: Own sends our cover domain with a real certificate; Borrowed sends any name the network allows with a pinned certificate; None sends no SNI, like Chrome opening an IP address." width="100%" />
</picture>

Networks filter on the handshake's server name in different ways, so the SNI is a per-network setting rather than one fixed value. Because the login happens *inside* TLS, **the server accepts any SNI, or none at all**.

| Mode | SNI sent | Certificate check | Best for |
|---|---|---|---|
| **Own** | The node's cover domain | Real Let's Encrypt certificate, verified by name | Open networks and blocklist censors. SNI, DNS, IP and certificate all agree. |
| **Borrowed** | Any name the network allows, from a list the hub supplies or typed in by the user | The node's default certificate, verified by SPKI pin | SNI allowlists that read the name but don't check it against the destination IP |
| **None** | No SNI extension, which is exactly what Chrome sends when it opens `https://<IP>` | Default certificate, verified by SPKI pin, or a Let's Encrypt IP certificate | SNI allowlists that let connections without an SNI through |

- **The certificate is hidden from the filter.** TLS 1.3 encrypts the server certificate, so a filter watching passively never sees that it doesn't match a borrowed name. The client still verifies the node through the pin.
- **How the server chooses a certificate.** If the SNI is the node's own domain, the server presents the real certificate. For any other name, or no name, it presents its default certificate, which is how most web servers behave.
- **Active probes in borrowed mode** receive the default certificate and the cover website. That's ordinary behaviour for a server, though not a perfect disguise. REALITY handles this case better, which is one reason it stays in the cascade.
- **Picking the mode automatically.** On a network it hasn't seen before, the client tries all three modes in parallel for the first lane and keeps the first one that logs in. It remembers that mode for the network, so the next connection goes straight to it. Allowlist filters usually reject a blocked handshake within one round trip, so trying all three costs very little.

### Domains for Own mode

- Nothing about a domain links it to PangeaVPN: no brand name in it, private WHOIS, and a registrar and DNS host different from ours.
- Every certificate is published in public Certificate Transparency logs, which censors can watch for new domains. Wildcard certificates keep each node's subdomain out of those logs.
- Use a few base domains, each with a subdomain per node. If one base domain gets blocked, the hub moves its nodes to a fresh one.
- Every domain serves a plausible small website.

---

## 10. Carriers

The core (login, frames, scheduler and shaper) doesn't care how a lane reaches the node.

| Carrier | What a lane is | When it's used |
|---|---|---|
| **Direct** | A TLS 1.3 connection to the node on port 443, using one of the [SNI modes](#9-sni-modes) | By default. This is the fastest route. |
| **CDN** | A WebSocket over TLS to a CDN edge, which forwards it to the node. `HELLO` is sent in the first WebSocket message, and the node also checks a header signed by the CDN. | When direct lanes can't open, for example because the node's IP is null-routed |

The client switches carriers within the same session, and direct and CDN lanes can briefly run side by side during the switch. The user sees one transport, Tectonic, that keeps working.

---

## 11. Threat model

| Attack | Tectonic's answer | What's left |
|---|---|---|
| Passive DPI on the handshake | Chrome's ClientHello via uTLS. In Own mode, SNI, IP and certificate all agree. | uTLS has to keep up with Chrome releases |
| Active probing | A probe that fails login gets the cover website, with the same timing as a successful login | The cover site has to look real and maintained |
| Replaying a captured login | The login is bound to its TLS session's exporter, and checked against a timestamp window | None known |
| Long-connection and volume heuristics | Lane churn limits each connection's lifetime and byte count | Many connections from one client to one server is itself a pattern, though browsers make many connections too |
| Per-connection throttling | Throttle detection adds lanes | A per-host throttle, which caps all connections to one server together, can't be beaten this way |
| Injected TCP resets | The lane is replaced and traffic continues on the others | Resetting every lane at once forces a rejoin, which takes about 2 RTT |
| Packet size and timing analysis | The shaping budget hides WireGuard's fixed sizes and keepalive timer | Machine-learning classifiers ([section 8](#8-traffic-shaping)) |
| SNI allowlist | Borrowed or None mode, chosen automatically and remembered per network | A filter that checks borrowed names against their real IPs *and* drops connections with no SNI. The CDN carrier is next. |
| Node IP blocked | CDN carrier | The CDN itself blocked. The cascade continues. |
| Cover domain blocked | The hub moves the node to a new domain | Needs a supply of domains |
| IP allowlist | Out of scope | Any protocol fails here |

---

## 12. Compared with existing protocols

This is a broad comparison of public designs. Each of them solves a real problem well.

| Protocol | What it does | How Tectonic differs |
|---|---|---|
| VLESS + REALITY | Borrows another site's TLS identity, and its server only accepts the names it's configured for | Uses our own identity by default. When it borrows a name, it accepts any name, or none. Traffic is spread across lanes rather than one connection. |
| Trojan | Real TLS plus a password, with a fallback website, over one long-lived stream | The login is bound to the TLS session, so it can't be replayed. Lanes churn and deliver datagrams unordered. |
| Cloak | Hides its login in ClientHello fields and multiplexes ordered streams over several connections | The ClientHello is untouched Chrome. Datagrams are unordered, with no head-of-line blocking between lanes. |
| AnyTLS | TLS with padding aimed at defeating TLS-in-TLS detection | There's no TLS inside the TLS, because the payload is WireGuard. Shaping targets WireGuard's own patterns and costs nothing during bulk transfer. |
| NaiveProxy | Uses Chrome's real network stack and HTTP/2 CONNECT | Pure Go with no native library, so it runs on iOS too. Multiple lanes and datagram-native framing. |
| Speed-first VPN protocols | Built for speed, with little or no disguise | Speed comes from the scheduler, while the traffic still looks like browsing |

---

## 13. Measuring speed

`bench/` runs the client and server in a single process over a simulated link, where bandwidth, RTT, random and burst loss, and a per-connection rate cap can all be set. It compares Tectonic against REALITY and AnyTLS under identical conditions.

| Measurement | Target |
|---|---|
| Time to first WireGuard packet | ≤ 2 RTT |
| Throughput on a clean link (100 Mbit/s, 50 ms) | ≥ 90% of plain WireGuard over UDP |
| Throughput with 1% random loss | Clearly above REALITY and AnyTLS |
| Throughput under a 4 Mbit/s per-connection cap | Rises with the number of lanes, up to `max_lanes` |
| Latency under load | Ping inside the tunnel stays within 2× idle RTT during a saturating download |
| Recovery from a reset lane | No visible stall in a TCP transfer inside the tunnel |
| Bandwidth overhead | ≤ 3% during bulk transfer, ≤ 15% during interactive use |

> [!IMPORTANT]
> Tectonic won't be called faster until these numbers exist. After the lab benchmarks come field tests on real censored networks, through opt-in builds.

---

## 14. Code layout

This repository holds the protocol, and the PangeaVPN daemon imports it.

| Path | Contents |
|---|---|
| `wire/` | Frames, `HELLO` and `WELCOME`, key derivation. No I/O; unit- and fuzz-tested. |
| `lane/` | A single lane: dial, TLS, login, frame I/O, retire |
| `sched/` | The lane pool, scheduler, duplication, churn and throttle detection |
| `shape/` | Shaping profiles and record-size planning |
| `server/` | The server: TLS listener, login check, cover-site fallback, session table, UDP forwarding to WireGuard |
| `client.go` | A small public API that dials a profile and returns a datagram connection for WireGuard |
| `cmd/tectonic-server/` | The node binary |
| `bench/` | Simulated-link benchmarks |

In [pangeavpn-app](https://github.com/pangeavpn/pangeavpn-app), the integration is a thin `daemon/internal/tectonic` adapter that implements the daemon's transport interfaces. That repo also gets a `TectonicProfile` in the daemon state, a `tectonic` entry in the transport cascade, and a Tectonic option in the desktop, iOS and Android apps.

---

## 15. Milestones

| | Milestone | Done when |
|---|---|---|
| M0 | Design sign-off | This document is agreed and the open questions are answered |
| M1 | Core, single lane | `wire`, `lane` and `server` exist. An in-process end-to-end test carries a real WireGuard handshake, and a probe that fails login gets the cover site. |
| M2 | Lanes | The scheduler, unordered delivery, duplication, churn and throttle detection work, and the benchmark harness has first numbers |
| M3 | Daemon integration | Tectonic can be chosen explicitly in the daemon. It isn't yet part of the automatic cascade. |
| M4 | Node deployment | `tectonic-server` and a cover site run on the nodes, and the hub issues credentials |
| M5 | SNI modes and shaping | All three SNI modes are chosen and remembered automatically per network. Shaping profiles are recorded from real Chrome sessions. A fingerprint audit is done. |
| M6 | CDN carrier | Lanes run over WebSocket through a CDN, and the client switches between direct and CDN carriers within a session |
| M7 | Apps and default | Tectonic is in the transport picker on all platforms. It becomes first in the automatic cascade once field data supports it. |

---

## 16. Open questions

1. **Domains.** One base domain per group of nodes, and who registers and rotates them?
2. **Node deployment.** Who deploys `tectonic-server`, and is port 443 free on every node?
3. **Hub changes.** The hub needs to hold the `node_secret`s and issue `key_id`/`device_key` pairs. It also needs a revocation list.
4. **Custom SNI in the apps.** A setting where users on allowlist networks type in a name their network allows. Which names should the hub supply by default?
5. **Mobile limits.** The maximum lane count on cellular, and whether lane churn costs noticeable battery.
