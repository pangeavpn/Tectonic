<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.svg" />
  <img src="docs/assets/banner-light.svg" alt="Tectonic: WireGuard across many short-lived TLS lanes. Fast, unordered, and unremarkable on the wire." width="100%" />
</picture>

[**Design methodology**](docs/design.md) · [License](LICENSE) · [PangeaVPN](https://github.com/pangeavpn/pangeavpn-app)

</div>

---

Tectonic is PangeaVPN's own TCP transport for WireGuard. It spreads WireGuard
datagrams across a small pool of short-lived TLS 1.3 connections ("lanes")
and puts them back in order on arrival. Each lane has its own congestion
window, so a loss slows one lane and the others keep their pace. To a network
observer each lane is Chrome loading an ordinary website.

**Status:** implemented, not yet field-tested. The protocol in the
[design](docs/design.md) is built and covered by tests, including an
in-process end-to-end run with real WireGuard. `bench/` measures the speed
targets in [§13](docs/design.md#13-measuring-speed); see
[`bench/RESULTS.md`](bench/RESULTS.md) for which it meets. Its simulator only
exercises the path that lanes take without `TCP_NOTSENT_LOWAT`, which in
production means Windows clients; the path other platforms take is measured
on Linux with `bench -kernel` (see [`bench/recent.md`](bench/recent.md)). The
default shaping profile opens a lane with records measured from Chromium;
its other numbers are placeholders until profiles are recorded from real
Chrome sessions (milestone M5).

- [**Design methodology**](docs/design.md): how Tectonic works and why.
- Client: linked into the PangeaVPN daemon
  ([pangeavpn-app](https://github.com/pangeavpn/pangeavpn-app)).
- Server: `cmd/tectonic-server`, run on VPN nodes.

## Layout

See [Design methodology § Code layout](docs/design.md#14-code-layout) for details.

| Path | Contents |
|---|---|
| `wire/` | Frames, HELLO/WELCOME, key derivation. No I/O. |
| `lane/` | One TLS lane: dial, login, frame I/O, retire. Direct and CDN carriers. |
| `sched/` | Lane pool, scheduler, resequencer, duplication, churn, throttle detection. |
| `shape/` | Shaping profiles and record-size planning. |
| `server/` | Server library: TLS listener, login check, cover-site fallback, sessions. |
| `client.go` | Public client API: dial a profile, get a `net.PacketConn` for WireGuard. |
| `cmd/tectonic-server/` | Node binary. |
| `bench/` | Simulated-link benchmarks against other transports (its own module). |

## Using the client

The hub's `tectonic` profile block goes in, and a `net.PacketConn` comes out.
Relay WireGuard's loopback UDP socket to it the way the daemon relays every
transport:

```go
conn, err := tectonic.Dial(ctx, tectonic.Config{
	Profile: profile,   // node, cover_domain, key_id, device_key, pins, cdn...
	Network: networkID, // the SNI mode that works is remembered per network
	Control: protect,   // optional: keep lane sockets out of the tunnel on mobile
})
if err != nil {
	return err
}
defer conn.Close()
err = conn.WaitForSession(ctx, 15*time.Second)
```

`Dial` returns at once. The first packet WireGuard writes goes out with the
first lane's login, so it reaches the node within two round trips.
`ErrCredentialRejected` means the key_id expired or was revoked, and the hub
must issue a new one.

## Running a node

Build the node with Go 1.27 or newer. From that version Go's web server
serves the node's connections exactly as it serves its own, which is what
makes a node answer strangers the way any Go website does. An older Go builds
a node that is close but not identical, and it logs a warning at start.

```sh
go build ./cmd/tectonic-server
(umask 077; head -c 32 /dev/urandom | xxd -p -c 32 > node_secret)

./tectonic-server serve \
  -secret-file node_secret \
  -cover-domain n12.example-cdn.net -cert cover.crt -key cover.key \
  -cover-dir /var/www/cover \
  -wireguard 127.0.0.1:51820
```

Each session reads WireGuard's packets from a UDP socket, and WireGuard sends
them in bursts. The node asks for a 7 MB receive buffer on it, which Linux
grants only up to `net.core.rmem_max` (about 200 KB by default) unless the
process has `CAP_NET_ADMIN`. With the default, bursts overflow the buffer and
the tunnel loses packets it had room for; the node logs a warning when that
is the case. Raise the limit on the node:

```sh
sysctl -w net.core.rmem_max=7500000
```

On first run the node creates its default certificate (`default.crt`) and
logs its pin. The certificate is self-signed for `localhost`;
`-default-cert-name` sets another name. An existing certificate is never
rewritten, because clients pin it, and if it carries the machine's hostname
the node says so at start. Give that pin to the hub; clients in Borrowed and None mode
check it. `tectonic-server pin -cert default.crt` prints the pin again, and
`tectonic-server issue -secret-file node_secret -node HOST:443 -pin PIN`
mints a test profile the way the hub does. Send SIGHUP to reload the
certificates and the `-revoked` list.

The node secret derives every device key the node accepts, so the node
refuses a secret file that anyone but its owner can read. Keep it at mode
600, as the `umask` above does.

A credential holds `-max-sessions-per-key` sessions at once (4) and each new
one ends its oldest, and a node holds `-max-sessions` in all (4096), past
which a login that would start a session is refused while rejoining one
still works.

## Testing and benchmarks

```sh
go test ./...          # unit, fuzz-seed and end-to-end tests
cd bench && go run .   # simulated-link benchmarks (see bench/README.md)
```

## Developing alongside the daemon

Until the API settles, edit both repos together with a Go workspace rather
than tagging every change. From a directory that contains both checkouts:

```sh
go work init ./pangeavpn-app/daemon ./Tectonic
```

## License

GPL-3.0, the same as the PangeaVPN client. See [LICENSE](LICENSE).
