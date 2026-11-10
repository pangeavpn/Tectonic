// Package knet builds the bench's network path out of kernel parts, so that
// both the TCP under the transports and the TCP inside the tunnel are Linux's
// own rather than gVisor's.
//
// The process re-executes itself in a new user and network namespace (see
// Reexec), so nothing needs root once the kernel modules are loaded. Inside,
// New builds three network namespaces joined by veth pairs:
//
//	client 10.0.1.1 ──c0│rc── router ──rs│s0── 10.0.2.1 server
//
// The server is the process's own namespace, so any socket opened without
// asking for another namespace (the node's UDP to WireGuard, for instance)
// is on the server. The client and router are separate namespaces; sockets
// and commands are placed in them by running on a locked OS thread that has
// joined the namespace.
//
// Every impairment sits on the router's two egress interfaces, one per
// direction, so the end hosts see a path rather than a local qdisc (a local
// netem would hold their sockets' buffers and change TCP's behaviour). Each
// direction runs, in order:
//
//  1. netem: one-way delay of RTT/2, and random or Gilbert–Elliott loss;
//  2. tbf: the bottleneck, with a drop-tail queue of Config.QueueBytes
//     (one bandwidth-delay product by default, as in bench/link);
//  3. fq with maxrate, when PerConnRate is set: every 5-tuple flow paced to
//     the cap, with a short per-flow queue (fq hashes forwarded packets into
//     1024 buckets, so two flows can share a cap, rarely).
//
// Segmentation offloads are off on every veth, so the qdiscs count, delay
// and drop real MTU-sized packets, not 64 KB aggregates.
//
// Needs the veth, sch_netem, sch_tbf, sch_fq and inet_diag/tcp_diag modules
// loaded (an unprivileged namespace can't load them), and unprivileged user
// namespaces enabled.
package knet

import "net/netip"

// Addresses on the outer path.
var (
	ClientAddr = netip.MustParseAddr("10.0.1.1")
	ServerAddr = netip.MustParseAddr("10.0.2.1")
)
