// Package stacktune applies the TCP/UDP settings shared by every gVisor
// stack in the benchmarks, so that the userspace stacks are not the
// bottleneck on a fast, long link.
//
// The choices below were measured against the pinned gVisor version
// (v0.0.0-20250503011706-39ed1f5ac29c) on bench/link:
//
//   - CUBIC, because its HyStart usually leaves slow start before a
//     BDP-sized drop-tail queue overflows. Reno always overshoots, loses
//     hundreds of segments in one window, and on this gVisor often never
//     recovers (≈0 Mbit/s on the 100 Mbit/s, 50 ms reference link).
//   - RACK loss detection is optional. With it, a burst of drops (a
//     slow-start overshoot when the process is CPU-starved, or a
//     per-connection shaper) can leave a flow moving only on RTOs for
//     seconds; classic SACK recovery (RFC 6675) recovers. Without it, a
//     flow tolerates less reordering (three duplicate ACKs trigger a
//     retransmit), which matters only on paths that reorder.
package stacktune

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	// DefaultBuffer is the initial send/receive buffer of every socket.
	// It comfortably exceeds the bandwidth-delay product of the reference
	// 100 Mbit/s, 50 ms link (625 KB) plus a BDP-sized bottleneck queue.
	DefaultBuffer = 4 << 20
	// MaxBuffer is how far receive-buffer moderation may grow a buffer.
	MaxBuffer = 16 << 20
	// CongestionControl is the TCP congestion control algorithm.
	CongestionControl = "cubic"
)

// Tune enables SACK and receive-buffer moderation, selects
// CongestionControl, turns RACK-TLP loss detection on or off, and raises the
// default and maximum socket buffers of s for TCP and for the stack-wide
// (UDP) defaults. It affects sockets created afterwards.
func Tune(s *stack.Stack, rack bool) error {
	sack := tcpip.TCPSACKEnabled(true)
	mod := tcpip.TCPModerateReceiveBufferOption(true)
	cc := tcpip.CongestionControlOption(CongestionControl)
	recovery := tcpip.TCPRecovery(0)
	if rack {
		recovery = tcpip.TCPRACKLossDetection
	}
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: DefaultBuffer, Max: MaxBuffer}
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: DefaultBuffer, Max: MaxBuffer}
	for _, opt := range []tcpip.SettableTransportProtocolOption{&sack, &mod, &cc, &recovery, &snd, &rcv} {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			return fmt.Errorf("stacktune: TCP option %T: %v", opt, err)
		}
	}
	if err := s.SetOption(tcpip.SendBufferSizeOption{Min: stack.MinBufferSize, Default: DefaultBuffer, Max: MaxBuffer}); err != nil {
		return fmt.Errorf("stacktune: send buffer: %v", err)
	}
	if err := s.SetOption(tcpip.ReceiveBufferSizeOption{Min: stack.MinBufferSize, Default: DefaultBuffer, Max: MaxBuffer}); err != nil {
		return fmt.Errorf("stacktune: receive buffer: %v", err)
	}
	return nil
}
