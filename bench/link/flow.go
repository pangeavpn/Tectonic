package link

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// IP protocol numbers used in Flow.Proto.
const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// TCP flags.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// Flow identifies a TCP or UDP flow by its 5-tuple. Src is the endpoint
// that sent the first packet the link saw (for TCP, the side that dialled).
// Methods that take a Flow accept either orientation.
type Flow struct {
	Proto    uint8 // ProtoTCP or ProtoUDP
	Src, Dst netip.AddrPort
}

func (f Flow) String() string {
	proto := fmt.Sprintf("proto%d", f.Proto)
	switch f.Proto {
	case ProtoTCP:
		proto = "tcp"
	case ProtoUDP:
		proto = "udp"
	}
	return fmt.Sprintf("%s %v→%v", proto, f.Src, f.Dst)
}

type flowKey struct {
	proto    uint8
	src, dst netip.AddrPort
}

func (k flowKey) reverse() flowKey { return flowKey{k.proto, k.dst, k.src} }

// flowState is what the link knows about one flow. Guarded by Link.mu.
type flowState struct {
	flow       Flow
	srcDir     int // direction in which flow.Src sends
	blackholed bool
	shapers    [2]shaper   // per direction
	tcp        [2]tcpTrack // per direction: what was delivered that way
}

// tcpTrack follows the sequence space of TCP segments delivered in one
// direction, which is what a forged reset needs to land in the window.
type tcpTrack struct {
	seen    bool
	nextSeq uint32 // highest seq+len delivered, i.e. ≥ the receiver's RCV.NXT
	ackSeen bool
	ack     uint32 // ACK field of the latest delivered segment with ACK set
}

func (t *tcpTrack) observe(m meta) {
	if !t.seen || int32(m.seqEnd-t.nextSeq) > 0 {
		t.nextSeq = m.seqEnd
		t.seen = true
	}
	if m.flags&tcpACK != 0 {
		t.ack = m.ack
		t.ackSeen = true
	}
}

// meta is what the link parses out of an IPv4 packet.
type meta struct {
	ok     bool // a TCP or UDP packet with ports (not a later fragment)
	key    flowKey
	isTCP  bool
	seqEnd uint32 // TCP: sequence number after this segment
	ack    uint32
	flags  uint8
}

func parse(b []byte) (m meta) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return m
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < 20 || total < ihl || total > len(b) {
		return m
	}
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return m // not the first fragment: no transport header
	}
	proto := b[9]
	l4 := b[ihl:total]
	switch proto {
	case ProtoTCP:
		if len(l4) < 20 {
			return m
		}
		off := int(l4[12]>>4) * 4
		if off < 20 || off > len(l4) {
			return m
		}
		m.isTCP = true
		m.flags = l4[13]
		m.ack = binary.BigEndian.Uint32(l4[8:12])
		segLen := uint32(len(l4) - off)
		if m.flags&tcpSYN != 0 {
			segLen++
		}
		if m.flags&tcpFIN != 0 {
			segLen++
		}
		m.seqEnd = binary.BigEndian.Uint32(l4[4:8]) + segLen
	case ProtoUDP:
		if len(l4) < 8 {
			return m
		}
	default:
		return m
	}
	src := netip.AddrFrom4([4]byte(b[12:16]))
	dst := netip.AddrFrom4([4]byte(b[16:20]))
	m.key = flowKey{
		proto: proto,
		src:   netip.AddrPortFrom(src, binary.BigEndian.Uint16(l4[0:2])),
		dst:   netip.AddrPortFrom(dst, binary.BigEndian.Uint16(l4[2:4])),
	}
	m.ok = true
	return m
}

// flowLocked returns the state for the flow m belongs to, creating it on
// first sight. It returns nil for packets that are not TCP or UDP.
func (l *Link) flowLocked(m meta, dir int) *flowState {
	if !m.ok {
		return nil
	}
	if f := l.flows[m.key]; f != nil {
		return f
	}
	return l.addFlowLocked(m.key, dir)
}

func (l *Link) addFlowLocked(k flowKey, dir int) *flowState {
	f := &flowState{flow: Flow{Proto: k.proto, Src: k.src, Dst: k.dst}, srcDir: dir}
	l.flows[k] = f
	l.flows[k.reverse()] = f
	l.flowList = append(l.flowList, f)
	return f
}

// Flows returns every TCP and UDP flow the link has seen (or was told to
// blackhole in advance), oldest first.
func (l *Link) Flows() []Flow {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Flow, len(l.flowList))
	for i, f := range l.flowList {
		out[i] = f.flow
	}
	return out
}

// BlackholeFlow silently drops every further packet of f in both
// directions, including packets already in flight on the link. A flow the
// link has not seen yet is blackholed from its first packet.
func (l *Link) BlackholeFlow(f Flow) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := flowKey{f.Proto, f.Src, f.Dst}
	fs := l.flows[k]
	if fs == nil {
		dir := dirUp
		if f.Src.Addr() == ServerAddr {
			dir = dirDown
		}
		fs = l.addFlowLocked(k, dir)
	}
	fs.blackholed = true
}

// ResetFlow models an on-path injector tearing down a TCP connection: it
// forges an RST|ACK to each end, as if sent by the other end, using the
// sequence numbers the link last delivered so that both land in the
// receivers' windows. The resets reach the hosts immediately, ahead of
// anything still in flight. Packets of the flow keep flowing afterwards; the
// endpoints answer them with their own resets.
//
// It fails if f is not a TCP flow the link has carried packets for.
func (l *Link) ResetFlow(f Flow) error {
	if f.Proto != ProtoTCP {
		return fmt.Errorf("link: ResetFlow %v: not a TCP flow", f)
	}
	type forged struct {
		to  *endpoint
		pkt []byte
	}
	var out []forged

	l.mu.Lock()
	fs := l.flows[flowKey{f.Proto, f.Src, f.Dst}]
	if fs == nil {
		l.mu.Unlock()
		return fmt.Errorf("link: ResetFlow %v: unknown flow", f)
	}
	for dir := range 2 {
		// The RST travels in direction dir, so it resets dir's receiver.
		in, back := &fs.tcp[dir], &fs.tcp[1-dir]
		var seq uint32
		switch {
		case in.seen:
			// At or beyond the receiver's RCV.NXT and within its window.
			seq = in.nextSeq
		case back.ackSeen:
			// Nothing delivered to it yet; fall back to what it acked.
			seq = back.ack
		default:
			continue
		}
		var ack uint32
		if back.seen {
			ack = back.nextSeq
		}
		src, dst := fs.flow.Src, fs.flow.Dst
		if dir != fs.srcDir {
			src, dst = dst, src
		}
		out = append(out, forged{l.receiver(dir).ep, forgeRST(src, dst, seq, ack)})
	}
	l.mu.Unlock()

	if len(out) == 0 {
		return fmt.Errorf("link: ResetFlow %v: %w", f, errNoSegments)
	}
	for _, p := range out {
		p.to.deliver(p.pkt)
	}
	return nil
}

var errNoSegments = errors.New("no TCP segments delivered yet")

// forgeRST builds a 40-byte IPv4 TCP RST|ACK segment with valid checksums.
func forgeRST(src, dst netip.AddrPort, seq, ack uint32) []byte {
	b := make([]byte, 40)
	ip, tcp := b[:20], b[20:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // DF
	ip[8] = 64
	ip[9] = ProtoTCP
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	binary.BigEndian.PutUint16(ip[10:12], ^checksum(0, ip))

	binary.BigEndian.PutUint16(tcp[0:2], src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = tcpRST | tcpACK
	var pseudo [12]byte
	copy(pseudo[0:4], s4[:])
	copy(pseudo[4:8], d4[:])
	pseudo[9] = ProtoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	binary.BigEndian.PutUint16(tcp[16:18], ^checksum(checksum(0, pseudo[:]), tcp))
	return b
}

// checksum folds b into the running ones'-complement sum.
func checksum(sum uint16, b []byte) uint16 {
	s := uint32(sum)
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	return uint16(s)
}
