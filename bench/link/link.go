// Package link simulates a network path between two in-process hosts.
//
// New builds two gVisor network stacks, a client (10.0.0.1) and a server
// (10.0.0.2), joined by a point-to-point IPv4 link. Sockets on either host
// are ordinary net.Conn, net.Listener and net.PacketConn values (gonet), so
// any Go code that speaks TCP or UDP can run over the link unchanged.
//
// Each direction of the link is independent and passes every IP packet
// through four stages, in order:
//
//  1. Loss: random (Bernoulli) loss and, optionally, burst loss from a
//     Gilbert–Elliott two-state chain.
//  2. Per-connection rate cap: a token-bucket shaper per 5-tuple flow with a
//     short drop-tail queue, modelling middleboxes that throttle each TCP
//     connection separately. Flows never share a bucket.
//  3. Bottleneck: serialization at the link bandwidth through a drop-tail
//     queue of QueueBytes.
//  4. Propagation: a fixed one-way delay of RTT/2.
//
// Packets keep FIFO order within a flow and, after the bottleneck, within the
// direction. The pipeline is computed arithmetically from packet arrival
// times and drained by one goroutine per direction, so timer jitter (about a
// millisecond) delays delivery slightly but never distorts the modelled
// rates.
//
// The link also acts as an on-path censor: ResetFlow forges TCP resets to
// both ends of a connection, and BlackholeFlow silently drops a flow.
//
// Both hosts run gVisor TCP with CUBIC, SACK, no RACK and 4 MiB socket
// buffers that may grow to 16 MiB; with these one flow reaches about 96
// Mbit/s of goodput on a 100 Mbit/s, 50 ms link. gVisor recovers from heavy
// or bursty loss less well than a kernel TCP does, so absolute numbers on
// lossy links run low; transports compared on the same link are still
// compared fairly. Host.Stack allows retuning.
package link

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Addresses of the two hosts.
var (
	ClientAddr = netip.MustParseAddr("10.0.0.1")
	ServerAddr = netip.MustParseAddr("10.0.0.2")
)

const (
	// DefaultMTU is the link MTU when Config.MTU is zero.
	DefaultMTU = 1500
	// MinQueueBytes is the smallest default bottleneck queue.
	MinQueueBytes = 64 << 10

	// capQueueTime is how much backlog a per-flow shaper holds before it
	// drops, expressed as time at the capped rate.
	capQueueTime = 50 * time.Millisecond
	// capQueueMinPackets is the floor on that backlog, in full-size packets.
	capQueueMinPackets = 4
	// capBurstTime is the token-bucket depth, as time at the capped rate.
	capBurstTime = 10 * time.Millisecond
	// capBurstMinPackets is the floor on the bucket depth.
	capBurstMinPackets = 2
)

// GilbertElliott configures burst loss as a two-state Markov chain that
// steps once per packet. In the good state no packets are lost (beyond
// Config.Loss); in the bad state each packet is lost with probability
// LossBad. The long-run loss rate is LossBad·PGoodToBad/(PGoodToBad+PBadToGood)
// and the mean time spent in the bad state is 1/PBadToGood packets.
type GilbertElliott struct {
	PGoodToBad float64 // per-packet probability of entering the bad state
	PBadToGood float64 // per-packet probability of leaving the bad state
	LossBad    float64 // loss probability while in the bad state
}

// Config describes the simulated path. Every setting applies to each
// direction independently; the zero value is an ideal link with no delay.
type Config struct {
	// Bandwidth is the bottleneck rate in bits per second per direction,
	// counted on whole IP packets. Zero means unlimited.
	Bandwidth int64
	// RTT is the base round-trip time; each direction adds RTT/2.
	RTT time.Duration
	// Loss is the probability that any packet is dropped at random.
	Loss float64
	// Burst, if set, adds Gilbert–Elliott burst loss on top of Loss.
	Burst *GilbertElliott
	// PerConnRate caps each 5-tuple flow (TCP or UDP) to this many bits per
	// second per direction. Zero disables the cap.
	PerConnRate int64
	// QueueBytes is the bottleneck's drop-tail queue. Zero means one
	// bandwidth-delay product (Bandwidth·RTT/8), but at least MinQueueBytes.
	// It has no effect when Bandwidth is zero.
	QueueBytes int
	// Seed seeds the loss generators. The same seed gives each direction the
	// same sequence of loss decisions.
	Seed int64
	// MTU is the link MTU. Zero means DefaultMTU.
	MTU int
}

// DirStats counts what one direction of the link did with packets.
type DirStats struct {
	Packets          uint64 // packets delivered
	Bytes            uint64 // IP-level bytes delivered
	DroppedLoss      uint64 // dropped by random or burst loss
	DroppedQueue     uint64 // dropped by the bottleneck queue
	DroppedCap       uint64 // dropped by a per-connection shaper queue
	DroppedBlackhole uint64 // dropped because the flow was blackholed
}

// Link is a running simulated link between two hosts.
type Link struct {
	Client, Server *Host

	cfg        Config
	queueBytes int
	capBurst   int // per-flow token bucket depth, bytes
	capQueue   int // per-flow shaper queue limit, bytes

	mu       sync.Mutex
	closed   bool
	dirs     [2]*direction // dirUp: client→server, dirDown: server→client
	flows    map[flowKey]*flowState
	flowList []*flowState

	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

const (
	dirUp   = 0
	dirDown = 1
)

// New builds and starts a link.
func New(cfg Config) (*Link, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}
	l := &Link{
		cfg:   cfg,
		flows: make(map[flowKey]*flowState),
		done:  make(chan struct{}),
	}
	l.queueBytes = cfg.QueueBytes
	if l.queueBytes == 0 && cfg.Bandwidth > 0 {
		l.queueBytes = max(int(float64(cfg.Bandwidth)*cfg.RTT.Seconds()/8), MinQueueBytes)
	}
	if r := cfg.PerConnRate; r > 0 {
		l.capBurst = max(int(float64(r)*capBurstTime.Seconds()/8), capBurstMinPackets*cfg.MTU)
		l.capQueue = max(int(float64(r)*capQueueTime.Seconds()/8), capQueueMinPackets*cfg.MTU)
	}

	clientEP := &endpoint{mtu: uint32(cfg.MTU)}
	serverEP := &endpoint{mtu: uint32(cfg.MTU)}
	l.dirs[dirUp] = newDirection(l, dirUp, serverEP)
	l.dirs[dirDown] = newDirection(l, dirDown, clientEP)
	clientEP.out = l.dirs[dirUp]
	serverEP.out = l.dirs[dirDown]

	var err error
	if l.Client, err = newHost(ClientAddr, clientEP); err != nil {
		return nil, err
	}
	if l.Server, err = newHost(ServerAddr, serverEP); err != nil {
		l.Client.Stack.Destroy()
		return nil, err
	}
	for _, d := range l.dirs {
		l.wg.Add(1)
		go d.run()
	}
	return l, nil
}

func (c *Config) validate() error {
	prob := func(name string, p float64) error {
		if p < 0 || p > 1 {
			return fmt.Errorf("link: %s = %v, want a probability in [0, 1]", name, p)
		}
		return nil
	}
	switch {
	case c.Bandwidth < 0:
		return errors.New("link: negative Bandwidth")
	case c.RTT < 0:
		return errors.New("link: negative RTT")
	case c.PerConnRate < 0:
		return errors.New("link: negative PerConnRate")
	case c.QueueBytes < 0:
		return errors.New("link: negative QueueBytes")
	case c.MTU != 0 && c.MTU < 576:
		return fmt.Errorf("link: MTU %d below the IPv4 minimum of 576", c.MTU)
	}
	if err := prob("Loss", c.Loss); err != nil {
		return err
	}
	if b := c.Burst; b != nil {
		for _, p := range []struct {
			name string
			v    float64
		}{{"Burst.PGoodToBad", b.PGoodToBad}, {"Burst.PBadToGood", b.PBadToGood}, {"Burst.LossBad", b.LossBad}} {
			if err := prob(p.name, p.v); err != nil {
				return err
			}
		}
	}
	return nil
}

// Config returns the link's configuration with defaults filled in.
func (l *Link) Config() Config {
	cfg := l.cfg
	cfg.QueueBytes = l.queueBytes
	return cfg
}

// Close stops the link and tears down both stacks, aborting every socket on
// them. It is safe to call more than once.
func (l *Link) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		l.mu.Unlock()
		close(l.done)
		l.wg.Wait()
		l.Client.Stack.Destroy()
		l.Server.Stack.Destroy()
	})
	return nil
}

// Stats reports per-direction counters. up is client→server.
func (l *Link) Stats() (up, down DirStats) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dirs[dirUp].stats, l.dirs[dirDown].stats
}

// receiver returns the host on the receiving end of direction dir.
func (l *Link) receiver(dir int) *Host {
	if dir == dirUp {
		return l.Server
	}
	return l.Client
}

var _ stack.LinkEndpoint = (*endpoint)(nil)
