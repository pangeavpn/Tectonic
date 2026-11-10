//go:build !linux

package knet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/pangeavpn/tectonic/bench/link"
)

var errUnsupported = errors.New("knet: the kernel path needs Linux (network namespaces, veth, netem)")

func Supported() error                        { return errUnsupported }
func InNamespace() bool                       { return false }
func Reexec() (code int, ran bool, err error) { return 0, false, errUnsupported }

// Topology is unavailable on this platform; New always fails.
type Topology struct{ ServerCC string }

func New() (*Topology, error)                                     { return nil, errUnsupported }
func (t *Topology) Close()                                        {}
func (t *Topology) Configure(link.Config) error                   { return errUnsupported }
func (t *Topology) Stats() (up, down link.DirStats)               { return }
func (t *Topology) TCPFlows(uint16) ([]link.Flow, error)          { return nil, errUnsupported }
func (t *Topology) ResetFlow(link.Flow) error                     { return errUnsupported }
func (t *Topology) SS(bool, uint16) string                        { return "" }
func (t *Topology) Client() *Host                                 { return &Host{} }
func (t *Topology) Server() *Host                                 { return &Host{} }
func (t *Topology) ClientTunnel(netip.Addr) *Host                 { return &Host{} }
func (t *Topology) ServerTunnel(netip.Addr) *Host                 { return &Host{} }
func (t *Topology) TUN(bool, netip.Addr, int) (tun.Device, error) { return nil, errUnsupported }
func (t *Topology) WaitGone(time.Duration)                        {}

// Host is unavailable on this platform.
type Host struct{}

func (h *Host) Addr() netip.Addr                                          { return netip.Addr{} }
func (h *Host) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) { return nil, errUnsupported }
func (h *Host) ListenTCP(uint16) (net.Listener, error)                    { return nil, errUnsupported }
func (h *Host) ListenTCPAddrPort(netip.AddrPort) (net.Listener, error)    { return nil, errUnsupported }
func (h *Host) ListenUDP(uint16) (net.PacketConn, error)                  { return nil, errUnsupported }
func (h *Host) ListenUDPAddrPort(netip.AddrPort) (net.PacketConn, error)  { return nil, errUnsupported }
func (h *Host) DialUDP(netip.AddrPort) (net.Conn, error)                  { return nil, errUnsupported }
