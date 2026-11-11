//go:build !go1.27

package server

// httpServesTLSConns reports whether net/http serves a connection that has a
// tls.Conn's ConnectionState method the way it serves a tls.Conn. Before Go
// 1.27 only a *tls.Conn itself will do, and the cover web server can't be
// given one: the node has to see what the client sends first.
const httpServesTLSConns = false
