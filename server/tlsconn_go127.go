//go:build go1.27

package server

// httpServesTLSConns reports whether net/http serves a connection that has a
// tls.Conn's ConnectionState method the way it serves a tls.Conn: the TLS
// handshake, then HTTP/2 or HTTP/1.1 by ALPN. It does from Go 1.27.
const httpServesTLSConns = true
