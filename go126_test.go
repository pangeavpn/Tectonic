//go:build !go1.27

package tectonic_test

// nodeOwnsConnection is false before Go 1.27: the node runs the TLS
// handshake itself, cannot rehearse a page load, and opens lanes with the
// shaping profile's records instead of the web server's.
const nodeOwnsConnection = false
