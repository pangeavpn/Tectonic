//go:build go1.27

package tectonic_test

// nodeOwnsConnection reports whether a node built with this Go lets its
// cover web server own the connections it is handed, which is what lets it
// learn its lane opening from the web server itself (design §8). From Go
// 1.27 it does. The server package decides the same thing for itself; this
// is the end-to-end tests' copy.
const nodeOwnsConnection = true
