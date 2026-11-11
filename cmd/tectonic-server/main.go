// Command tectonic-server is the Tectonic node binary. It listens on port
// 443, logs clients in, serves its cover website to everyone else, and
// forwards tunnel traffic to the node's WireGuard.
//
//	tectonic-server serve -secret-file /etc/tectonic/node_secret \
//	    -cover-domain n12.example-cdn.net -cert cover.crt -key cover.key \
//	    -default-cert default.crt -default-key default.key \
//	    -cover-dir /var/www/cover -wireguard 127.0.0.1:51820
//
//	tectonic-server pin -cert default.crt
//	tectonic-server issue -secret-file /etc/tectonic/node_secret -days 30
//
// SIGHUP reloads the certificates and the revocation list; SIGINT and
// SIGTERM tell every client the node is going away and shut down.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pangeavpn/tectonic/lane"
	"github.com/pangeavpn/tectonic/server"
	"github.com/pangeavpn/tectonic/shape"
	"github.com/pangeavpn/tectonic/wire"
)

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "pin":
		err = pin(args)
	case "issue":
		err = issue(args)
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tectonic-server:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  tectonic-server [serve] [flags]   run the node
  tectonic-server pin -cert FILE    print a certificate's SPKI pin for the hub
  tectonic-server issue [flags]     issue a test credential the way the hub does

Run a command with -h for its flags.
`)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", ":443", "TCP address to listen on")
	secretFile := fs.String("secret-file", "", "file holding the node secret (hex, or at least 16 raw bytes)")
	coverDomain := fs.String("cover-domain", "", "the node's own domain, or a *.wildcard")
	certFile := fs.String("cert", "", "real certificate chain for the cover domain (PEM)")
	keyFile := fs.String("key", "", "key for -cert (PEM)")
	defCert := fs.String("default-cert", "default.crt", "default certificate for other names, created if missing")
	defKey := fs.String("default-key", "default.key", "key for -default-cert, created if missing")
	defName := fs.String("default-cert-name", defaultCertName, "name to put in the default certificate when it is created; an existing one is left as it is")
	coverDir := fs.String("cover-dir", "", "serve the cover website from this directory")
	coverProxy := fs.String("cover-proxy", "", "or proxy the cover website to this URL")
	wg := fs.String("wireguard", "127.0.0.1:51820", "the node's WireGuard UDP address")
	maxLanes := fs.Int("max-lanes", server.DefaultMaxLanes, "most lanes per client")
	maxCell := fs.Int("max-lanes-cellular", server.DefaultMaxLanesCellular, "most lanes per client on cellular")
	resume := fs.Duration("resume-window", server.DefaultResumeWindow, "how long a session outlives its last lane")
	shaping := fs.String("shaping", "", "shaping profile (JSON) to announce; default is built in")
	revoked := fs.String("revoked", "", "file of revoked key_ids, one hex key_id per line")
	cdnPath := fs.String("cdn-path", "", "WebSocket path for the CDN carrier (empty disables it)")
	cdnHeader := fs.String("cdn-header", "Edge-Signature", "header the CDN signs requests with")
	cdnSecretFile := fs.String("cdn-secret-file", "", "file holding the secret the CDN signs with")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	fs.Parse(args)

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	secret, err := readSecret(*secretFile)
	if err != nil {
		return fmt.Errorf("node secret: %w", err)
	}

	def := &certFiles{cert: *defCert, key: *defKey, name: *defName}
	if err := ensureDefaultCert(def, log); err != nil {
		return err
	}
	if err := def.reload(); err != nil {
		return fmt.Errorf("default certificate: %w", err)
	}
	if host, _ := os.Hostname(); def.names(host) {
		// It was made before the name could be chosen, and is left alone
		// because clients pin it.
		log.Warn("the default certificate names this machine, and it is shown to anyone who connects without the cover name; "+
			"remove both files to have one made under a neutral name, which has a new pin for the hub",
			"cert", def.cert, "key", def.key, "name", host)
	}
	var own *certFiles
	if *certFile != "" || *keyFile != "" {
		if *coverDomain == "" {
			return errors.New("-cert needs -cover-domain")
		}
		own = &certFiles{cert: *certFile, key: *keyFile}
		if err := own.reload(); err != nil {
			return fmt.Errorf("cover certificate: %w", err)
		}
	}

	var cover http.Handler
	switch {
	case *coverDir != "" && *coverProxy != "":
		return errors.New("use -cover-dir or -cover-proxy, not both")
	case *coverDir != "":
		cover = http.FileServer(http.Dir(*coverDir))
	case *coverProxy != "":
		u, err := url.Parse(*coverProxy)
		if err != nil {
			return fmt.Errorf("-cover-proxy: %w", err)
		}
		cover = httputil.NewSingleHostReverseProxy(u)
	default:
		return errors.New("a cover website is required: -cover-dir or -cover-proxy")
	}

	var profile *shape.Profile
	if *shaping != "" {
		b, err := os.ReadFile(*shaping)
		if err != nil {
			return err
		}
		if profile, err = shape.Parse(b); err != nil {
			return fmt.Errorf("-shaping: %w", err)
		}
	}

	rev := server.NewRevocation()
	loadRevoked := func() {
		if *revoked == "" {
			return
		}
		f, err := os.Open(*revoked)
		if err != nil {
			log.Error("revocation list", "err", err)
			return
		}
		defer f.Close()
		ids, err := server.ParseRevocationList(f)
		if err != nil {
			log.Error("revocation list", "err", err)
			return
		}
		rev.Set(ids)
		log.Info("revocation list loaded", "revoked", len(ids))
	}
	loadRevoked()

	cfg := server.Config{
		NodeSecret:         secret,
		CoverDomain:        *coverDomain,
		DefaultCertificate: def.get,
		Cover:              cover,
		WireGuard:          *wg,
		MaxLanes:           *maxLanes,
		MaxLanesCellular:   *maxCell,
		ResumeWindow:       *resume,
		Shaping:            profile,
		Revoked:            rev,
		Logger:             log,
	}
	if own != nil {
		cfg.OwnCertificate = own.get
	}
	if *cdnPath != "" {
		cdnSecret, err := readSecret(*cdnSecretFile)
		if err != nil {
			return fmt.Errorf("CDN secret: %w", err)
		}
		cfg.CDN = &server.CDNConfig{Path: *cdnPath, Verify: server.EdgeHeader(*cdnHeader, cdnSecret, nil)}
	}
	srv, err := server.New(cfg)
	if err != nil {
		return err
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigs {
			if sig == syscall.SIGHUP {
				for _, c := range []*certFiles{def, own} {
					if c != nil {
						if err := c.reload(); err != nil {
							log.Error("certificate reload", "file", c.cert, "err", err)
						}
					}
				}
				loadRevoked()
				srv.EnforceRevocation()
				log.Info("reloaded")
				continue
			}
			log.Info("shutting down")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			srv.Shutdown(ctx)
			cancel()
			return
		}
	}()

	log.Info("listening", "addr", *listen, "cover_domain", *coverDomain, "default_pin", def.pin(), "cdn", *cdnPath != "")
	if err := srv.ListenAndServe(*listen); !errors.Is(err, server.ErrServerClosed) {
		return err
	}
	return nil
}

// readSecret reads a secret file: hex if it decodes as hex, the raw bytes
// otherwise. Surrounding whitespace is ignored.
func readSecret(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("no file given")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(b))
	if h, err := hex.DecodeString(s); err == nil && len(h) >= 16 {
		return h, nil
	}
	if len(s) < 16 {
		return nil, errors.New("secret shorter than 16 bytes")
	}
	return []byte(s), nil
}

// certFiles is a certificate loaded from PEM files, reloadable while the
// server runs.
type certFiles struct {
	cert, key string
	// name is what ensureDefaultCert calls a certificate it creates. Empty
	// means defaultCertName.
	name string
	cur  atomic.Pointer[tls.Certificate]
}

func (c *certFiles) reload() error {
	tc, err := tls.LoadX509KeyPair(c.cert, c.key)
	if err != nil {
		return err
	}
	if tc.Leaf == nil {
		if tc.Leaf, err = x509.ParseCertificate(tc.Certificate[0]); err != nil {
			return err
		}
	}
	c.cur.Store(&tc)
	return nil
}

func (c *certFiles) get() (*tls.Certificate, error) {
	if tc := c.cur.Load(); tc != nil {
		return tc, nil
	}
	return nil, errors.New("no certificate loaded")
}

func (c *certFiles) pin() string {
	tc := c.cur.Load()
	if tc == nil || tc.Leaf == nil {
		return ""
	}
	return lane.PinOf(tc.Leaf).String()
}

// names reports whether the loaded certificate carries host as its subject
// or one of its DNS names.
func (c *certFiles) names(host string) bool {
	tc := c.cur.Load()
	if host == "" || tc == nil || tc.Leaf == nil {
		return false
	}
	if strings.EqualFold(tc.Leaf.Subject.CommonName, host) {
		return true
	}
	for _, n := range tc.Leaf.DNSNames {
		if strings.EqualFold(n, host) {
			return true
		}
	}
	return false
}

// defaultCertName is what a default certificate is called unless
// -default-cert-name says otherwise. The certificate goes to anyone who
// connects without the cover name, so its name must say nothing about the
// machine, and must not tell one node from another. "localhost" is among
// the commonest names on the self-signed certificates of web servers that
// nobody has configured.
const defaultCertName = "localhost"

// ensureDefaultCert creates a self-signed default certificate if the files
// don't exist, called c.name. A certificate that exists is left as it is,
// whatever it is called: clients pin it.
func ensureDefaultCert(c *certFiles, log *slog.Logger) error {
	_, errC := os.Stat(c.cert)
	_, errK := os.Stat(c.key)
	switch {
	case errC == nil && errK == nil:
		return nil
	case errC == nil || errK == nil:
		// Regenerating would change the pin every client trusts.
		return fmt.Errorf("only one of %s and %s exists; restore the other or remove both", c.cert, c.key)
	case !os.IsNotExist(errC):
		return errC
	case !os.IsNotExist(errK):
		return errK
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	// Not the machine's hostname: every prober would be told it.
	name := c.name
	if name == "" {
		name = defaultCertName
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(c.key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(c.cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	leaf, _ := x509.ParseCertificate(der)
	log.Info("created a default certificate; give its pin to the hub", "cert", c.cert, "name", name, "pin", lane.PinOf(leaf).String())
	return nil
}

func pin(args []string) error {
	fs := flag.NewFlagSet("pin", flag.ExitOnError)
	certFile := fs.String("cert", "default.crt", "PEM certificate")
	fs.Parse(args)
	b, err := os.ReadFile(*certFile)
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return errors.New("no PEM block found")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return err
	}
	fmt.Println(lane.PinOf(cert).String())
	return nil
}

// issue mints a credential the way the hub does, for testing a node
// without the hub. With -node it prints a complete profile block.
func issue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	secretFile := fs.String("secret-file", "", "file holding the node secret")
	days := fs.Int("days", 30, "days until the credential expires")
	node := fs.String("node", "", "node address for the profile block")
	coverDomain := fs.String("cover-domain", "", "cover domain for the profile block")
	pinFlag := fs.String("pin", "", "default-certificate pin for the profile block")
	fs.Parse(args)
	secret, err := readSecret(*secretFile)
	if err != nil {
		return err
	}
	id, err := wire.NewKeyID(time.Now().AddDate(0, 0, *days))
	if err != nil {
		return err
	}
	dk := wire.DeviceKey(secret, id)
	out := map[string]any{
		"key_id":     base64.StdEncoding.EncodeToString(id[:]),
		"device_key": base64.StdEncoding.EncodeToString(dk[:]),
	}
	if *node != "" {
		out["node"] = *node
	}
	if *coverDomain != "" {
		out["cover_domain"] = *coverDomain
	}
	if *pinFlag != "" {
		out["pins"] = []string{*pinFlag}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	fmt.Fprintf(os.Stderr, "key_id %s expires %s\n", id, time.Unix(int64(id.ExpiryDay())*86400, 0).UTC().Format("2006-01-02"))
	return enc.Encode(out)
}
