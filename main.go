package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/42wim/sshmux"
	"github.com/fsnotify/fsnotify"
	"github.com/pires/go-proxyproto"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

type Host struct {
	Address         string   `json:"address"`
	Users           []string `json:"users"`
	NoAuth          bool     `json:"noAuth"`
	SSHCertRequired bool     `json:"sshCertRequired"`
}

type User struct {
	PublicKey string `json:"publicKey"`
	Name      string `json:"name"`
}

// config is an immutable snapshot of everything the request path reads.
// It is replaced wholesale on reload, so a connection never observes a
// half-applied configuration.
type config struct {
	hosts       []Host
	users       []*sshmux.User
	rules       Rules
	sshCA       []ssh.PublicKey
	destIPAllow []netip.Prefix
	hasDefaults bool
}

var (
	configFile   = flag.String("config", "", "User-supplied configuration file to use")
	activeUsers  sync.Map
	activeConfig atomic.Pointer[config]
)

// loadConfig builds a complete snapshot from viper. It either returns a fully
// valid config or an error, so a bad reload can never be applied partially.
func loadConfig() (*config, error) {
	c := &config{}

	if err := viper.UnmarshalKey("hosts", &c.hosts); err != nil {
		return nil, fmt.Errorf("hosts: %w", err)
	}

	var err error

	if c.users, err = parseUsers(); err != nil {
		return nil, fmt.Errorf("users: %w", err)
	}

	if c.rules, err = parseRules(); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}

	for _, r := range c.rules {
		c.hosts = append(c.hosts, r.Hosts...)
	}

	if c.sshCA, err = parseSSHCA(); err != nil {
		return nil, fmt.Errorf("sshca: %w", err)
	}

	if c.destIPAllow, err = parseDestIPAllow(); err != nil {
		return nil, fmt.Errorf("destipallow: %w", err)
	}

	for _, h := range c.hosts {
		if h.NoAuth {
			c.hasDefaults = true
			break
		}
	}

	return c, nil
}

func parseSSHCA() ([]ssh.PublicKey, error) {
	var sshCA []ssh.PublicKey

	for _, caKey := range viper.GetStringSlice("sshca") {
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caKey))
		if err != nil {
			return nil, fmt.Errorf("could not parse CA key %q: %w", caKey, err)
		}

		sshCA = append(sshCA, pubKey)
	}

	return sshCA, nil
}

func parseDestIPAllow() ([]netip.Prefix, error) {
	var prefixes []netip.Prefix

	for _, p := range viper.GetStringSlice("destipallow") {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("could not parse prefix %q: %w", p, err)
		}

		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}

func parseUsers() ([]*sshmux.User, error) {
	var users []*sshmux.User

	us := make([]User, 0)

	err := viper.UnmarshalKey("users", &us)
	if err != nil {
		return nil, err
	}

	for _, u := range us {
		encoded, err := base64.StdEncoding.DecodeString(u.PublicKey)
		if err != nil {
			return nil, errors.New("Could not decode key: " + u.Name)
		}

		pk, err := ssh.ParsePublicKey(encoded)
		if err != nil {
			return nil, errors.New(err.Error() + " for " + u.Name)
		}

		u := &sshmux.User{
			PublicKey: pk,
			Name:      u.Name,
		}

		users = append(users, u)
	}

	return users, nil
}

func checkCert(c ssh.ConnMetadata, key ssh.PublicKey, sshCA []ssh.PublicKey) (*sshmux.User, error) {
	certChecker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			marshaled := auth.Marshal()
			for _, k := range sshCA {
				if bytes.Equal(marshaled, k.Marshal()) {
					return true
				}
			}

			return false
		},
	}

	// Authenticate, unlike CheckCert, rejects host certificates and refuses a
	// cert whose signing authority is unknown.
	if _, err := certChecker.Authenticate(c, key); err != nil {
		return nil, errors.New("access denied")
	}

	return &sshmux.User{
		PublicKey: key,
		Name:      c.User(),
	}, nil
}

func getCertPublicKeys(cert *ssh.Certificate) (ssh.PublicKey, ssh.PublicKey) {
	pks, err := ssh.ParsePublicKey(cert.SignatureKey.Marshal())
	if err != nil {
		log.Printf("cert %#v signaturekey parsing failed: %s", cert, err)
	}

	pk, err := ssh.ParsePublicKey(cert.Key.Marshal())
	if err != nil {
		log.Printf("cert %#v publickey parsing failed: %s", cert, err)
	}

	return pk, pks
}

func logCertInfo(cert *ssh.Certificate, remote, username, status string) error {
	pk, pks := getCertPublicKeys(cert)
	if pk == nil || pks == nil {
		return errors.New("access denied - cert incorrect")
	}

	log.Printf("%s: %s %s (certificate %s %s ID \"%s\" (serial %d) CA %s %s principals: %s validuntil: %s)",
		remote, username, status,
		pk.Type(), ssh.FingerprintSHA256(pk),
		cert.KeyId, cert.Serial,
		pks.Type(), ssh.FingerprintSHA256(pks),
		strings.Join(cert.ValidPrincipals, ","),
		time.Unix(int64(cert.ValidBefore), 0),
	)

	return nil
}

func createAuth() func(c ssh.ConnMetadata, key ssh.PublicKey) (*sshmux.User, error) {
	// sshmux setup
	return func(c ssh.ConnMetadata, key ssh.PublicKey) (*sshmux.User, error) {
		cfg := activeConfig.Load()

		t := key.Type()
		k := key.Marshal()

		if cert, ok := key.(*ssh.Certificate); ok {
			sshmuxUser, err := checkCert(c, key, cfg.sshCA)
			if err != nil {
				logCertInfo(cert, c.RemoteAddr().String(), c.User(), "access denied")
				return nil, err
			}

			return sshmuxUser, nil
		}

		for i := range cfg.users {
			candidate := cfg.users[i].PublicKey
			if t == candidate.Type() && bytes.Equal(k, candidate.Marshal()) {
				return cfg.users[i], nil
			}
		}

		if cfg.hasDefaults {
			return nil, nil
		}

		log.Printf("%s: access denied (username: %s)", c.RemoteAddr(), c.User())

		return nil, errors.New("access denied")
	}
}

func createSetup() func(*sshmux.Session) error {
	return func(session *sshmux.Session) error {
		hosts := activeConfig.Load().hosts

		var username string
		if session.User != nil {
			username = session.User.Name
		} else {
			username = "unknown user"
		}

		if session.User != nil && session.User.PublicKey != nil {
			if cert, ok := session.User.PublicKey.(*ssh.Certificate); ok {
				err := logCertInfo(cert, session.Conn.RemoteAddr().String(), username, "authorized")
				if err != nil {
					return err
				}
			} else {
				log.Printf("%s: authorized (username: %s)", session.Conn.RemoteAddr(), username)
			}
		} else {
			log.Printf("%s: authorized (username: %s)", session.Conn.RemoteAddr(), username)
		}

	outer:
		for _, h := range hosts {
			switch {
			case h.NoAuth:
				session.Remotes = append(session.Remotes, &sshmux.Remote{
					Names:   []string{h.Address},
					Address: h.Address,
				})
				continue outer
			case h.SSHCertRequired && session.User != nil && session.User.PublicKey != nil:
				if _, ok := session.User.PublicKey.(*ssh.Certificate); ok {
					session.Remotes = append(session.Remotes, &sshmux.Remote{
						Names:   []string{h.Address},
						Address: h.Address,
					})
				}
				continue outer
			case session.User == nil:
				continue
			}

			for _, u := range h.Users {
				if u != session.User.Name {
					continue
				}

				session.Remotes = append(session.Remotes, &sshmux.Remote{
					Names:   []string{h.Address},
					Address: h.Address,
				})
				continue outer
			}
		}

		return nil
	}
}

func createForwardClose(session *sshmux.Session, remote string) {
	var username string

	if session.User != nil {
		username = session.User.Name
	} else {
		username = "unknown user"
	}

	if session.User != nil && session.User.PublicKey != nil {
		if _, ok := session.User.PublicKey.(*ssh.Certificate); ok {
			addresses, _ := remoteToIPAddresses(remote)
			lifetime := "unlimited"

			if session.Duration != 0 {
				lifetime = session.Duration.String()
			}

			log.Printf("%s: %s disconnecting from %s (%s) session lifetime: %s", session.Conn.RemoteAddr(), username, remote, addresses, lifetime)
		}
	}

	activeUsers.Delete(username + " " + remote + " " + fmt.Sprintf("%x", session.Conn.SessionID()))
}

func remoteToIPAddresses(remote string) ([]string, error) {
	var err error

	remote, _, err = net.SplitHostPort(remote)
	if err != nil {
		return nil, err
	}

	address, err := net.LookupHost(remote)
	if err != nil {
		return nil, fmt.Errorf("error looking up address for %s", remote)
	}

	return address, nil
}

func destinationAllowed(remote string, allowed []netip.Prefix) bool {
	if len(allowed) == 0 {
		return true
	}

	address, err := remoteToIPAddresses(remote)
	if err != nil {
		return false
	}

	if len(address) == 0 {
		log.Printf("no address found for %s", remote)
		return false
	}

	// Every resolved address must be permitted, so a mixed result set denies.
	for _, a := range address {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			log.Printf("could not parse resolved address %q for %s: %s", a, remote, err)
			return false
		}

		if !slices.ContainsFunc(allowed, func(p netip.Prefix) bool { return p.Contains(addr) }) {
			return false
		}
	}

	return true
}

// newProxyListener honours PROXY protocol headers only from trustedProxies.
// Without that restriction any peer can declare its own source address.
func newProxyListener(l net.Listener, trustedProxies []string) (net.Listener, error) {
	proxyListener := &proxyproto.Listener{Listener: l}

	if len(trustedProxies) == 0 {
		proxyproto.DefaultPolicy = proxyproto.USE

		log.Printf("WARNING: trustedproxies is unset, so a PROXY protocol header is accepted " +
			"from any peer. Any client can then choose its own source address, which defeats " +
			"rule \"src\" matching and forges the source address in the audit log. " +
			"Set trustedproxies to the CIDRs of your load balancers.")

		return proxyListener, nil
	}

	// Trusted peers may send a header; headers from anyone else are ignored
	// rather than rejected, so direct clients keep working.
	policy, err := proxyproto.PolicyFromRanges(trustedProxies, proxyproto.USE, proxyproto.IGNORE)
	if err != nil {
		return nil, fmt.Errorf("invalid trustedproxies entry: %w", err)
	}

	proxyListener.ConnPolicy = policy

	log.Printf("PROXY protocol headers accepted from: %s", strings.Join(trustedProxies, ", "))

	return proxyListener, nil
}

func signalHandler(signal os.Signal) {
	if signal == syscall.SIGUSR1 {
		log.Println("Active users/connections")

		i := 1

		activeUsers.Range(func(key, value any) bool {
			log.Printf("%d) %s %s", i, key, value)
			i++

			return true
		})
	}
}

// warnInsecureConfig reports a config file that other local users can read or
// replace. It holds the SSH host private key.
func warnInsecureConfig(path string) {
	if path == "" {
		return
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}

	info, err := os.Stat(abs)
	if err != nil {
		log.Printf("WARNING: cannot stat config file %s: %s", abs, err)
		return
	}

	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		log.Printf("WARNING: config file %s is mode %#o but holds the SSH host private key. "+
			"Restrict it with: chmod 600 %s", abs, mode, abs)
	}

	if cwd, err := os.Getwd(); err == nil && filepath.Dir(abs) == cwd {
		log.Printf("WARNING: config file %s was loaded from the working directory, which is "+
			"searched before $HOME/.sshmuxd and /etc/sshmuxd. Anyone able to write there "+
			"controls the host key, CA list, user list and rules.", abs)
	}
}

func setupViper() {
	flag.Parse()
	viper.SetDefault("address", ":22")
	viper.SetConfigName("sshmuxd")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.sshmuxd")
	viper.AddConfigPath("/etc/sshmuxd/")
	viper.SetConfigFile(*configFile)

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("error parsing the config file: %s", err))
	}

	log.Printf("Config File used: %s", viper.ConfigFileUsed())
	warnInsecureConfig(viper.ConfigFileUsed())
}

func setupViperWatch() {
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Println("Config file changed:", e.Name)

		c, err := loadConfig()
		if err != nil {
			log.Printf("Error parsing the config file: %s\n"+
				"Keeping the running configuration", err)

			return
		}

		activeConfig.Store(c)

		log.Printf("Configuration reloaded: %d hosts, %d users, %d rules, anonymous access: %t",
			len(c.hosts), len(c.users), len(c.rules), c.hasDefaults)
	})
}

func getDialer() func(network string, address string) (net.Conn, error) {
	return func(network string, address string) (net.Conn, error) {
		if viper.GetString("localAddress") == "" {
			return net.Dial(network, address)
		}

		hasIPv6dest := false

		addresses, err := remoteToIPAddresses(address)
		if err != nil {
			return nil, err
		}

		for _, a := range addresses {
			if strings.Contains(a, ":") {
				hasIPv6dest = true
			}
		}

		localAddress := viper.GetString("localAddress")
		if hasIPv6dest {
			localAddress = viper.GetString("localAddress6")
		}

		dialer := &net.Dialer{
			LocalAddr: &net.TCPAddr{
				IP:   net.ParseIP(localAddress),
				Port: 0,
			},
		}

		return dialer.Dial(network, address)
	}
}

func main() {
	setupViper()

	cfg, err := loadConfig()
	if err != nil {
		panic(fmt.Errorf("error parsing the config file: %w", err))
	}

	activeConfig.Store(cfg)

	hostkeys := viper.GetStringSlice("hostkey")
	var hostSigners []ssh.Signer

	for i, hostkey := range hostkeys {
		hostSigner, err := ssh.ParsePrivateKey([]byte(hostkey))
		if err != nil {
			panic(fmt.Errorf("error parsing hostkey %d: %w", i, err))
		}

		hostSigners = append(hostSigners, hostSigner)
	}

	if len(hostSigners) == 0 {
		panic(errors.New(`no hostkey configured: set "hostkey" to one or more SSH private keys`))
	}

	setupViperWatch()

	sigchnl := make(chan os.Signal, 1)
	signal.Notify(sigchnl, syscall.SIGUSR1)

	go func() {
		for {
			s := <-sigchnl
			signalHandler(s)
		}
	}()

	server := sshmux.New(hostSigners, createAuth(), createSetup())
	server.OnlyProxyJump = viper.GetBool("onlyproxyjump")
	server.Selected = createSelectedWithRules()
	server.Dialer = getDialer()
	server.ForwardClose = createForwardClose
	// Set up listener
	l, err := net.Listen("tcp", viper.GetString("address"))
	if err != nil {
		panic(err)
	}

	proxyListener, err := newProxyListener(l, viper.GetStringSlice("trustedproxies"))
	if err != nil {
		panic(err)
	}

	if err = server.Serve(proxyListener); err != nil {
		panic(err)
	}
}
