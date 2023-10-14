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
	"strings"
	"sync"
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

var (
	configFile  = flag.String("config", "", "User-supplied configuration file to use")
	activeUsers sync.Map
)

func parseSSHCA() []ssh.PublicKey {
	var sshCA []ssh.PublicKey

	for _, caKey := range viper.GetStringSlice("sshca") {
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caKey))
		if err != nil {
			panic(fmt.Sprintf("Failed to parse sshca keys: %s %v", caKey, err))
		}

		sshCA = append(sshCA, pubKey)
	}

	return sshCA
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

func checkCert(c ssh.ConnMetadata, key ssh.PublicKey, cert *ssh.Certificate) (*sshmux.User, error) {
	certChecker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			marshaled := auth.Marshal()
			for _, k := range parseSSHCA() {
				if bytes.Equal(marshaled, k.Marshal()) {
					return true
				}
			}

			return false
		},
	}

	if !certChecker.IsUserAuthority(cert.SignatureKey) {
		return nil, errors.New("access denied")
	}

	if err := certChecker.CheckCert(c.User(), cert); err != nil {
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

func createAuth(users []*sshmux.User, hasDefaults bool) func(c ssh.ConnMetadata, key ssh.PublicKey) (*sshmux.User, error) {
	// sshmux setup
	return func(c ssh.ConnMetadata, key ssh.PublicKey) (*sshmux.User, error) {
		t := key.Type()
		k := key.Marshal()

		if cert, ok := key.(*ssh.Certificate); ok {
			sshmuxUser, err := checkCert(c, key, cert)
			if err != nil {
				logCertInfo(cert, c.RemoteAddr().String(), c.User(), "access denied")
				return nil, err
			}

			return sshmuxUser, nil
		}

		for i := range users {
			candidate := users[i].PublicKey
			if t == candidate.Type() && bytes.Equal(k, candidate.Marshal()) {
				return users[i], nil
			}
		}

		if hasDefaults {
			return nil, nil
		}

		log.Printf("%s: access denied (username: %s)", c.RemoteAddr(), c.User())

		return nil, errors.New("access denied")
	}
}

func createSetup(hosts []Host) func(*sshmux.Session) error {
	return func(session *sshmux.Session) error {
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

func createSelected(session *sshmux.Session, remote string) error {
	var username string

	if session.User != nil {
		username = session.User.Name
	} else {
		username = "unknown user"
	}

	if !destinationAllowed(remote) {
		addresses, _ := remoteToIPAddresses(remote)
		log.Printf("%s: %s tried connecting to %s: destination IP (%s) not allowed", session.Conn.RemoteAddr(), username, remote, addresses)

		return errors.New("access denied")
	}

	if session.User != nil && session.User.PublicKey != nil {
		if _, ok := session.User.PublicKey.(*ssh.Certificate); ok {
			addresses, _ := remoteToIPAddresses(remote)
			log.Printf("%s: %s connecting to %s (%s)", session.Conn.RemoteAddr(), username, remote, addresses)
		} else {
			log.Printf("%s: %s connecting to %s", session.Conn.RemoteAddr(), username, remote)
		}
	} else {
		log.Printf("%s: %s connecting to %s", session.Conn.RemoteAddr(), username, remote)
	}

	activeUsers.Store(username+" "+remote, time.Now().Format(time.RFC3339))

	return nil
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
			log.Printf("%s: %s disconnecting from %s (%s)", session.Conn.RemoteAddr(), username, remote, addresses)
		}
	}

	activeUsers.Delete(username + " " + remote)
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

func destinationAllowed(remote string) bool {
	if len(viper.GetStringSlice("destipallow")) == 0 {
		return true
	}

	var err error

	address, err := remoteToIPAddresses(remote)
	if err != nil {
		return false
	}

	if len(address) == 0 {
		fmt.Println("no address found for", remote)
		return false
	}

	count := 0

	for _, a := range address {
		for _, ip := range viper.GetStringSlice("destipallow") {
			prefix := netip.MustParsePrefix(ip)
			if prefix.Contains(netip.MustParseAddr(a)) {
				count++

				break
			}
		}
	}

	return count == len(address)
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

func setupViper() {
	flag.Parse()
	viper.SetDefault("address", ":22")
	viper.SetDefault("hostkey", "hostkey")
	viper.SetDefault("authkeys", "authkeys")
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
}

func setupViperWatch(hosts []Host, users []*sshmux.User) {
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Println("Config file changed:", e.Name)
		nh := make([]Host, 0)

		err := viper.UnmarshalKey("hosts", &nh)
		if err != nil {
			log.Printf("Error parsing the config file hosts list: %s\n"+
				"Keeping current host list", err)
		} else {
			hosts = nh
			log.Printf("New hosts list: %+v\n", hosts)
		}

		var u []*sshmux.User

		if u, err = parseUsers(); err != nil {
			log.Printf("Error parsing the config file users list: %s\n"+
				"Keeping current users list", err)
		} else {
			users = u
		}
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

	hosts := make([]Host, 0)

	if err := viper.UnmarshalKey("hosts", &hosts); err != nil {
		panic(fmt.Errorf("error parsing the config file hosts list: %s", err))
	}

	users, err := parseUsers()
	if err != nil {
		panic(fmt.Errorf("error parsing the config file hosts list: %s", err))
	}

	hostkeys := viper.GetStringSlice("hostkey")
	var hostSigners []ssh.Signer

	for _, hostkey := range hostkeys {
		hostSigner, err := ssh.ParsePrivateKey([]byte(hostkey))
		if err != nil {
			panic(err)
		}

		hostSigners = append(hostSigners, hostSigner)
	}

	setupViperWatch(hosts, users)

	hasDefaults := false

	for _, h := range hosts {
		if h.NoAuth {
			hasDefaults = true
			break
		}
	}

	sigchnl := make(chan os.Signal, 1)
	signal.Notify(sigchnl, syscall.SIGUSR1)

	go func() {
		for {
			s := <-sigchnl
			signalHandler(s)
		}
	}()

	server := sshmux.New(hostSigners, createAuth(users, hasDefaults), createSetup(hosts))
	server.OnlyProxyJump = viper.GetBool("onlyproxyjump")
	server.Selected = createSelected
	server.Dialer = getDialer()
	server.ForwardClose = createForwardClose
	// Set up listener
	l, err := net.Listen("tcp", viper.GetString("address"))
	if err != nil {
		panic(err)
	}

	proxyListener := &proxyproto.Listener{Listener: l}

	if err = server.Serve(proxyListener); err != nil {
		panic(err)
	}
}
