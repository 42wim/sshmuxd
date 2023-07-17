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
	"strings"

	"github.com/42wim/sshmux"
	"github.com/fsnotify/fsnotify"
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

var configFile = flag.String("config", "", "User-supplied configuration file to use")

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

func createAuth(users []*sshmux.User, hasDefaults bool) func(c ssh.ConnMetadata, key ssh.PublicKey) (*sshmux.User, error) {
	// sshmux setup
	return func(c ssh.ConnMetadata, key ssh.PublicKey) (*sshmux.User, error) {
		t := key.Type()
		k := key.Marshal()

		if cert, ok := key.(*ssh.Certificate); ok {
			return checkCert(c, key, cert)
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
				log.Printf("%s: authorized (principals: %s)", session.Conn.RemoteAddr(), strings.Join(cert.ValidPrincipals, ","))
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
		log.Printf("%s: %s tried connecting to %s: destination IP not allowed", session.Conn.RemoteAddr(), username, remote)
		return errors.New("access denied")
	}

	if session.User != nil && session.User.PublicKey != nil {
		if cert, ok := session.User.PublicKey.(*ssh.Certificate); ok {
			log.Printf("%s: principals: %s connecting to %s", session.Conn.RemoteAddr(), strings.Join(cert.ValidPrincipals, ","), remote)
		} else {
			log.Printf("%s: %s connecting to %s", session.Conn.RemoteAddr(), username, remote)
		}
	} else {
		log.Printf("%s: %s connecting to %s", session.Conn.RemoteAddr(), username, remote)
	}

	return nil
}

func destinationAllowed(remote string) bool {
	if len(viper.GetStringSlice("allowedIPs")) == 0 {
		return true
	}

	var err error

	remote, _, err = net.SplitHostPort(remote)
	if err != nil {
		return false
	}

	address, err := net.LookupHost(remote)
	if err != nil {
		fmt.Println("error looking up address for", remote)
		return false
	}

	if len(address) == 0 {
		fmt.Println("no address found for", remote)
		return false
	}

	count := 0

	for _, a := range address {
		for _, ip := range viper.GetStringSlice("allowedIPs") {
			prefix := netip.MustParsePrefix(ip)
			if prefix.Contains(netip.MustParseAddr(a)) {
				count++

				break
			}
		}
	}

	return count == len(address)
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

func setupViperWatch(hosts []Host, users []*sshmux.User, hostSigner ssh.Signer) {
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

		var h ssh.Signer

		h, err = ssh.ParsePrivateKey([]byte(viper.GetString("hostkey")))
		if err != nil {
			log.Printf("Error parsing the config file hostkey: %s\n"+
				"Keeping current hostkey", err)
		} else {
			hostSigner = h
		}
	})
}

func getDialer() func(network string, address string) (net.Conn, error) {
	return func(network string, address string) (net.Conn, error) {
		if viper.GetString("localAddress") == "" {
			return net.Dial(network, address)
		}

		dialer := &net.Dialer{
			LocalAddr: &net.TCPAddr{
				IP:   net.ParseIP(viper.GetString("localAddress")),
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

	hostSigner, err := ssh.ParsePrivateKey([]byte(viper.GetString("hostkey")))
	if err != nil {
		panic(err)
	}

	setupViperWatch(hosts, users, hostSigner)

	hasDefaults := false

	for _, h := range hosts {
		if h.NoAuth {
			hasDefaults = true
			break
		}
	}

	server := sshmux.New(hostSigner, createAuth(users, hasDefaults), createSetup(hosts))
	server.OnlyProxyJump = viper.GetBool("onlyproxyjump")
	server.Selected = createSelected
	server.Dialer = getDialer()
	// Set up listener
	l, err := net.Listen("tcp", viper.GetString("address"))
	if err != nil {
		panic(err)
	}

	if err = server.Serve(l); err != nil {
		panic(err)
	}
}
