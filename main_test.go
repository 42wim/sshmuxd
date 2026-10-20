package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42wim/sshmux"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

var testAddr = &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}

type fakeConn struct {
	user string
	addr net.Addr
}

func (f *fakeConn) User() string          { return f.user }
func (f *fakeConn) SessionID() []byte     { return []byte("session-id") }
func (f *fakeConn) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (f *fakeConn) ServerVersion() []byte { return []byte("SSH-2.0-sshmuxd") }
func (f *fakeConn) RemoteAddr() net.Addr  { return f.addr }
func (f *fakeConn) LocalAddr() net.Addr   { return f.addr }

func (f *fakeConn) SendRequest(string, bool, []byte) (bool, []byte, error) {
	return false, nil, nil
}

func (f *fakeConn) OpenChannel(string, []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, errors.New("not supported")
}

func (f *fakeConn) Close() error { return nil }
func (f *fakeConn) Wait() error  { return nil }

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	return signer
}

func signCert(t *testing.T, ca ssh.Signer, pub ssh.PublicKey, certType uint32, principals []string, validBefore uint64) *ssh.Certificate {
	t.Helper()

	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          1,
		CertType:        certType,
		KeyId:           "test-cert",
		ValidPrincipals: principals,
		ValidAfter:      0,
		ValidBefore:     validBefore,
	}

	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("sign cert: %v", err)
	}

	return cert
}

func primeDNS(t *testing.T, host string, addrs ...string) {
	t.Helper()

	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()

	dnsCache[host] = dnsEntry{addresses: addrs, expires: time.Now().Add(time.Hour)}
	t.Cleanup(func() {
		dnsCacheMu.Lock()
		defer dnsCacheMu.Unlock()
		delete(dnsCache, host)
	})
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()

	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}

	return addr
}

func TestSanitise(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "alice", `"alice"`},
		{"newline is escaped", "evil\nFORGED admin authorized", `"evil\nFORGED admin authorized"`},
		{"carriage return is escaped", "a\rb", `"a\rb"`},
		{"tab is escaped", "a\tb", `"a\tb"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitise(tt.in); got != tt.want {
				t.Errorf("sanitise(%q) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}

	t.Run("long input is capped", func(t *testing.T) {
		got := sanitise(strings.Repeat("A", 500))
		if len(got) > 140 {
			t.Errorf("sanitise did not cap length, got %d bytes", len(got))
		}
	})

	t.Run("no raw newline survives", func(t *testing.T) {
		if strings.Contains(sanitise("a\nb"), "\n") {
			t.Error("sanitise leaked a raw newline")
		}
	})
}

func TestCheckCert(t *testing.T) {
	ca := testSigner(t)
	otherCA := testSigner(t)
	user := testSigner(t)
	trusted := []ssh.PublicKey{ca.PublicKey()}

	t.Run("valid user certificate is accepted", func(t *testing.T) {
		cert := signCert(t, ca, user.PublicKey(), ssh.UserCert, []string{"alice"}, ssh.CertTimeInfinity)

		got, err := checkCert(&fakeConn{user: "alice", addr: testAddr}, cert, trusted)
		if err != nil {
			t.Fatalf("valid user cert rejected: %v", err)
		}

		if got.Name != "alice" {
			t.Errorf("got name %q, want alice", got.Name)
		}
	})

	// A host cert signed by the same CA used to authenticate as a user cert,
	// because CheckCert does not inspect CertType.
	t.Run("host certificate is rejected", func(t *testing.T) {
		cert := signCert(t, ca, user.PublicKey(), ssh.HostCert, []string{"alice"}, ssh.CertTimeInfinity)

		if _, err := checkCert(&fakeConn{user: "alice", addr: testAddr}, cert, trusted); err == nil {
			t.Fatal("host certificate was accepted as a user certificate")
		}
	})

	t.Run("certificate from an unknown CA is rejected", func(t *testing.T) {
		cert := signCert(t, otherCA, user.PublicKey(), ssh.UserCert, []string{"alice"}, ssh.CertTimeInfinity)

		if _, err := checkCert(&fakeConn{user: "alice", addr: testAddr}, cert, trusted); err == nil {
			t.Fatal("certificate from an untrusted CA was accepted")
		}
	})

	t.Run("expired certificate is rejected", func(t *testing.T) {
		cert := signCert(t, ca, user.PublicKey(), ssh.UserCert, []string{"alice"}, uint64(time.Now().Add(-time.Hour).Unix()))

		if _, err := checkCert(&fakeConn{user: "alice", addr: testAddr}, cert, trusted); err == nil {
			t.Fatal("expired certificate was accepted")
		}
	})

	t.Run("principal mismatch is rejected", func(t *testing.T) {
		cert := signCert(t, ca, user.PublicKey(), ssh.UserCert, []string{"alice"}, ssh.CertTimeInfinity)

		if _, err := checkCert(&fakeConn{user: "mallory", addr: testAddr}, cert, trusted); err == nil {
			t.Fatal("certificate accepted for a principal it was not issued to")
		}
	})
}

func TestCreateAuth(t *testing.T) {
	known := testSigner(t)
	unknown := testSigner(t)

	base := &config{
		users: []*sshmux.User{{PublicKey: known.PublicKey(), Name: "alice"}},
	}

	t.Run("known key authenticates", func(t *testing.T) {
		activeConfig.Store(base)

		got, err := createAuth()(&fakeConn{user: "alice", addr: testAddr}, known.PublicKey())
		if err != nil {
			t.Fatalf("known key rejected: %v", err)
		}

		if got == nil || got.Name != "alice" {
			t.Fatalf("got %+v, want user alice", got)
		}
	})

	t.Run("unknown key is denied without noAuth hosts", func(t *testing.T) {
		activeConfig.Store(base)

		if _, err := createAuth()(&fakeConn{user: "mallory", addr: testAddr}, unknown.PublicKey()); err == nil {
			t.Fatal("unknown key was accepted")
		}
	})

	// Any noAuth host enables anonymous access globally. Unchanged behaviour,
	// asserted so a regression is visible.
	t.Run("unknown key is anonymous when a noAuth host exists", func(t *testing.T) {
		withDefaults := *base
		withDefaults.hasDefaults = true
		activeConfig.Store(&withDefaults)

		got, err := createAuth()(&fakeConn{user: "mallory", addr: testAddr}, unknown.PublicKey())
		if err != nil {
			t.Fatalf("expected anonymous acceptance, got %v", err)
		}

		if got != nil {
			t.Fatalf("expected a nil user for anonymous access, got %+v", got)
		}
	})
}

func TestCreateSetup(t *testing.T) {
	user := testSigner(t)
	ca := testSigner(t)

	hosts := []Host{
		{Address: "open.example.com:22", NoAuth: true},
		{Address: "alice-only.example.com:22", Users: []string{"alice"}},
		{Address: "bob-only.example.com:22", Users: []string{"bob"}},
		{Address: "cert.example.com:22", SSHCertRequired: true},
	}

	activeConfig.Store(&config{hosts: hosts})

	remotes := func(t *testing.T, u *sshmux.User) []string {
		t.Helper()

		session := &sshmux.Session{User: u, Conn: &ssh.ServerConn{Conn: &fakeConn{user: "x", addr: testAddr}}}
		if err := createSetup()(session); err != nil {
			t.Fatalf("setup failed: %v", err)
		}

		var got []string
		for _, r := range session.Remotes {
			got = append(got, r.Address)
		}

		return got
	}

	t.Run("named user gets only their hosts", func(t *testing.T) {
		got := remotes(t, &sshmux.User{PublicKey: user.PublicKey(), Name: "alice"})

		want := []string{"open.example.com:22", "alice-only.example.com:22"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("anonymous user gets only noAuth hosts", func(t *testing.T) {
		got := remotes(t, nil)

		want := []string{"open.example.com:22"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("certificate user reaches sshCertRequired hosts", func(t *testing.T) {
		cert := signCert(t, ca, user.PublicKey(), ssh.UserCert, []string{"carol"}, ssh.CertTimeInfinity)
		got := remotes(t, &sshmux.User{PublicKey: cert, Name: "carol"})

		if !strings.Contains(strings.Join(got, ","), "cert.example.com:22") {
			t.Errorf("certificate user did not reach the sshCertRequired host, got %v", got)
		}
	})

	t.Run("plain key user does not reach sshCertRequired hosts", func(t *testing.T) {
		got := remotes(t, &sshmux.User{PublicKey: user.PublicKey(), Name: "alice"})

		if strings.Contains(strings.Join(got, ","), "cert.example.com:22") {
			t.Errorf("plain key user reached an sshCertRequired host, got %v", got)
		}
	})
}

func TestDestinationAllowed(t *testing.T) {
	primeDNS(t, "allowed.example.com", "10.1.0.5")
	primeDNS(t, "denied.example.com", "192.0.2.5")
	primeDNS(t, "mixed.example.com", "10.1.0.5", "192.0.2.5")

	allowed := []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}

	tests := []struct {
		name    string
		remote  string
		allowed []netip.Prefix
		want    bool
	}{
		{"empty allow list permits everything", "denied.example.com:22", nil, true},
		{"address inside an allowed prefix", "allowed.example.com:22", allowed, true},
		{"address outside every prefix", "denied.example.com:22", allowed, false},
		// All resolved addresses must pass, so a partial match denies.
		{"mixed result set is denied", "mixed.example.com:22", allowed, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := destinationAllowed(tt.remote, tt.allowed); got != tt.want {
				t.Errorf("destinationAllowed(%q) = %t, want %t", tt.remote, got, tt.want)
			}
		})
	}
}

func TestParseHostKeys(t *testing.T) {
	key := generatePEM(t)

	t.Run("single key list", func(t *testing.T) {
		viper.Reset()
		viper.Set("hostkey", []string{key})

		got, err := parseHostKeys()
		if err != nil {
			t.Fatalf("single key hostkey rejected: %v", err)
		}

		if len(got) != 1 {
			t.Fatalf("got %d signers, want 1", len(got))
		}
	})

	t.Run("list form", func(t *testing.T) {
		viper.Reset()
		viper.Set("hostkey", []string{key, key})

		got, err := parseHostKeys()
		if err != nil {
			t.Fatalf("list hostkey rejected: %v", err)
		}

		if len(got) != 2 {
			t.Fatalf("got %d signers, want 2", len(got))
		}
	})

	t.Run("missing hostkey is an error", func(t *testing.T) {
		viper.Reset()

		if _, err := parseHostKeys(); err == nil {
			t.Fatal("missing hostkey accepted")
		}
	})

	t.Run("malformed hostkey is an error", func(t *testing.T) {
		viper.Reset()
		viper.Set("hostkey", []string{"not a key"})

		if _, err := parseHostKeys(); err == nil {
			t.Fatal("malformed hostkey accepted")
		}
	})
}

func generatePEM(t *testing.T) string {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	return string(pem.EncodeToMemory(block))
}

func TestLoadConfigRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		set  func()
	}{
		{"malformed CA key", func() { viper.Set("sshca", []string{"ssh-rsa not-base64"}) }},
		{"malformed destipallow prefix", func() { viper.Set("destipallow", []string{"10.0.0.0/notanumber"}) }},
		{"malformed localAddress", func() { viper.Set("localAddress", "999.999.999.999") }},
		{"malformed rule duration", func() {
			viper.Set("rules", []map[string]any{{"name": "r", "duration": "not-a-duration"}})
		}},
		{"malformed rule source prefix", func() {
			viper.Set("rules", []map[string]any{{"name": "r", "src": []string{"nonsense"}}})
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			tt.set()

			if _, err := loadConfig(); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestLoadConfigDerivesHasDefaults(t *testing.T) {
	viper.Reset()
	viper.Set("hosts", []map[string]any{{"address": "a.example.com:22", "users": []string{"alice"}}})

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.hasDefaults {
		t.Error("hasDefaults is true with no noAuth host")
	}

	viper.Set("hosts", []map[string]any{{"address": "a.example.com:22", "noAuth": true}})

	cfg, err = loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	// Previously computed once at startup, so removing the last noAuth host
	// left anonymous access enabled until a restart.
	if !cfg.hasDefaults {
		t.Error("hasDefaults is false despite a noAuth host")
	}
}

func TestLoadConfigIncludesRuleHosts(t *testing.T) {
	viper.Reset()
	viper.Set("hosts", []map[string]any{{"address": "direct.example.com:22"}})
	viper.Set("rules", []map[string]any{
		{"name": "r", "hosts": []map[string]any{{"address": "viarule.example.com:22"}}},
	})

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	var got []string
	for _, h := range cfg.hosts {
		got = append(got, h.Address)
	}

	want := "direct.example.com:22,viarule.example.com:22"
	if strings.Join(got, ",") != want {
		t.Errorf("got %v, want %s", got, want)
	}
}

// The request path used to read shared slices while the fsnotify goroutine
// rewrote them. Run under -race, this is the regression test for that.
func TestConcurrentReloadAndRequests(t *testing.T) {
	known := testSigner(t)
	user := testSigner(t)

	newCfg := func(n int) *config {
		return &config{
			users: []*sshmux.User{{PublicKey: known.PublicKey(), Name: "alice"}},
			hosts: []Host{
				{Address: "open.example.com:22", NoAuth: true},
				{Address: "alice.example.com:22", Users: []string{"alice"}},
			}[:1+n%2],
		}
	}

	activeConfig.Store(newCfg(0))

	auth := createAuth()
	setup := createSetup()

	stop := make(chan struct{})

	var reloader sync.WaitGroup

	reloader.Add(1)

	go func() {
		defer reloader.Done()

		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}

			activeConfig.Store(newCfg(i))
		}
	}()

	var workers sync.WaitGroup

	for range 8 {
		workers.Add(1)

		go func() {
			defer workers.Done()

			for range 500 {
				if _, err := auth(&fakeConn{user: "alice", addr: testAddr}, known.PublicKey()); err != nil {
					t.Errorf("auth failed during reload: %v", err)
					return
				}

				session := &sshmux.Session{
					User: &sshmux.User{PublicKey: user.PublicKey(), Name: "alice"},
					Conn: &ssh.ServerConn{Conn: &fakeConn{user: "alice", addr: testAddr}},
				}

				if err := setup(session); err != nil {
					t.Errorf("setup failed during reload: %v", err)
					return
				}
			}
		}()
	}

	workers.Wait()
	close(stop)
	reloader.Wait()
}
