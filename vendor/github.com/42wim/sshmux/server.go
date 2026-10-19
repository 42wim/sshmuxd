package sshmux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultHandshakeTimeout bounds how long an unauthenticated connection may
// occupy the server, mirroring OpenSSH's LoginGraceTime.
const DefaultHandshakeTimeout = 2 * time.Minute

// Remote describes the selectable remote server.
type Remote struct {
	// The various names that can be used to select this remote
	Names []string

	// The description used for interactive prompting
	Description string

	// The address of this remote
	Address string

	// The username to connect with
	Username string
}

// User describes an authenticable user.
type User struct {
	// The public key of the user.
	PublicKey ssh.PublicKey

	// The name the user will be referred to as. *NOT* the username used when
	// starting the session.
	Name string
}

// Session describes the current user session.
type Session struct {
	// Conn is the ssh.ServerConn associated with the connection.
	Conn *ssh.ServerConn

	// User is the current user, or nil if unknown.
	User *User

	// Duration
	Duration time.Duration

	// Remotes is the allowed set of remote hosts.
	Remotes []*Remote

	// PublicKey is the public key used in this session.
	PublicKey ssh.PublicKey
}

// Server is the sshmux server instance.
type Server struct {
	// Authenticator checks if a connection is permitted, and returns a user if
	// recognized.. Returning nil error indicates that the login was allowed,
	// regardless of whether the user was recognized or not. To disallow a
	// connection, return an error.
	Authenticator func(ssh.ConnMetadata, ssh.PublicKey) (*User, error)

	// Setup takes a Session, the most important task being filling out the
	// permitted remote hosts. Returning an error here will send the error to
	// the user and terminate the connection. This is not as clean as denying
	// the user in Authenticator, but can be used in case the denial was too
	// dynamic.
	Setup func(*Session) error

	// Interactive is called to ask the user to select a host on the list of
	// potential remote hosts. This is only called in the case where more than
	// one option is available. If an error is returned, it is presented to the
	// user and the connection is terminated. The io.ReadWriter is to be used
	// for user interaction.
	Interactive func(io.ReadWriter, *Session) (*Remote, error)

	// Selected is called when a remote host has been decided upon. The main
	// purpose of this callback is logging, but returning an error will
	// terminate the connection, allowing it to be used as a last-minute
	// bailout.
	Selected func(*Session, string) error

	// Dialer specifies a dial-up function used to establish the underlying
	// network connection to the ssh servers. Defaults to net.Dial.
	Dialer func(network, address string) (net.Conn, error)

	// UsernamePrompt is used to prompt the user for a username. If nil, the
	// username used to connect to sshmux will be used.
	UsernamePrompt func(io.ReadWriter, *Session) (string, error)

	// ConnectionTimeout specifies the timeout to use when forwarding a
	// connection. If zero, a sensible default will be used.
	ConnectionTimeout time.Duration

	// OnlyProxyJump specifies that we can only use this as a ProxyJump
	OnlyProxyJump bool

	// ForwardClose is run when the forwarded connection closes.
	// Main use case is to log connections ending.
	ForwardClose func(*Session, string)

	// KeyExchanges, Ciphers and MACs restrict the algorithms offered to
	// connecting clients. If empty, the corresponding Default* list is used.
	KeyExchanges []string
	Ciphers      []string
	MACs         []string

	// PublicKeyAuthAlgorithms restricts the algorithms accepted for client
	// public key authentication. If empty,
	// DefaultPublicKeyAuthAlgorithms is used.
	PublicKeyAuthAlgorithms []string

	// MaxAuthTries is the number of authentication attempts permitted per
	// connection. If zero, a sensible default is used. Negative means
	// unlimited.
	MaxAuthTries int

	// ServerVersion is the version string announced during the handshake. It
	// must start with "SSH-2.0-". If empty, a sensible default is used.
	ServerVersion string

	// HandshakeTimeout bounds the time between accepting a connection and
	// completing authentication. If zero, DefaultHandshakeTimeout is used.
	// Negative disables the deadline.
	HandshakeTimeout time.Duration

	// UpstreamHostKeyCallback verifies the host key presented by an upstream
	// server during a session forward. If nil, upstream host keys are
	// accepted without verification, which leaves the hop between sshmux and
	// the target open to interception. Prefer knownhosts.New.
	//
	// This does not apply to direct-tcpip forwards (ssh -W, ProxyJump), where
	// sshmux relays raw TCP and the client verifies the host key itself.
	UpstreamHostKeyCallback ssh.HostKeyCallback

	// UpstreamHostKeyAlgorithms restricts the host key algorithms accepted
	// from upstream servers. If empty, DefaultHostKeyAlgorithms is used.
	UpstreamHostKeyAlgorithms []string

	// UpstreamKeyExchanges, UpstreamCiphers and UpstreamMACs restrict the
	// algorithms offered to upstream servers. If empty, the corresponding
	// Default* list is used.
	UpstreamKeyExchanges []string
	UpstreamCiphers      []string
	UpstreamMACs         []string

	// MaxConcurrentConns bounds the number of connections served at once.
	// Further connections wait for a slot. If zero, there is no limit.
	MaxConcurrentConns int

	// Logger receives connection, authentication and forwarding events. If
	// nil, slog.Default is used.
	Logger *slog.Logger

	sshConfig            *ssh.ServerConfig
	configOnce           sync.Once
	insecureUpstreamOnce sync.Once

	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
	closed  bool
	wg      sync.WaitGroup
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}

	return slog.Default()
}

func (s *Server) trackConn(c net.Conn) bool {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()

	if s.closed {
		return false
	}

	if s.conns == nil {
		s.conns = make(map[net.Conn]struct{})
	}

	s.conns[c] = struct{}{}

	return true
}

func (s *Server) untrackConn(c net.Conn) {
	s.connsMu.Lock()
	delete(s.conns, c)
	s.connsMu.Unlock()
}

// closeConns marks the server closed and drops every live connection, so that
// the handlers blocked on them return.
func (s *Server) closeConns() {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()

	s.closed = true

	for c := range s.conns {
		c.Close()
	}
}

// applyConfig folds the Server fields into the ssh.ServerConfig. It runs once,
// lazily, so that fields assigned after New still take effect.
func (s *Server) applyConfig() {
	s.configOnce.Do(func() {
		s.sshConfig.Config = s.cryptoConfig()
		s.sshConfig.PublicKeyAuthAlgorithms = orDefault(
			s.PublicKeyAuthAlgorithms, DefaultPublicKeyAuthAlgorithms)
		s.sshConfig.MaxAuthTries = s.MaxAuthTries
		s.sshConfig.ServerVersion = s.ServerVersion
		s.sshConfig.AuthLogCallback = func(conn ssh.ConnMetadata, method string, err error) {
			if err == nil || errors.Is(err, ssh.ErrNoAuth) {
				return
			}

			s.logger().Info("authentication failed",
				"remote", conn.RemoteAddr().String(),
				"login", conn.User(),
				"method", method,
				"error", err)
		}
	})
}

type publicKey struct {
	publicKey     []byte
	publicKeyType string
}

func (p *publicKey) Marshal() []byte {
	b := make([]byte, len(p.publicKey))
	copy(b, p.publicKey)
	return b
}

func (p *publicKey) Type() string {
	return p.publicKeyType
}

func (p *publicKey) Verify([]byte, *ssh.Signature) error {
	return errors.New("verify not implemented")
}

// HandleConn takes a net.Conn and runs it through sshmux.
func (s *Server) HandleConn(c net.Conn) {
	s.HandleConnContext(context.Background(), c)
}

// HandleConnContext is HandleConn with a context. Cancelling the context
// closes the connection.
func (s *Server) HandleConnContext(ctx context.Context, c net.Conn) {
	s.applyConfig()

	if !s.trackConn(c) {
		c.Close()
		return
	}
	defer s.untrackConn(c)

	if ctx.Done() != nil {
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
	}

	if d := s.handshakeTimeout(); d > 0 {
		c.SetDeadline(time.Now().Add(d))
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig)
	if err != nil {
		s.logger().Info("handshake failed",
			"remote", c.RemoteAddr().String(), "error", err)
		c.Close()

		return
	}
	defer sshConn.Close()

	// Authentication is done; the deadline must not bound the session itself.
	c.SetDeadline(time.Time{})

	if sshConn.Permissions == nil || sshConn.Permissions.Extensions == nil {
		return
	}

	ext := sshConn.Permissions.Extensions

	pk, err := ssh.ParsePublicKey([]byte(ext["pubKey"]))
	if err != nil {
		s.logger().Warn("could not parse authenticated public key",
			"remote", sshConn.RemoteAddr().String(), "error", err)

		return
	}

	user, _ := sshConn.Permissions.ExtraData[authenticatedUser{}].(*User)

	log := s.logger().With(
		"remote", sshConn.RemoteAddr().String(),
		"login", sshConn.User(),
		"fingerprint", ssh.FingerprintSHA256(pk),
	)
	if user != nil {
		log = log.With("user", user.Name)
	}

	if a, ok := sshConn.Conn.(ssh.AlgorithmsConnMetadata); ok {
		algs := a.Algorithms()
		log.Info("negotiated algorithms",
			"kex", algs.KeyExchange,
			"hostkey", algs.HostKey,
			"cipher", algs.Read.Cipher,
			"mac", algs.Read.MAC)
	}

	log.Info("session opened")
	defer log.Info("session closed")

	session := &Session{
		Conn:      sshConn,
		User:      user,
		PublicKey: pk,
	}

	if err := s.Setup(session); err != nil {
		log.Info("setup denied connection", "error", err)

		return
	}

	go func() {
		for req := range reqs {
			switch req.Type {
			case "keepalive@openssh.com":
				if req.WantReply {
					req.Reply(true, []byte{})
				}
			default:
				req.Reply(false, []byte{})
			}
		}
	}()

	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			if s.OnlyProxyJump {
				newChannel.Reject(ssh.UnknownChannelType, "you can not login here, please ProxyJump to a host first")

				continue
			}

			go s.SessionForward(session, newChannel)
		case "direct-tcpip":
			go s.ChannelForward(session, newChannel)
		case "forwarded-tcpip":
			newChannel.Reject(ssh.UnknownChannelType, "sshmux server cannot remote forward ports, please ProxyJump to a host first")
		default:
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("sshmux server cannot handle %s channel types, please ProxyJump to a host first", newChannel.ChannelType()))
		}
	}
}

// Serve is an Accept loop that sends the accepted connections through
// HandleConn.
func (s *Server) Serve(l net.Listener) error {
	return s.ServeContext(context.Background(), l)
}

// ServeContext is Serve with a context. Cancelling the context stops the
// accept loop, closes the listener and every live connection, and returns once
// the handlers have finished.
func (s *Server) ServeContext(ctx context.Context, l net.Listener) error {
	s.applyConfig()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	context.AfterFunc(ctx, func() {
		l.Close()
		s.closeConns()
	})

	var sem chan struct{}
	if s.MaxConcurrentConns > 0 {
		sem = make(chan struct{}, s.MaxConcurrentConns)
	}

	var delay time.Duration

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				s.wg.Wait()
				return ctxErr
			}

			if errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return err
			}

			// A single failed accept, such as hitting the file descriptor
			// limit, must not tear down the whole listener.
			delay = min(max(delay*2, 5*time.Millisecond), time.Second)
			s.logger().Warn("accept failed, retrying", "error", err, "delay", delay)
			time.Sleep(delay)

			continue
		}

		delay = 0

		if sem != nil {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				conn.Close()
				s.wg.Wait()

				return ctx.Err()
			}
		}

		s.wg.Add(1)

		go func() {
			defer s.wg.Done()

			if sem != nil {
				defer func() { <-sem }()
			}

			s.HandleConnContext(ctx, conn)
		}()
	}
}

// authenticatedUser keys the *User resolved during authentication in
// ssh.Permissions.ExtraData.
type authenticatedUser struct{}

func (s *Server) handshakeTimeout() time.Duration {
	if s.HandshakeTimeout == 0 {
		return DefaultHandshakeTimeout
	}

	return s.HandshakeTimeout
}

func (s *Server) auth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	user, err := s.Authenticator(conn, key)
	if err != nil {
		return nil, err
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"pubKey":     string(key.Marshal()),
			"pubKeyType": key.Type(),
		},
		ExtraData: map[any]any{authenticatedUser{}: user},
	}, nil
}

// New returns a Server initialized with the provided signer and callbacks.
func New(signers []ssh.Signer, auth func(ssh.ConnMetadata, ssh.PublicKey) (*User, error), setup func(*Session) error) *Server {
	server := &Server{
		Authenticator: auth,
		Setup:         setup,
		Dialer:        net.Dial,
	}

	server.sshConfig = &ssh.ServerConfig{
		PublicKeyCallback: server.auth,
	}

	for _, signer := range signers {
		server.sshConfig.AddHostKey(restrictHostKey(signer))
	}

	return server
}
