package sshmux

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

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

	sshConfig *ssh.ServerConfig
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
	sshConn, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig)
	if err != nil {
		c.Close()
		return
	}
	defer sshConn.Close()

	if sshConn.Permissions == nil || sshConn.Permissions.Extensions == nil {
		return
	}

	ext := sshConn.Permissions.Extensions

	pk, err := ssh.ParsePublicKey([]byte(ext["pubKey"]))
	if err != nil {
		return
	}

	user, err := s.Authenticator(sshConn, pk)
	if err != nil {
		return
	}

	session := &Session{
		Conn:      sshConn,
		User:      user,
		PublicKey: pk,
	}

	s.Setup(session)

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
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go s.HandleConn(conn)
	}
}

func (s *Server) auth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	k := key.Marshal()
	t := key.Type()

	perm := &ssh.Permissions{
		Extensions: map[string]string{
			"pubKey":     string(k),
			"pubKeyType": t,
		},
	}

	_, err := s.Authenticator(conn, key)
	if err == nil {
		return perm, nil
	}

	return nil, err
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
		server.sshConfig.AddHostKey(signer)
	}

	return server
}
