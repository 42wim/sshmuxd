package sshmux

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/ryanuber/go-glob"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func proxy(reqs1, reqs2 <-chan *ssh.Request, channel1, channel2 ssh.Channel) {
	var closer sync.Once

	closeFunc := func() {
		channel1.Close()
		channel2.Close()
	}

	defer closer.Do(closeFunc)

	closerChan := make(chan bool, 1)

	go func() {
		io.Copy(channel1, channel2)
		closerChan <- true
	}()

	go func() {
		io.Copy(channel2, channel1)
		closerChan <- true
	}()

	for {
		select {
		case req := <-reqs1:
			if req == nil {
				return
			}

			b, err := channel2.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}

			req.Reply(b, nil)

		case req := <-reqs2:
			if req == nil {
				return
			}

			b, err := channel1.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}

			req.Reply(b, nil)
		case <-closerChan:
			return
		}
	}
}

// https://tools.ietf.org/html/rfc4254
type channelOpenDirectMsg struct {
	RAddr string
	RPort uint32
	LAddr string
	LPort uint32
}

// ChannelForward establishes a secure channel forward (ssh -W) to the server
// requested by the user, assuming it is a permitted host.
func (s *Server) ChannelForward(session *Session, newChannel ssh.NewChannel) {
	var (
		msg      channelOpenDirectMsg
		selected *Remote
	)

	if err := ssh.Unmarshal(newChannel.ExtraData(), &msg); err != nil {
		s.logger().Warn("malformed direct-tcpip request",
			"remote", session.Conn.RemoteAddr().String(), "error", err)
		newChannel.Reject(ssh.ConnectionFailed, "malformed direct-tcpip request")

		return
	}

	address := fmt.Sprintf("%s:%d", msg.RAddr, msg.RPort)

	// A matched remote is dialed at the address the user asked for, so that a
	// single globbed entry can cover many hosts. Names without a wildcard
	// compare equal, so this also covers exact matches.
search:
	for _, remote := range session.Remotes {
		for _, name := range remote.Names {
			if glob.Glob(name, address) {
				selected = remote
				break search
			}
		}
	}

	if selected == nil {
		s.logger().Info("forward denied",
			"remote", session.Conn.RemoteAddr().String(),
			"login", session.Conn.User(),
			"target", address)
		newChannel.Reject(ssh.Prohibited, "remote host access denied for user")

		return
	}

	log := s.logger().With(
		"remote", session.Conn.RemoteAddr().String(),
		"login", session.Conn.User(),
		"target", address,
	)

	// Log the selection
	if s.Selected != nil {
		if err := s.Selected(session, address); err != nil {
			log.Info("forward denied by Selected", "error", err)
			newChannel.Reject(ssh.Prohibited, "access denied")

			return
		}
	}

	conn, err := s.Dialer("tcp", address)
	if err != nil {
		log.Warn("upstream dial failed", "error", err)
		newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("error: %v", err))

		return
	}

	channel, reqs, err := newChannel.Accept()
	if err != nil {
		log.Warn("could not accept direct-tcpip channel", "error", err)
		conn.Close()

		return
	}

	log.Info("forward opened")

	go ssh.DiscardRequests(reqs)

	var closer sync.Once

	closeFunc := func() {
		log.Info("forward closed")

		if s.ForwardClose != nil {
			s.ForwardClose(session, address)
		}
		channel.Close()
		conn.Close()
	}

	if session.Duration != 0 {
		go func() {
			time.Sleep(session.Duration)
			conn.Close()
		}()
	}

	go func() {
		io.Copy(channel, conn)
		closer.Do(closeFunc)
	}()

	io.Copy(conn, channel)
	closer.Do(closeFunc)
}

type rw struct {
	io.Reader
	io.Writer
}

// SessionForward performs a regular forward, providing the user with an
// interactive remote host selection if necessary. This forwarding type
// requires agent forwarding in order to work.
func (s *Server) SessionForward(session *Session, newChannel ssh.NewChannel) {
	// Okay, we're handling this as a regular session
	sesschan, sessReqs, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer sesschan.Close()

	// Buffered: the request pump must not block if the agent request arrives
	// after the wait below has already given up.
	agentCh := make(chan struct{}, 1)

	// Proxy the channel and its requests
	maskedReqs := make(chan *ssh.Request, 1)

	go func() {
		for req := range sessReqs {
			// Filter out auth agent requests, and answer some request types immediately in order to cope with PuTTY.
			switch req.Type {
			case "auth-agent-req@openssh.com":
				if req.WantReply {
					req.Reply(true, []byte{})
				}

				select {
				case agentCh <- struct{}{}:
				default:
				}

				continue
			case "pty-req", "shell":
				if req.WantReply {
					req.Reply(true, []byte{})
					req.WantReply = false
				}
			case "keepalive@openssh.com":
				if req.WantReply {
					req.Reply(true, []byte{})
					req.WantReply = false
				}
			}
			maskedReqs <- req
		}
	}()

	stderr := sesschan.Stderr()

	var remote *Remote

	comm := rw{Reader: sesschan, Writer: stderr}

	if s.Interactive == nil {
		remote, err = DefaultInteractive(comm, session)
	} else {
		remote, err = s.Interactive(comm, session)
	}

	if err != nil {
		fmt.Fprintf(stderr, "Error selecting remote: %+v\r\n", err)
		return
	}

	var username string

	switch {
	case s.UsernamePrompt != nil:
		comm := rw{Reader: sesschan, Writer: stderr}

		username, err = s.UsernamePrompt(comm, session)
		if err != nil {
			fmt.Fprintf(stderr, "username prompt failed: %+v", err)
			return
		}
	case remote.Username == "":
		username = session.Conn.User()
	default:
		username = remote.Username
	}

	// Log the selection
	if s.Selected != nil {
		if err = s.Selected(session, remote.Address); err != nil {
			fmt.Fprintf(stderr, "Remote host selection denied.\r\n")
			return
		}
	}

	fmt.Fprintf(stderr, "Connecting to %s\r\n", remote.Address)

	// Set up the agent
	useAgent := false
	select {
	case <-agentCh:
		useAgent = true
	case <-time.After(1 * time.Second):
		fmt.Fprintf(stderr, "\r\n====== sshmux ======\r\n")
		fmt.Fprintf(stderr, "No agent request received. Public key authentication will not be\r\n")
		fmt.Fprintf(stderr, "available. Either enable agent forwarding (-A), or use a ProxyJump.\r\n")
		fmt.Fprintf(stderr, "For more info, see the sshmux wiki.\r\n")
	}

	// Set up the client
	clientConfig := &ssh.ClientConfig{
		Config:            s.upstreamCryptoConfig(),
		HostKeyCallback:   s.upstreamHostKeyCallback(),
		HostKeyAlgorithms: orDefault(s.UpstreamHostKeyAlgorithms, DefaultHostKeyAlgorithms),
		User:              username,
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				comm := rw{Reader: sesschan, Writer: stderr}
				return KeyboardChallenge(comm, user, instruction, questions, echos)
			}),
			ssh.PasswordCallback(func() (string, error) {
				comm := rw{Reader: sesschan, Writer: stderr}
				return StringCallback(comm, username+"@"+remote.Address+":", true)
			}),
		},
		Timeout: 10 * time.Second,
	}

	if useAgent {
		agentChan, agentReqs, chanErr := session.Conn.OpenChannel("auth-agent@openssh.com", nil)
		if chanErr != nil {
			fmt.Fprintf(stderr, "agent forwarding failed: %+v", chanErr)
			return
		}

		defer agentChan.Close()

		go ssh.DiscardRequests(agentReqs)

		ag := agent.NewClient(agentChan)
		clientConfig.Auth = append([]ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)}, clientConfig.Auth...)
	}

	if s.ConnectionTimeout != 0 {
		clientConfig.Timeout = s.ConnectionTimeout
	}

	log := s.logger().With(
		"remote", session.Conn.RemoteAddr().String(),
		"login", session.Conn.User(),
		"target", remote.Address,
		"upstream_user", username,
	)

	conn, err := s.Dialer("tcp", remote.Address)
	if err != nil {
		log.Warn("upstream dial failed", "error", err)
		fmt.Fprintf(stderr, "Connect failed: %v\r\n", err)

		return
	}
	defer conn.Close()

	clientConn, clientChans, clientReqs, err := ssh.NewClientConn(conn, remote.Address, clientConfig)
	if err != nil {
		log.Warn("upstream handshake failed", "error", err)
		fmt.Fprintf(stderr, "Client connection setup failed: %v\r\n", err)

		return
	}

	client := ssh.NewClient(clientConn, clientChans, clientReqs)

	// Forward the session channel
	channel2, reqs2, err := client.OpenChannel("session", []byte{})
	if err != nil {
		log.Warn("upstream session channel failed", "error", err)
		fmt.Fprintf(stderr, "Remote session setup failed: %v\r\n", err)

		return
	}

	log.Info("session forward opened")
	defer log.Info("session forward closed")

	proxy(maskedReqs, reqs2, sesschan, channel2)
}
