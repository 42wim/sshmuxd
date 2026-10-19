package sshmux

import (
	"golang.org/x/crypto/ssh"
)

// DefaultKeyExchanges lists the permitted key exchange algorithms, in
// preference order. The post-quantum hybrid exchange is offered first so that
// peers supporting it are not downgraded to a classical exchange.
var DefaultKeyExchanges = []string{
	ssh.KeyExchangeMLKEM768X25519,
	ssh.KeyExchangeCurve25519,
	ssh.KeyExchangeECDHP256,
	ssh.KeyExchangeECDHP384,
	ssh.KeyExchangeECDHP521,
	ssh.KeyExchangeDH16SHA512,
	ssh.KeyExchangeDH14SHA256,
}

// DefaultCiphers lists the permitted ciphers, in preference order. Only AEAD
// ciphers are offered; the encrypt-then-MAC and AEAD constructions are immune
// to the Terrapin prefix truncation attack (CVE-2023-48795).
var DefaultCiphers = []string{
	ssh.CipherAES256GCM,
	ssh.CipherAES128GCM,
	ssh.CipherChaCha20Poly1305,
}

// DefaultMACs lists the permitted MAC algorithms, in preference order.
// Encrypt-then-MAC variants are preferred and SHA-1 is not offered. These only
// apply when a non-AEAD cipher is negotiated, which DefaultCiphers prevents.
var DefaultMACs = []string{
	ssh.HMACSHA256ETM,
	ssh.HMACSHA512ETM,
	ssh.HMACSHA256,
	ssh.HMACSHA512,
}

// DefaultHostKeyAlgorithms lists the host key algorithms accepted from upstream
// servers, in preference order. SHA-1 based ssh-rsa and ssh-dss are excluded.
var DefaultHostKeyAlgorithms = []string{
	ssh.CertAlgoED25519v01,
	ssh.CertAlgoECDSA256v01,
	ssh.CertAlgoECDSA384v01,
	ssh.CertAlgoECDSA521v01,
	ssh.CertAlgoRSASHA256v01,
	ssh.CertAlgoRSASHA512v01,
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA256,
	ssh.KeyAlgoRSASHA512,
}

// DefaultPublicKeyAuthAlgorithms lists the algorithms accepted for client
// public key authentication. Certificate algorithms are deliberately absent:
// the SSH server derives those from the underlying key algorithm.
var DefaultPublicKeyAuthAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA256,
	ssh.KeyAlgoRSASHA512,
}

func orDefault(configured, fallback []string) []string {
	if len(configured) == 0 {
		return fallback
	}

	return configured
}

// cryptoConfig returns the algorithm policy applied to connections accepted by
// this server.
func (s *Server) cryptoConfig() ssh.Config {
	return ssh.Config{
		KeyExchanges: orDefault(s.KeyExchanges, DefaultKeyExchanges),
		Ciphers:      orDefault(s.Ciphers, DefaultCiphers),
		MACs:         orDefault(s.MACs, DefaultMACs),
	}
}

// upstreamCryptoConfig returns the algorithm policy applied to connections this
// server makes to upstream hosts.
func (s *Server) upstreamCryptoConfig() ssh.Config {
	return ssh.Config{
		KeyExchanges: orDefault(s.UpstreamKeyExchanges, DefaultKeyExchanges),
		Ciphers:      orDefault(s.UpstreamCiphers, DefaultCiphers),
		MACs:         orDefault(s.UpstreamMACs, DefaultMACs),
	}
}

// upstreamHostKeyCallback returns the configured upstream verifier, falling
// back to accepting any host key.
func (s *Server) upstreamHostKeyCallback() ssh.HostKeyCallback {
	if s.UpstreamHostKeyCallback != nil {
		return s.UpstreamHostKeyCallback
	}

	s.insecureUpstreamOnce.Do(func() {
		s.logger().Warn("upstream host keys are not verified, set UpstreamHostKeyCallback")
	})

	return ssh.InsecureIgnoreHostKey()
}

// restrictHostKey drops SHA-1 from the signature algorithms a host key may
// use. ssh.ServerConfig has no host key algorithm setting: the server
// advertises every algorithm the key format allows, which for RSA includes
// ssh-rsa, unless the signer reports a narrower set itself.
func restrictHostKey(signer ssh.Signer) ssh.Signer {
	if underlyingKeyType(signer.PublicKey().Type()) != ssh.KeyAlgoRSA {
		return signer
	}

	as, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return signer
	}

	restricted, err := ssh.NewSignerWithAlgorithms(as,
		[]string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512})
	if err != nil {
		return signer
	}

	return restricted
}

func underlyingKeyType(keyType string) string {
	if keyType == ssh.CertAlgoRSAv01 {
		return ssh.KeyAlgoRSA
	}

	return keyType
}
