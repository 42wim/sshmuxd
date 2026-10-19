# sshmux [![GoDoc](https://godoc.org/github.com/42wim/sshmux?status.svg)](http://godoc.org/github.com/42wim/sshmux)  [![Go Report Card](https://goreportcard.com/badge/kennylevinsen/sshmux)](https://goreportcard.com/report/42wim/sshmux)

Forked from https://github.com/kennylevinsen/sshmux
- adds support for globbing of hostnames
- supports ssh certificates
- add an OnlyProxyJump option

SSH multiplexing library, allowing you to write "jump host" style proxies.

Supports both transparent `-oProxyJump=sshmux-server` style jumps, as well as interactive session forwarding (with some limitations).


# Cryptographic policy

sshmux restricts the algorithms it negotiates rather than taking the Go defaults.

| | Offered, in preference order |
| --- | --- |
| Key exchange | `mlkem768x25519-sha256`, `curve25519-sha256`, `ecdh-sha2-nistp256/384/521`, `diffie-hellman-group16-sha512`, `diffie-hellman-group14-sha256` |
| Ciphers | `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `chacha20-poly1305@openssh.com` |
| MACs | `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256`, `hmac-sha2-512` |
| Host keys / public key auth | `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `rsa-sha2-256`, `rsa-sha2-512`, and the matching certificate algorithms |

The post-quantum hybrid exchange `mlkem768x25519-sha256` is listed first, so a
peer that supports it is never downgraded to a classical exchange. It protects
against store-now-decrypt-later attacks and requires OpenSSH 9.9 or newer on the
other end; older clients simply fall back to `curve25519-sha256`.

Only AEAD ciphers are offered, and the MACs only apply if a non-AEAD cipher is
somehow negotiated. Together with encrypt-then-MAC this rules out the Terrapin
prefix truncation attack (CVE-2023-48795). CBC, RC4, 3DES, the CTR modes,
`hmac-sha1`, `ssh-rsa` (SHA-1) and `ssh-dss` are not offered at all.

RSA host keys are automatically restricted to `rsa-sha2-256` and `rsa-sha2-512`.
`ssh.ServerConfig` has no host key algorithm setting, so without this the server
would advertise `ssh-rsa` for any RSA host key and scanners would flag it.

**Compatibility:** this needs roughly OpenSSH 7.2 or PuTTY 0.68 on the client
side. Anything older will fail to negotiate.

Every list can be overridden per field, and the defaults are exported if you
want to extend rather than replace them:

```go
server.Ciphers = []string{ssh.CipherAES256GCM}
server.KeyExchanges = append([]string{"custom-kex"}, sshmux.DefaultKeyExchanges...)
```

The `Upstream*` equivalents (`UpstreamCiphers`, `UpstreamKeyExchanges`,
`UpstreamMACs`, `UpstreamHostKeyAlgorithms`) control connections sshmux makes to
target hosts, separately from what it offers to clients.

## Verifying upstream host keys

For interactive session forwarding, sshmux terminates SSH and opens a second
connection to the target. By default that upstream host key is **not verified**,
which leaves the hop between sshmux and the target open to interception. sshmux
logs a warning when this is the case.

Supply a verifier to close that gap:

```go
cb, err := knownhosts.New("/etc/sshmux/known_hosts")
if err != nil {
    return err
}

server.UpstreamHostKeyCallback = cb
```

This does not apply to `direct-tcpip` forwards, which is what `ProxyJump` uses.
There sshmux relays raw TCP and the client verifies the target's host key itself,
end to end.

## Other security-relevant settings

| Field | Default | Purpose |
| --- | --- | --- |
| `HandshakeTimeout` | 2 minutes | Bounds the unauthenticated phase, like OpenSSH's `LoginGraceTime`. |
| `MaxAuthTries` | 6 | Authentication attempts per connection. |
| `MaxConcurrentConns` | unlimited | Caps connections served at once. |
| `OnlyProxyJump` | `false` | Refuses interactive sessions on the proxy itself. |
| `Logger` | `slog.Default()` | Receives connection, authentication and forwarding events. |

Use `ServeContext` instead of `Serve` for graceful shutdown: cancelling the
context stops the accept loop, closes live connections and returns once the
handlers have drained.


# But i just want to run it...

Look at sshmuxd instead, then: https://github.com/42wim/sshmuxd.
