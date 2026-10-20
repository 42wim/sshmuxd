# sshmuxd [![Go Report Card](https://goreportcard.com/badge/42wim/sshmuxd)](https://goreportcard.com/report/42wim/sshmuxd)

Forked from https://github.com/kennylevinsen/sshmuxd
- adds support for globbing of hostnames
- supports ssh certificates
- add an OnlyProxyJump option

A SSH "jump host" style proxy, based off the https://github.com/42wim/sshmux library.

So, why not just a jump host? Well, if it's just you and no one else needing access, go ahead. If you, however, want to give more than one person SSH access through your public IP on port N (N often being 22), then you might want something with a bit more access control. Sure, you can make really complicated SSH configs that limit a lot of things for the other users, but they'll always be able to poke around more than you want them to, and it'll be a pain in the butt to maintain.

Thinking it could be done simpler, sshmux and sshmuxd got written. It allows you to have a proxy that will *only* permit forwarding to user-specific servers, regardless of method. No other poking around is possible, and no having to allow actual login for anyone to the server running sshmuxd.

# Installation
The safest way to install sshmuxd is via git:

	go install github.com/42wim/sshmuxd

# What does it do?

It acts like a regular SSH server, waiting for either session channel requests (regular ssh) or direct tcp connection requests (ssh -W).

If it gets a regular session channel request, it will figure out what servers the user is allowed to connect to. If the user is only permitted access to one server, it writes out which server it is connecting to, and connects immediately. If the user is permitted access to multiple servers, it will present the user with an interactive prompt, asking which server the user wishes to connect to.

If it gets a direct tcp connection request, it will simply check if this connection is permitted for the user, and if yes, execute the connection.

## Just show me what it looks like!

Using the "regular ssh"-mode with interactive selection (that is, more than one permitted remote host for that user):

	$ ssh sshmux.example.com
	Welcome to sshmux, kennylevinsen
	    [0] server1.example.com:22
	    [1] server2.example.com:22
	    [2] secret.example.com:65432
	Please select remote server:

If you then enter a number, it'll look like this:

	Please select remote server: 1
	Connecting to server2.example.com:22
	$ hostname
	server2.example.com

If there were only one permitted host, sshmuxd will skip right to showing "Connecting to...". In direct tcp mode (ssh -W), you don't see any difference at all.

## But agent forwarding is dangerous!

In the general sense, yes. If you don't just ignore SSH's warnings about changed host keys, then you can be sure that you're connecting to the real host. That means that, to abuse agents in the common sense, the root user must be compromised on that machine. The root user will then be able to sign things with our private key by accessing the agent socket that got forwarded. The result is the same as if the root user of your local machine got compromised, with a private key that is password protected very well, but the agent had the key unlocked, signing requests as it is told.

With sshmux, agent forwarding isn't handled as a socket, but in-memory. Depending on OS, this doesn't necessarily protect you against an evil root, due to peculiar interfaces such as /dev/mem, but it sure does increase the barrier of entry: Rather than just reading an easily found socket, you need to inspect arbitrary process memory, finding the right component and interfacing with it accordingly.

A good note, however, is that if you are concerned about the hosts you log into having arbitrary process memory or root login compromised, you shouldn't really log in to them at all, but take them offline immediately and use a serial console (virtual or physical) to salvage what is necessary, followed by a total wipe of the machine. Using them, or even just leaving them online in this state, will not bring you any good.

With this, I am not saying that agent forwarding isn't dangerous. Don't use agent-forwarding to arbitrary machines you don't trust. If you have these concerns, you can use ssh -W, which provides guarantees of security against any issues with the jump host (but not the remote host). ssh -W as ProxyCommand in ssh_config is also much more convenient for hosts you log into often, rather than having to make interactive selections.

Personally, I wish that ssh agents would ask the user before signing. This way, agent forwarding could be used a bit more relaxed, as users would be prompted with what and who is trying to sign before accepting. If signing is attempted without you using it, you could simply deny it. Blindly signing things is a bad idea.

## But what's ssh -W?

ssh -W asks the SSH server to make a raw TCP connection, and forward stdin/stdout of the local client over the ssh connection to the raw TCP connection. How do you use that to jump hosts? With ProxyCommand! Put the following in your ~/.ssh/config (see the ssh_config manpage):

	Host server1.example.com
		ProxyCommand ssh -W %h:%p sshmux.example.com

Followed by running ssh from your command-line:

	ssh server1.example.com

You can also do this directly on the command-line, without ssh_config, with:

	ssh -oProxyCommand="ssh -W %h:%p sshmux.example.com" server1.example.com

This technique works is the general approach to jump hosts, and not related to sshmux. sshmux simply implements it with fine-grained controls. For more info, see the the wiki page (https://github.com/kennylevinsen/sshmuxd/wiki/ProxyCommand) or the ssh manpage.

# Limitations
sshmux, and by extension, sshmuxd, can only forward normal sessions (ssh'ing directly to sshmuxd without a ProxyCommand) if agent forwarding is enabled. This is because your normal session authenticates to sshmux, but sshmux then has to authenticate you with the remote host, requiring a additional access to your agent. sshmux will, however, not forward your agent to the final remote host. Doing this is simple if wanted, but I have yet to decide on how this is toggled.

Please note that the sftp and scp clients bundled with openssh cannot use normal session forwarding thus you must use a ProxyCommand for them. If you want them to work normal session forwarding, try to revive this *very* old bug report about it: https://bugzilla.mindrot.org/show_bug.cgi?id=831.

Using a "ssh -W" ProxyCommand circumvents this limitation, both for ssh and sftp/scp, and also bypasses the interactive server selection, as the client will inform sshmux of the wanted target directly. If the target is permitted, the user will be connected. This also provides more protection for the paranoid, as the connection to the final host is encrypted end-to-end, rather than being plaintext in the memory of sshmux.

# Configuration
sshmuxd requires a configuration file named sshmuxd.json/.yml in one of the following places:
  - Working dir
	- $HOME/.sshmuxd/
	- /etc/sshmuxd/
	- or pass the path on command line using --config filename.json

The format of the file is as follows (note that, due to the presence of comments, this is not actually a valid JSON file. Remove comments before use, or refer to sshmuxd.json).
You can also use YAML, see sshmuxd.yml for an example.

```
{
	// Listening address as given directly to net.Listen.
	"address": ":22",

	// Private keys to use for built-in SSH server. Make sure you replace all newlines with \n
	// Generate your own with: ssh-keygen -t ed25519 -f sshmuxd_host_key -N ""
	// Never reuse a key published in documentation.
	"hostkey": ["-----BEGIN OPENSSH PRIVATE KEY-----\nREPLACE THIS WITH YOUR OWN HOST KEY\n-----END OPENSSH PRIVATE KEY-----"],

	// Authorized keys to use for authenticating users.
	"users": [
		{
			"publicKey": "AAAAC3NzaC1lZDI1NTE5AAAAIG5AnPTKFnstV0y4n9m4Qo624wEkQKdVKz0HTrsGmecs",
			"name": "me"
		},
		{
			"publicKey": "AAAAC3NzaC1lZDI1NTE5AAAAINg6gWZLnH5gwLeDlw/URtvYgKmlFiiXHmra6oYObfBz",
			"name": "boss"
		},
		{
			"publicKey": "AAAAB3NzaC1yc2EAAAADAQABAAACAQDEmICmR4ZD175AlaWnLrMlHnNTu9MqZplgkj2MZOoX4gODbzlRUcI4MquehcZ3evF7o9GjAMLRVN16fkDBx6YH7tFfQFxsSSfIToXHW0L8k06HW5eoLEo6nZ/mBI7tq98XQ4qWC71n+/O59bGP2mFph1LR4G2m9DApW4I/JVTLqWh0dkQbNV5RrPn9h+nJ0dNUumubUU2uTyd9u6UjCc+Hg9ScqNc3fheNoeS72ihu/33G/O+xwUc0nX+0ngRsUkakGgk5IiU4Lx4xofqMRiKKcQNHajo9tLGKLv11EaMEOdMDVJiTf/JGFyEMofM0tPqJjLXXwtTqgFx/8y5PIiZsuepaouNBWZ3T/Sp8OUZsim67Tllvc7qFZ6zzdMXLD5aKLtqkRgDvP9NuGlHVbq2cdkrCToIjsz5PZo+KvNV6V+Tzy13QKkwkHmabMOMRiR5MH4Jt80lJeOce1Se9e57rHhJ8DmxhEmqNSCIYegrX6hW+8XMRDdmL8OS7US9v7dwpjB+lehDidH2xd3rTzEbR+EeFZJ47L+jSSO+GDYRRB7IffnVf2JAwKCAQu13w8TJwLKBwKUHqcbb/vnofHz6geLweIM03Rbi4e87zdMgeghbM0ys6hAg/ZMwUkpUn89OGtGBE5cmjPYXEdbJcd8EF3LTmEf/POdaJ1qc/ObHbUw==",
			"name": "granny"
		}
	],

	// The list of remote hosts that can be used through this proxy.
	"hosts": [
		{
			// The address of the remote host. This address must include the
			// port.
			"address": "ssh1.example.com:22",

			// The list of users permitted to access this host.
			"users": [ "boss", "me", "granny" ],

			// Whether or not this server can be accessed by anyone,
			// regardless of public key and presence in user list.
			// Defaults to false.
			"noAuth": false
		},
		{
			"address": "public.example.com:22",
			"noAuth": true
		},
		{
			"address": "secret.example.com:22",
			"users": [ "me" ]
		}
	]
}
```

## Optional security settings

All of these are optional. Leaving one unset keeps the previous behaviour.

| Key | Default | Purpose |
| --- | --- | --- |
| `trustedproxies` | unset | List of CIDRs allowed to send a PROXY protocol header. |
| `destipallow` | unset | List of CIDRs a destination must resolve into. Unset allows any destination. |
| `maxconnections` | `0` | Cap on concurrent connections. `0` means unlimited. |
| `debug` | `false` | Enables per-attempt rule matching output. |
| `localAddress` / `localAddress6` | unset | Source address to bind when dialing upstreams. |

### trustedproxies

When sshmuxd sits behind a load balancer that speaks the PROXY protocol, set
this to the balancer's addresses:

```json
"trustedproxies": [ "10.0.0.0/8", "192.168.1.5/32" ]
```

A PROXY header is honoured only from a listed peer. Headers from anyone else
are ignored and the real peer address is used, so direct clients keep working.

If this is left unset, a PROXY header is accepted from **any** peer. That lets
any client choose the source address used for `src` rule matching and recorded
in the audit log. A warning is logged at startup when that is the case.

# Security notes

- The config file contains the SSH host private key. Keep it mode `0600`.
  sshmuxd warns at startup if it is group- or world-accessible.
- The working directory is searched for `sshmuxd.json`/`.yml` before
  `$HOME/.sshmuxd` and `/etc/sshmuxd`. Anyone who can write to the directory
  the daemon is started from controls the host key, CA list, users and rules.
  Prefer `--config /etc/sshmuxd/sshmuxd.json`.
- Binding port 22 needs privileges, and sshmuxd does not drop them. Run it
  under systemd with `User=` and `AmbientCapabilities=CAP_NET_BIND_SERVICE`
  rather than as root.
- `SIGTERM` and `SIGINT` shut down gracefully. `SIGUSR1` dumps active sessions.

## Known limitations

- A CA-signed certificate with no `ValidPrincipals` authenticates as whatever
  username the client asks for. Always issue certificates with explicit
  principals.
- There is no certificate revocation list. Removing a CA from `sshca` is the
  only way to revoke, and it revokes every certificate that CA issued.
- `sshCertRequired` checks only that a valid certificate was presented, not
  which principal it belongs to. Any certificate from a configured CA reaches
  every `sshCertRequired` host.
- Upstream host keys are not verified on the interactive session-forward path,
  so that hop can be intercepted. This does not affect `ProxyJump` / `ssh -W`,
  where the client verifies the upstream host key itself. Prefer `ProxyJump`,
  which `onlyproxyjump: true` enforces.
- An empty `rules` list disables rule checking entirely, and an unset
  `destipallow` allows every destination.
- Any host with `noAuth: true` enables anonymous access for the whole daemon:
  an unrecognised public key is accepted and the session is named
  `unknown user`. Rules with no `users` field also match that session.
- Host name patterns use `*` globbing, which crosses `.` and `:`. A pattern
  like `*example.com:22` also matches `evilexample.com:22`.

# More info
For more details about this project, see the underlying library: http://github.com/kennylevinsen/sshmux
