# sshmux [![GoDoc](https://godoc.org/github.com/42wim/sshmux?status.svg)](http://godoc.org/github.com/42wim/sshmux)  [![Go Report Card](https://goreportcard.com/badge/kennylevinsen/sshmux)](https://goreportcard.com/report/42wim/sshmux)

Forked from https://github.com/kennylevinsen/sshmux
- adds support for globbing of hostnames
- supports ssh certificates
- add an OnlyProxyJump option

SSH multiplexing library, allowing you to write "jump host" style proxies.

Supports both transparent `-oProxyJump=sshmux-server` style jumps, as well as interactive session forwarding (with some limitations).


# But i just want to run it...

Look at sshmuxd instead, then: https://github.com/42wim/sshmuxd.
