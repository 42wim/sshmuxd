package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/42wim/sshmux"
	"github.com/ryanuber/go-glob"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

type Rule struct {
	Name                     string         `json:"name"`
	Users                    []string       `json:"users"`
	Src                      []string       `json:"src"`
	Dst                      []string       `json:"dst"`
	Hosts                    []Host         `json:"hosts"`
	SourceParsed             []netip.Prefix `json:"-"`
	SourceNomatchParsed      []netip.Prefix `json:"-"`
	DestinationParsed        []netip.Prefix `json:"-"`
	DestinationNomatchParsed []netip.Prefix `json:"-"`
}

type Rules []Rule

func createSelectedWithRules(rules *Rules) func(*sshmux.Session, string) error {
	return func(session *sshmux.Session, remote string) error {
		var username string

		if session.User != nil {
			username = session.User.Name
		} else {
			username = "unknown user"
		}

		clientip, _, err := net.SplitHostPort(session.Conn.RemoteAddr().String())
		if err != nil {
			log.Printf("%s: failed parsing %s: %s", session.Conn.RemoteAddr(), session.Conn.RemoteAddr(), err)
			return errors.New("access denied")
		}

		if len(*rules) > 0 && !rules.IsAllowed(username, clientip, remote) {
			log.Printf("%s: %s tried connecting to %s: not allowed", session.Conn.RemoteAddr(), username, remote)
			return errors.New("access denied")
		}

		if !destinationAllowed(remote) {
			log.Printf("%s: %s tried connecting to %s: destination IP not allowed", session.Conn.RemoteAddr(), username, remote)
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
}

func parseRules() (Rules, error) {
	var rules Rules

	err := viper.UnmarshalKey("rules", &rules)
	if err != nil {
		return nil, err
	}

	for i := range rules {
		rule := &rules[i]

		for _, s := range rule.Src {
			if strings.HasPrefix(s, "!") {
				prefix, err := netip.ParsePrefix(s[1:])
				if err != nil {
					return nil, fmt.Errorf("error parsing source prefix %s: %s", s, err)
				}

				rule.SourceNomatchParsed = append(rule.SourceNomatchParsed, prefix)

				continue
			}

			prefix, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("error parsing source prefix %s: %s", s, err)
			}

			rule.SourceParsed = append(rule.SourceParsed, prefix)
		}

		for _, d := range rule.Dst {
			if strings.HasPrefix(d, "!") {
				prefix, err := netip.ParsePrefix(d[1:])
				if err != nil {
					return nil, fmt.Errorf("error parsing destination prefix %s: %s", d, err)
				}

				rule.DestinationNomatchParsed = append(rule.DestinationNomatchParsed, prefix)

				continue
			}

			prefix, err := netip.ParsePrefix(d)
			if err != nil {
				return nil, fmt.Errorf("error parsing destination prefix %s: %s", d, err)
			}

			rule.DestinationParsed = append(rule.DestinationParsed, prefix)
		}

		for _, h := range rule.Hosts {
			if h.NoAuth && h.SSHCertRequired {
				return nil, fmt.Errorf("host %s: noAuth and sshCertRequired cannot be both true", h.Address)
			}
		}
	}

	return rules, nil
}

// findUserRules returns a list of rules that match the username
func (r *Rules) findUserRules(username string) Rules {
	var rules Rules

	for _, rule := range *r {
		if slices.Contains(rule.Users, username) || len(rule.Users) == 0 {
			rules = append(rules, rule)
		}
	}

	return rules
}

func (r *Rules) findSourceIPRules(sourceIP string) Rules {
	var rules Rules

	for _, rule := range *r {
		if len(rule.SourceParsed) == 0 {
			rules = append(rules, rule)
		}

		for _, s := range rule.SourceParsed {
			if s.Contains(netip.MustParseAddr(sourceIP)) {
				rules = append(rules, rule)
			}
		}
	}

	return rules
}

func (r *Rules) findDestinationHostRules(destHost string) Rules {
	var rules Rules

	for _, rule := range *r {
		for _, h := range rule.Hosts {
			if glob.Glob(h.Address, destHost) || h.Address == destHost {
				rules = append(rules, rule)
			}
		}
	}

	return rules
}

func (r *Rules) findDestinationNomatchIPRules(destIP string) Rules {
	var rules Rules

	for _, rule := range *r {
		for _, d := range rule.DestinationNomatchParsed {
			if d.Contains(netip.MustParseAddr(destIP)) {
				rules = append(rules, rule)
			}
		}
	}

	return rules
}

func (r *Rules) findDestinationIPRules(destIP string) Rules {
	var rules Rules

	for _, rule := range *r {
		for _, d := range rule.DestinationParsed {
			if d.Contains(netip.MustParseAddr(destIP)) {
				rules = append(rules, rule)
			}
		}
	}

	return rules
}

func (r *Rules) IsAllowed(username, sourceIP, destHost string) bool {
	addresses, err := remoteToIPAddresses(destHost)
	if err != nil {
		log.Printf("dns lookup failed: %s", err)
		return false
	}

	count := 0

	for _, a := range addresses {
		if r.isAllowed(username, sourceIP, a, destHost) {
			count++
		}
	}

	return count == len(addresses)
}

func (r *Rules) isAllowed(username, sourceIP, destIP, destHost string) bool {
	userRules := r.findUserRules(username)

	if len(userRules) == 0 {
		log.Printf("%s: no user rules found for %s", sourceIP, username)
		return false
	}

	destHostRules := userRules.findDestinationHostRules(destHost)

	if len(destHostRules) == 0 {
		log.Printf("%s: no destHost rules found for %s %s", sourceIP, destHost, username)
		return false
	}

	sourceRules := destHostRules.findSourceIPRules(sourceIP)

	if len(sourceRules) == 0 {
		log.Printf("%s: no source rules found for %s", sourceIP, sourceIP)
		return false
	}

	destIPNomatchRules := sourceRules.findDestinationNomatchIPRules(destIP)

	if len(destIPNomatchRules) > 0 {
		log.Printf("%s: destination IP %s is not allowed", sourceIP, destIP)
		return false
	}

	destIPRules := sourceRules.findDestinationIPRules(destIP)

	if len(destIPRules) == 0 {
		log.Printf("%s: no destip rules found for %s", sourceIP, destIP)
		return false
	}

	return len(destIPRules) != 0
}
