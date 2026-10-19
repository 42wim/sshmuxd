package main

import (
	"testing"
	"time"

	"github.com/spf13/viper"
)

func mustRules(t *testing.T, raw []map[string]any) Rules {
	t.Helper()

	viper.Reset()
	viper.Set("rules", raw)

	rules, err := parseRules()
	if err != nil {
		t.Fatalf("parseRules: %v", err)
	}

	return rules
}

func TestParseRulesRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		rule map[string]any
	}{
		{"bad duration", map[string]any{"name": "r", "duration": "5 fortnights"}},
		{"bad source prefix", map[string]any{"name": "r", "src": []string{"10.0.0.0/64"}}},
		{"bad negated source prefix", map[string]any{"name": "r", "src": []string{"!garbage"}}},
		{"bad destination prefix", map[string]any{"name": "r", "dst": []string{"nope"}}},
		{
			"noAuth and sshCertRequired together",
			map[string]any{"name": "r", "hosts": []map[string]any{
				{"address": "a:22", "noAuth": true, "sshCertRequired": true},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			viper.Set("rules", []map[string]any{tt.rule})

			if _, err := parseRules(); err == nil {
				t.Fatal("invalid rule was accepted")
			}
		})
	}
}

func TestRulesIsAllowed(t *testing.T) {
	primeDNS(t, "internal.example.com", "10.1.2.3")
	primeDNS(t, "external.example.com", "192.0.2.9")

	rules := mustRules(t, []map[string]any{{
		"name":  "alice-internal",
		"users": []string{"alice"},
		"src":   []string{"10.0.0.0/8"},
		"dst":   []string{"10.0.0.0/8"},
		"hosts": []map[string]any{{"address": "*.example.com:22"}},
	}})

	tests := []struct {
		name     string
		username string
		sourceIP string
		destHost string
		want     bool
	}{
		{"permitted user, source and destination", "alice", "10.0.0.5", "internal.example.com:22", true},
		{"wrong user", "mallory", "10.0.0.5", "internal.example.com:22", false},
		{"source outside the permitted prefix", "alice", "192.0.2.1", "internal.example.com:22", false},
		{"destination outside the permitted prefix", "alice", "10.0.0.5", "external.example.com:22", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rules.IsAllowed(tt.username, tt.sourceIP, tt.destHost); got != tt.want {
				t.Errorf("IsAllowed(%q, %q, %q) = %t, want %t",
					tt.username, tt.sourceIP, tt.destHost, got, tt.want)
			}
		})
	}

	t.Run("unparseable source address denies", func(t *testing.T) {
		if rules.IsAllowed("alice", "not-an-ip", "internal.example.com:22") {
			t.Error("an unparseable source address was allowed")
		}
	})
}

// An empty DNS result made count == len(addresses) evaluate to 0 == 0 and allow.
func TestIsAllowedDeniesWhenDNSReturnsNothing(t *testing.T) {
	primeDNS(t, "empty.example.com")

	rules := mustRules(t, []map[string]any{{
		"name":  "any",
		"hosts": []map[string]any{{"address": "*.example.com:22"}},
		"dst":   []string{"0.0.0.0/0"},
	}})

	if rules.IsAllowed("alice", "10.0.0.5", "empty.example.com:22") {
		t.Error("destination with no resolved addresses was allowed")
	}
}

func TestIsAllowedRequiresEveryResolvedAddress(t *testing.T) {
	primeDNS(t, "split.example.com", "10.1.2.3", "192.0.2.9")

	rules := mustRules(t, []map[string]any{{
		"name":  "internal-only",
		"hosts": []map[string]any{{"address": "*.example.com:22"}},
		"dst":   []string{"10.0.0.0/8"},
	}})

	if rules.IsAllowed("alice", "10.0.0.5", "split.example.com:22") {
		t.Error("a host resolving partly outside the allowed prefix was allowed")
	}
}

func TestNegatedDestinationPrefixDenies(t *testing.T) {
	primeDNS(t, "blocked.example.com", "10.9.9.9")
	primeDNS(t, "ok.example.com", "10.1.1.1")

	rules := mustRules(t, []map[string]any{{
		"name":  "internal-except-one",
		"hosts": []map[string]any{{"address": "*.example.com:22"}},
		"dst":   []string{"10.0.0.0/8", "!10.9.0.0/16"},
	}})

	if rules.IsAllowed("alice", "10.0.0.5", "blocked.example.com:22") {
		t.Error("a negated destination prefix did not deny")
	}

	if !rules.IsAllowed("alice", "10.0.0.5", "ok.example.com:22") {
		t.Error("a permitted destination was denied")
	}
}

// getDuration used to look at addresses[0] only, so the lifetime could come
// from a different rule than the one that authorized the connection.
func TestGetDurationUsesShortestAcrossAllAddresses(t *testing.T) {
	primeDNS(t, "multi.example.com", "10.1.1.1", "192.0.2.9")

	rules := mustRules(t, []map[string]any{
		{
			"name":     "long",
			"hosts":    []map[string]any{{"address": "*.example.com:22"}},
			"dst":      []string{"10.0.0.0/8"},
			"duration": "1h",
		},
		{
			"name":     "short",
			"hosts":    []map[string]any{{"address": "*.example.com:22"}},
			"dst":      []string{"192.0.2.0/24"},
			"duration": "5m",
		},
	})

	got := rules.getDuration("alice", "10.0.0.5", "multi.example.com:22")
	if got != 5*time.Minute {
		t.Errorf("getDuration = %s, want 5m", got)
	}
}

func TestGetDurationUnmatchedIsUnlimited(t *testing.T) {
	primeDNS(t, "nomatch.example.com", "203.0.113.1")

	rules := mustRules(t, []map[string]any{{
		"name":     "internal",
		"hosts":    []map[string]any{{"address": "*.example.com:22"}},
		"dst":      []string{"10.0.0.0/8"},
		"duration": "1h",
	}})

	// Unchanged, fail-open by design: no matching rule means no lifetime cap.
	if got := rules.getDuration("alice", "10.0.0.5", "nomatch.example.com:22"); got != 0 {
		t.Errorf("getDuration = %s, want 0", got)
	}
}

// A rule with no "users" applies to everyone, including unauthenticated
// sessions, which are named "unknown user". Unchanged behaviour, pinned here.
func TestRuleWithoutUsersMatchesAnonymousSession(t *testing.T) {
	primeDNS(t, "open.example.com", "10.1.1.1")

	rules := mustRules(t, []map[string]any{{
		"name":  "everyone",
		"hosts": []map[string]any{{"address": "*.example.com:22"}},
		"dst":   []string{"10.0.0.0/8"},
	}})

	if !rules.IsAllowed("unknown user", "10.0.0.5", "open.example.com:22") {
		t.Error("a rule with no users did not match an anonymous session")
	}
}

func TestFindSourceIPRulesDoesNotDuplicate(t *testing.T) {
	rules := mustRules(t, []map[string]any{{
		"name":  "multi-prefix",
		"src":   []string{"10.0.0.0/8", "10.1.0.0/16"},
		"hosts": []map[string]any{{"address": "a.example.com:22"}},
	}})

	// 10.1.0.5 falls inside both prefixes.
	got := rules.findSourceIPRules(mustAddr(t, "10.1.0.5"))
	if len(got) != 1 {
		t.Errorf("got %d rules, want 1 (overlapping prefixes must not duplicate)", len(got))
	}
}
