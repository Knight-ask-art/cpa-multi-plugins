package main

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func pluginapiCandidate(status string, md map[string]any) pluginapi.SchedulerAuthCandidate {
	return pluginapi.SchedulerAuthCandidate{ID: "x", Provider: providerName, Status: status, Metadata: md}
}

func TestPickCreditsAuth_HighestBalanceWins(t *testing.T) {
	old := getActiveAuthID()
	defer setActiveAuthID(old)
	setActiveAuthID("b")
	got := pickCreditsAuth([]activeAuthCandidate{
		{ID: "a", Remain: 294},
		{ID: "b", Remain: 1094},
		{ID: "c", Remain: 500},
	})
	if got != "b" {
		t.Fatalf("pick = %q, want b (highest remaining)", got)
	}
}

func TestPickCreditsAuth_UnknownAndExhaustedRankLast(t *testing.T) {
	old := getActiveAuthID()
	defer setActiveAuthID(old)
	setActiveAuthID("x")
	got := pickCreditsAuth([]activeAuthCandidate{
		{ID: "x", Remain: -1},
		{ID: "y", Remain: 12},
		{ID: "z", Remain: 0, Exhausted: true},
	})
	if got != "y" {
		t.Fatalf("pick = %q, want y (known positive beats unknown and exhausted)", got)
	}
	// Unknown beats exhausted: a stale-but-usable pool is better than a drained one.
	got = pickCreditsAuth([]activeAuthCandidate{
		{ID: "x", Remain: -1},
		{ID: "z", Remain: 0, Exhausted: true},
	})
	if got != "x" {
		t.Fatalf("pick = %q, want x (unknown beats exhausted)", got)
	}
}

func TestPickCreditsAuth_TieKeepsCurrentSelection(t *testing.T) {
	old := getActiveAuthID()
	defer setActiveAuthID(old)
	setActiveAuthID("second")
	got := pickCreditsAuth([]activeAuthCandidate{
		{ID: "first", Remain: 100},
		{ID: "second", Remain: 100},
	})
	if got != "second" {
		t.Fatalf("pick = %q, want second (tie keeps current)", got)
	}
}

func TestPickCreditsAuth_SkipsDisabled(t *testing.T) {
	old := getActiveAuthID()
	defer setActiveAuthID(old)
	setActiveAuthID("a")
	got := pickCreditsAuth([]activeAuthCandidate{
		{ID: "a", Remain: 10},
		{ID: "b", Remain: 900, Disabled: true},
	})
	if got != "a" {
		t.Fatalf("pick = %q, want a (disabled candidate must not win on credits)", got)
	}
}

func TestPickCreditsAuth_EmptyAndAllDisabled(t *testing.T) {
	old := getActiveAuthID()
	defer setActiveAuthID(old)
	setActiveAuthID("")
	if got := pickCreditsAuth(nil); got != "" {
		t.Fatalf("empty candidates → %q, want \"\"", got)
	}
	setActiveAuthID("b")
	if got := pickCreditsAuth([]activeAuthCandidate{
		{ID: "a", Disabled: true},
		{ID: "b", Disabled: true},
	}); got != "b" {
		t.Fatalf("all disabled → %q, want current selection b", got)
	}
}

func TestPickCreditsAuth_StickyWhilePositive(t *testing.T) {
	old := getActiveAuthID()
	defer setActiveAuthID(old)
	// The selected account still has credits → keep it even if another pool
	// is larger (no bouncing between two healthy accounts).
	setActiveAuthID("small")
	got := pickCreditsAuth([]activeAuthCandidate{
		{ID: "small", Remain: 30},
		{ID: "big", Remain: 900},
	})
	if got != "small" {
		t.Fatalf("pick = %q, want small (sticky while positive)", got)
	}
	// Selected account drained → move to the fullest pool.
	setActiveAuthID("drained")
	got = pickCreditsAuth([]activeAuthCandidate{
		{ID: "drained", Remain: 0},
		{ID: "small", Remain: 30},
		{ID: "big", Remain: 900},
	})
	if got != "big" {
		t.Fatalf("pick = %q, want big after the selection drained", got)
	}
}

func TestPickCreditsAuth_ColdStartFollowsExhaustionFlag(t *testing.T) {
	old := getActiveAuthID()
	defer setActiveAuthID(old)
	// Cold start: no credits fetched yet, and the panel has already selected a
	// FREE account that the host marks exhausted (0/0 pool). The paid account
	// must win on the exhaustion flag alone, not on a missing balance.
	setActiveAuthID("intl-free")
	got := pickCreditsAuth([]activeAuthCandidate{
		{ID: "intl-free", Remain: -1, Exhausted: true},
		{ID: "cn-paid", Remain: -1},
	})
	if got != "cn-paid" {
		t.Fatalf("pick = %q, want cn-paid (exhausted flag beats unknown)", got)
	}
}

func TestCandidateExhausted(t *testing.T) {
	if !candidateExhausted(pluginapiCandidate("exhausted", nil)) {
		t.Fatal("status exhausted not detected")
	}
	if !candidateExhausted(pluginapiCandidate("", map[string]any{"exhausted": true})) {
		t.Fatal("metadata exhausted not detected")
	}
	if candidateExhausted(pluginapiCandidate("active", nil)) {
		t.Fatal("active account reported exhausted")
	}
}
