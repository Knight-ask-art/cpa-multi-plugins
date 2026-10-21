// active_auth.go tracks the panel-selected QoderWork account used for routing.
//
// Region is always CN for QoderWork —
// no per-request JWT iss decode. Default: first available candidate. When the
// active account is exhausted/disabled/missing, randomly switch to another
// non-exhausted candidate and remember the choice.
package main

import (
	"strings"
	"sync"
)

var (
	activeAuthID string
	activeAuthMu sync.RWMutex
)

func getActiveAuthID() string {
	activeAuthMu.RLock()
	defer activeAuthMu.RUnlock()
	return strings.TrimSpace(activeAuthID)
}

func setActiveAuthID(id string) {
	id = strings.TrimSpace(id)
	activeAuthMu.Lock()
	activeAuthID = id
	activeAuthMu.Unlock()
}

// clearActiveAuthIfMatch clears the selection when the given auth is removed.
func clearActiveAuthIfMatch(id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	activeAuthMu.Lock()
	if activeAuthID == id {
		activeAuthID = ""
	}
	activeAuthMu.Unlock()
}

// activeAuthCandidate is a thin view used by pickActiveAuth.
type activeAuthCandidate struct {
	ID        string
	Disabled  bool
	Exhausted bool
	// Remain is the cached remaining credits; -1 (or any negative) = unknown.
	// Only the credits-mode ranker reads it.
	Remain int64
}

// pickActiveAuth chooses which qoderwork auth to use from host candidates.
// The panel selection is sticky: it stays on the current account unless that
// account is no longer in the candidate list (disabled/deleted by host) or
// is marked exhausted in cache. When switching, it picks the first
// non-exhausted candidate and updates activeAuthID so the panel reflects
// the change on next dashboard load.
func pickActiveAuth(candidates []activeAuthCandidate) string {
	if len(candidates) == 0 {
		return ""
	}
	byID := make(map[string]activeAuthCandidate, len(candidates))
	for _, c := range candidates {
		byID[c.ID] = c
	}

	cur := getActiveAuthID()
	// Keep current selection if it's still a live candidate AND not disabled/exhausted.
	if cur != "" {
		if c, ok := byID[cur]; ok && !c.Disabled && !c.Exhausted {
			return cur
		}
	}

	// Selection is gone, disabled or exhausted — pick next non-disabled non-exhausted, else first.
	var next string
	for _, c := range candidates {
		if !c.Disabled && !c.Exhausted {
			next = c.ID
			break
		}
	}
	if next == "" {
		// All exhausted or disabled — keep current if still alive, else first candidate.
		if cur != "" {
			if _, ok := byID[cur]; ok {
				return cur
			}
		}
		next = candidates[0].ID
	}
	if next != "" && next != cur {
		setActiveAuthID(next)
	}
	return next
}

// pickCreditsAuth chooses the account for scheduler_mode=credits. The current
// selection stays as long as it holds a positive balance (sticky, so a session
// stays on one account); otherwise the candidate with the most remaining
// credits wins, draining the largest pool first before moving on. Unknown
// balances rank below any candidate with a positive balance and above
// exhausted ones; ties keep the current selection, then the host's candidate
// order. Disabled candidates are never picked unless nothing else is left.
func pickCreditsAuth(candidates []activeAuthCandidate) string {
	if len(candidates) == 0 {
		return ""
	}
	cur := getActiveAuthID()
	// v0.8.65: sticky at the top. The panel selection holds traffic as long as
	// it still has a positive balance — so credits mode never "bounces" between
	// two accounts whose pools are close (which, under session affinity, would
	// spread one conversation across accounts). Switch only when the current
	// account is gone, disabled, exhausted or its balance is unknown/drained.
	for _, c := range candidates {
		if c.ID == cur && !c.Disabled && !c.Exhausted && c.Remain > 0 {
			return cur
		}
	}
	best := -1
	for i, c := range candidates {
		if c.Disabled {
			continue
		}
		rankCur := creditsRank(c)
		if best < 0 {
			best = i
			continue
		}
		b := candidates[best]
		switch {
		case rankCur > creditsRank(b):
			best = i
		case rankCur == creditsRank(b):
			// Tie: keep the current selection, else the earlier candidate.
			if c.ID == cur && b.ID != cur {
				best = i
			}
		}
	}
	if best < 0 {
		// Everything is disabled — keep the current selection if it is live.
		for _, c := range candidates {
			if c.ID == cur {
				return cur
			}
		}
		return candidates[0].ID
	}
	return candidates[best].ID
}

// creditsRank maps a candidate to a sortable rank: real remaining credits when
// known, -1 for a never-fetched balance (unknown) and -2 for exhausted.
// "Unknown" loses to any known positive pool but still beats a drained one —
// except when the host itself says the account is exhausted (panel flag or an
// empty 0/0 pool): that account is strictly worse than an unknown one, which
// must not displace it.
func creditsRank(c activeAuthCandidate) int64 {
	if c.Exhausted {
		return -2
	}
	if c.Remain < 0 {
		return -1
	}
	return c.Remain
}

// ensureDefaultActiveAuth sets the panel-selected account.
// Called from buildDashboardEx on every /accounts and /refresh request.
//
// Rules (single source of truth, same as pickActiveAuth):
//  1. If current selection is live AND not exhausted → keep it.
//  2. If current selection is exhausted → switch to first non-exhausted.
//  3. If current selection is gone (disabled/deleted) → switch to first available.
//  4. If all exhausted → keep current if alive, else first.
//
// This ensures the panel's selected card always matches what scheduler.pick
// actually routes to. No silent drift.
func ensureDefaultActiveAuth(accounts []wbAccount) string {
	cur := getActiveAuthID()
	live := make(map[string]wbAccount, len(accounts))
	for _, a := range accounts {
		live[a.AuthID] = a
	}

	// Rule 1: current selection is live AND not exhausted → keep.
	if cur != "" {
		if a, ok := live[cur]; ok && !a.Disabled && !a.Exhausted {
			return cur
		}
	}

	// Rule 2 & 3: selection is exhausted or gone → find next.
	var firstAny, firstOK, firstReady string
	for _, a := range accounts {
		if firstAny == "" {
			firstAny = a.AuthID
		}
		if a.Disabled {
			continue
		}
		if firstOK == "" {
			firstOK = a.AuthID
		}
		if !a.Exhausted && firstReady == "" {
			firstReady = a.AuthID
		}
	}

	// Prefer first non-exhausted non-disabled.
	next := firstReady
	if next == "" {
		// Rule 4: all exhausted — keep current if still alive (not disabled).
		if cur != "" {
			if a, ok := live[cur]; ok && !a.Disabled {
				return cur
			}
		}
		next = firstOK
	}
	if next == "" {
		next = firstAny
	}
	if next != "" && next != cur {
		setActiveAuthID(next)
	}
	return next
}
