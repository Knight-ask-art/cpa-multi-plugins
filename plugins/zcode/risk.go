// risk.go implements the account-scoped response to zcode's risk-control
// rejection (biz code 3012, "method not allowed").
//
// 3012 is not shaped like the other upstream failures policy.go classifies. It
// is the gateway's content/identity gate: a request whose body does not look
// like the official ZCode client — system blocks missing (system_prompt.go) or
// an identity the inspection layer distrusts — is refused BEFORE any model is
// chosen. Two consequences follow, and both cut against the model-scoped
// throttling in cooldown.go:
//
//  1. Retrying a different model on the same credential does not help, because
//     the rejection happened upstream of model selection. Cooling only the
//     (auth, model) pair would let the executor walk the catalog and book a
//     fresh failure on every model in turn — the opposite of backing off.
//  2. Repeating it is what turns a soft challenge into a hard block. The ladder
//     below therefore escalates per ACCOUNT: the first strike is a short pause
//     in case it was one malformed request, the third says stop for the day.
//
// Routing surfaces this the same way per-model cooldowns do, by narrowing the
// credential's catalog (models.go): handleModelForAuth returning no models is
// the host's own signal that a credential has nothing to serve, so a pause
// takes effect without the plugin reaching for the host's `disabled` flag.
// That flag belongs to the operator; a plugin that flips it makes the panel's
// enable/disable toggle ambiguous and takes an action the user cannot attribute
// to anything they did.
//
// State is process-local, like cooldown.go: a restart clears it, which is the
// right failure direction for a soft signal we can only infer from a business
// code.
package main

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// riskControlCode is the gateway's content/identity rejection. Kept as a
	// string to match extractBizErrorCode's canonical digits.
	riskControlCode = "3012"

	// riskStrikeWindow bounds how far back strikes count. A challenge this
	// morning says nothing about an account this evening, and a permanent
	// counter would eventually quarantine every long-lived credential.
	riskStrikeWindow = 24 * time.Hour

	// riskFirstCooldown is deliberately short: the most common cause is one
	// request shape the inspection layer disliked, and a half-hour pause costs
	// the operator little while a wrong 24-hour one costs them a day.
	riskFirstCooldown = 30 * time.Minute

	// riskThirdCooldown is the "stop for today" rung. Three challenges inside
	// the window is a pattern, not an accident.
	riskThirdCooldown = 24 * time.Hour

	// riskQuarantineAt is where the ladder stops being a cooldown and becomes a
	// holding state with no clock. A credential that trips the gate five times
	// in a day is usually burnt or needs a fresh login, and no amount of waiting
	// fixes either — so this one is lifted only by an operator, and the panel
	// says so.
	riskQuarantineAt = 5

	// riskMaxAccounts bounds the table against a hostile or buggy upstream
	// minting fresh auth IDs.
	riskMaxAccounts = 4096
)

// riskEntry is one account's risk-control history and its current consequence.
type riskEntry struct {
	// Strikes are the in-window challenge timestamps.
	Strikes []time.Time
	// Until is when a timed pause ends. Zero when not paused.
	Until time.Time
	// Quarantined is the terminal rung: no clock, operator-lifted only.
	Quarantined bool
	// LastCode/LastModel/LastAt describe the most recent strike, for the panel.
	LastCode  string
	LastModel string
	LastAt    time.Time
}

var (
	riskMu    sync.Mutex
	riskTable = map[string]*riskEntry{}
	// riskNowFn is the injectable clock (same pattern as cooldownNowFn).
	riskNowFn = time.Now
)

// recordRiskControl books one strike for an account, prunes strikes that have
// aged out of the window, and reapplies the ladder. It returns the resulting
// state so the caller can log or surface it.
//
// model is recorded for display only — a 3012 is not attributable to a model,
// and the escalation deliberately ignores which model was asked for.
func recordRiskControl(authID, model, code string) riskEntry {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return riskEntry{}
	}
	code = strings.TrimSpace(code)
	if code == "" {
		code = riskControlCode
	}
	now := riskNowFn()

	riskMu.Lock()
	defer riskMu.Unlock()
	riskSweepLocked(now)

	e := riskTable[authID]
	if e == nil {
		if len(riskTable) >= riskMaxAccounts {
			// Drop the least recently struck account; it is the one closest to
			// ageing out of the window anyway.
			var oldestID string
			var oldestAt time.Time
			first := true
			for id, cand := range riskTable {
				if first || cand.LastAt.Before(oldestAt) {
					oldestID, oldestAt, first = id, cand.LastAt, false
				}
			}
			delete(riskTable, oldestID)
		}
		e = &riskEntry{}
		riskTable[authID] = e
	}

	e.Strikes = append(pruneRiskStrikes(e.Strikes, now), now)
	e.LastCode, e.LastModel, e.LastAt = code, normalizeCooldownModel(model), now

	switch {
	case len(e.Strikes) >= riskQuarantineAt:
		// Terminal: no expiry. Leaving any earlier Until in place would make
		// the state look self-healing in the panel.
		e.Quarantined = true
		e.Until = time.Time{}
	case len(e.Strikes) >= 3:
		e.Quarantined = false
		e.Until = now.Add(riskThirdCooldown)
	default:
		e.Quarantined = false
		e.Until = now.Add(riskFirstCooldown)
	}
	return *e
}

// pruneRiskStrikes drops timestamps older than the window.
func pruneRiskStrikes(strikes []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-riskStrikeWindow)
	out := strikes[:0:0]
	for _, ts := range strikes {
		if ts.After(cutoff) {
			out = append(out, ts)
		}
	}
	return out
}

// riskSweepLocked forgets accounts whose history has fully aged out and whose
// pause has lapsed, so the table does not grow without bound. Caller holds
// riskMu.
func riskSweepLocked(now time.Time) {
	for id, e := range riskTable {
		if e.Quarantined {
			continue
		}
		if len(pruneRiskStrikes(e.Strikes, now)) == 0 && !now.Before(e.Until) {
			delete(riskTable, id)
		}
	}
}

// riskStateFor returns a copy of an account's state. The zero riskEntry means
// no history.
func riskStateFor(authID string) riskEntry {
	riskMu.Lock()
	defer riskMu.Unlock()
	e := riskTable[strings.TrimSpace(authID)]
	if e == nil {
		return riskEntry{}
	}
	now := riskNowFn()
	out := *e
	out.Strikes = pruneRiskStrikes(e.Strikes, now)
	return out
}

// riskBlocksAuth reports whether the account must not be routed to right now:
// quarantined, or inside a timed pause.
func riskBlocksAuth(authID string) bool {
	riskMu.Lock()
	defer riskMu.Unlock()
	e := riskTable[strings.TrimSpace(authID)]
	if e == nil {
		return false
	}
	if e.Quarantined {
		return true
	}
	return riskNowFn().Before(e.Until)
}

// clearRisk drops an account's history and pause, lifting a quarantine. Returns
// the number of accounts affected so an empty selector can clear the lot, the
// way clearModelCooldown does.
func clearRisk(authID string) int {
	authID = strings.TrimSpace(authID)
	riskMu.Lock()
	defer riskMu.Unlock()
	if authID != "" {
		if _, ok := riskTable[authID]; !ok {
			return 0
		}
		delete(riskTable, authID)
		return 1
	}
	n := len(riskTable)
	riskTable = map[string]*riskEntry{}
	return n
}

// riskSummary is the panel-facing shape of one account's risk state.
type riskSummary struct {
	Strikes     int    `json:"strikes"`
	Paused      bool   `json:"paused"`
	Quarantined bool   `json:"quarantined"`
	Until       string `json:"until,omitempty"`
	Seconds     int64  `json:"seconds,omitempty"`
	LastCode    string `json:"last_code,omitempty"`
	LastModel   string `json:"last_model,omitempty"`
	LastAt      string `json:"last_at,omitempty"`
}

// riskSummaryFor renders an account's risk state for the dashboard, or nil when
// there is nothing to show — an absent field keeps the card clean for the
// overwhelmingly common healthy account.
func riskSummaryFor(authID string) *riskSummary {
	riskMu.Lock()
	e := riskTable[strings.TrimSpace(authID)]
	if e == nil {
		riskMu.Unlock()
		return nil
	}
	now := riskNowFn()
	cur := *e
	cur.Strikes = pruneRiskStrikes(e.Strikes, now)
	riskMu.Unlock()

	if len(cur.Strikes) == 0 && !cur.Quarantined && !now.Before(cur.Until) {
		return nil
	}
	out := &riskSummary{
		Strikes:     len(cur.Strikes),
		Paused:      cur.Quarantined || now.Before(cur.Until),
		Quarantined: cur.Quarantined,
		LastCode:    cur.LastCode,
		LastModel:   cur.LastModel,
	}
	if !cur.Until.IsZero() && now.Before(cur.Until) {
		out.Until = cur.Until.Format("2006-01-02 15:04:05")
		out.Seconds = int64(cur.Until.Sub(now).Seconds())
	}
	if !cur.LastAt.IsZero() {
		out.LastAt = cur.LastAt.Format("2006-01-02 15:04:05")
	}
	return out
}

// riskSummaryForAuth looks an account's risk state up under both identifiers
// the plugin uses for one credential: the host's record ID (what the dashboard
// lists, and what cooldownSnapshotFor is keyed by) and cooldownAuthIDFor (what
// the executor reports as AuthID, and therefore what recordRiskControl is keyed
// by). They agree for credentials this plugin created, but the host derives its
// own ID from the auth file path when it can, so a lookup that assumed they
// always match would silently report "no risk state" for a paused account.
func riskSummaryForAuth(hostID string, sa *storedAuth) *riskSummary {
	if s := riskSummaryFor(hostID); s != nil {
		return s
	}
	return riskSummaryFor(cooldownAuthIDFor(sa))
}

// clearRiskForAuth drops risk state under both identifiers, so an operator's
// "clear" cannot miss the key the routing filter is reading.
func clearRiskForAuth(hostID string, sa *storedAuth) int {
	n := clearRisk(hostID)
	if other := cooldownAuthIDFor(sa); other != hostID {
		n += clearRisk(other)
	}
	return n
}

// riskSnapshotAll renders every account with risk state, most severe first so
// a quarantined account is the first thing an operator sees.
func riskSnapshotAll() []map[string]any {
	riskMu.Lock()
	ids := make([]string, 0, len(riskTable))
	for id := range riskTable {
		ids = append(ids, id)
	}
	riskMu.Unlock()
	sort.Strings(ids)

	out := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		s := riskSummaryFor(id)
		if s == nil {
			continue
		}
		row := map[string]any{
			"auth_id":     id,
			"strikes":     s.Strikes,
			"paused":      s.Paused,
			"quarantined": s.Quarantined,
		}
		if s.Until != "" {
			row["until"] = s.Until
			row["seconds"] = s.Seconds
		}
		if s.LastCode != "" {
			row["last_code"] = s.LastCode
		}
		if s.LastModel != "" {
			row["last_model"] = s.LastModel
		}
		if s.LastAt != "" {
			row["last_at"] = s.LastAt
		}
		out = append(out, row)
	}
	// Severe first: quarantined, then paused, then the rest.
	sort.SliceStable(out, func(i, j int) bool {
		qi, _ := out[i]["quarantined"].(bool)
		qj, _ := out[j]["quarantined"].(bool)
		if qi != qj {
			return qi
		}
		pi, _ := out[i]["paused"].(bool)
		pj, _ := out[j]["paused"].(bool)
		if pi != pj {
			return pi
		}
		return out[i]["strikes"].(int) > out[j]["strikes"].(int)
	})
	return out
}

// isRiskControlBody reports whether an upstream error body carries the
// risk-control business code, in any of the shapes extractBizErrorCode accepts.
//
// It also accepts the bare substring: the coding plane wraps errors as
// {"error":{"code":"3012","message":"method not allowed"}} but a gateway
// interstitial can answer with a non-JSON body, and a strike we fail to book is
// a strike we will repeat.
func isRiskControlBody(body string) bool {
	if strings.TrimSpace(body) == "" {
		return false
	}
	if extractBizErrorCode(body) == riskControlCode {
		return true
	}
	return bizCodeSubstring(body, riskControlCode)
}

// bizCodeSubstring finds "code":<code> in a body that does not parse as JSON —
// a gateway interstitial often wraps the payload in HTML or a log line. The
// digits must END at the match: 30120 merely begins with 3012 and is a different
// business code, so a plain strings.Contains would book a risk strike for it.
func bizCodeSubstring(body, code string) bool {
	for _, prefix := range []string{`"code":`, `"code": `} {
		needle := prefix + code
		for off := 0; ; {
			i := strings.Index(body[off:], needle)
			if i < 0 {
				break
			}
			end := off + i + len(needle)
			if end >= len(body) || body[end] < '0' || body[end] > '9' {
				return true
			}
			off = end
		}
	}
	return false
}

// riskForTest exposes the raw table size, for the eviction and sweep tests.
func riskForTest() map[string]riskEntry {
	riskMu.Lock()
	defer riskMu.Unlock()
	out := make(map[string]riskEntry, len(riskTable))
	for id, e := range riskTable {
		out[id] = *e
	}
	return out
}

// resetRiskForTest clears all risk state and restores the clock.
func resetRiskForTest() {
	riskMu.Lock()
	riskTable = map[string]*riskEntry{}
	riskMu.Unlock()
	riskNowFn = time.Now
}
