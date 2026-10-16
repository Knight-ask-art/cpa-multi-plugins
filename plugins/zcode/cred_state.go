// cred_state.go is the per-credential health layer behind the dual-credential
// fallback.
//
// WHY IT EXISTS. A zcode account holds two independent credentials that ride
// two independent upstreams: the plan JWT (zcode.z.ai, anthropic dialect) and
// the resolved coding-plan API key (api.z.ai or open.bigmodel.cn, OpenAI
// dialect). Until now the plugin had health state only at ACCOUNT scope (risk
// control, lifecycle) and (account, model) scope (cooldown) — nothing that could
// say "this account's JWT is dead but its key is fine". So one dead credential
// took the whole account out of rotation, and every request paid a round trip to
// rediscover that.
//
// The two state machines are deliberately separate, because the two credentials
// fail for different reasons and recover differently:
//
//	credKindJWT   a 401/3007 means re-login; a 3007-family captcha challenge
//	              clears itself; a 429 is the gateway's own throttling.
//	credKindKey   the resolved key can be revoked or rotated on the Z.AI side
//	              with no signal to the JWT at all.
//
// WHAT IT IS NOT. It is not a routing table: `routeFor` still decides the plane
// from the credential's plan and the model's entitlement. This layer only says
// whether a credential is worth sending to, and it never overrides what the
// model's entitlement requires — see credRouteSkipFor for the one move it makes.
//
// State is process-local (cooldown.go's rule), so a CPA restart clears it.
package main

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// credKind identifies one of an account's two credentials.
type credKind string

const (
	// credKindJWT is the plan token: the credential the anthropic lane carries.
	credKindJWT credKind = "jwt"
	// credKindKey is the resolved coding-plan API key (molezzz's "managed API
	// key"; ours is resolved from the same OAuth flow into auth_keyres.go's
	// "{apiKey}.{secretKey}").
	credKindKey credKind = "key"
)

// credReason classifies why a credential is parked.
type credReason string

const (
	// credReasonAuth: the credential itself was rejected. Mirrors the host's
	// own 401 -> 30 min treatment (policy.go, statusError), and unlike a rate
	// limit it will not clear without a re-login — so the TTL is long enough
	// that we do not hammer the lane, but finite so a transient upstream 401
	// cannot pin the account forever.
	credReasonAuth credReason = "auth"
	// credReasonRate: throttled. Short, because this layer only avoids
	// immediate repeat attempts; the real backoff lives in cooldown.go.
	credReasonRate credReason = "rate"
	// credReasonChallenge: the gateway's verification layer asked for a captcha
	// (captcha_pool.go). Five minutes matches the reference's own retry window.
	credReasonChallenge credReason = "challenge"
	// credReasonTransport: no usable answer at all (5xx, connection failure).
	credReasonTransport credReason = "transport"
)

// credTTL is how long each reason parks the credential.
var credTTL = map[credReason]time.Duration{
	credReasonAuth:      30 * time.Minute,
	credReasonRate:      60 * time.Second,
	credReasonChallenge: 5 * time.Minute,
	credReasonTransport: 30 * time.Second,
}

type credKey struct {
	AuthID string
	Kind   credKind
}

type credEntry struct {
	Reason   credReason
	Until    time.Time
	Status   int
	Failures int
	LastAt   time.Time
}

const credMaxEntries = 4096

var (
	credMu    sync.Mutex
	credTable = map[credKey]credEntry{}
	credNowFn = time.Now
)

// credTTLFor is the park duration for one reason; unknown reasons get the
// transport TTL rather than none, so a future reason cannot become a permanent
// block by omission.
func credTTLFor(reason credReason) time.Duration {
	if d, ok := credTTL[reason]; ok {
		return d
	}
	return credTTL[credReasonTransport]
}

// markCredFailure parks one credential. Status is kept for the panel only.
func markCredFailure(authID string, kind credKind, reason credReason, status int) {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}
	now := credNowFn()
	key := credKey{AuthID: authID, Kind: kind}
	credMu.Lock()
	defer credMu.Unlock()
	credSweepLocked(now)
	if len(credTable) >= credMaxEntries {
		// Full: drop the entry closest to recovery, which is the least
		// informative one to lose.
		var soonest credKey
		until := time.Time{}
		first := true
		for k, v := range credTable {
			if first || v.Until.Before(until) {
				soonest, until, first = k, v.Until, false
			}
		}
		delete(credTable, soonest)
	}
	prev := credTable[key]
	// Consecutive failures accumulate so the panel can distinguish one blip
	// from a credential that keeps failing; they reset when the park lapses
	// (credSweepLocked drops the whole entry).
	failures := prev.Failures + 1
	credTable[key] = credEntry{
		Reason:   reason,
		Until:    now.Add(credTTLFor(reason)),
		Status:   status,
		Failures: failures,
		LastAt:   now,
	}
}

// markCredFailureFor parks a credential under BOTH identifiers that can name
// this account. The host's record ID (what the panel and `routeFor` hold) and
// the executor's reported AuthID agree for plugin-created credentials but are
// not guaranteed to, and risk.go already pays this cost for the same reason: a
// mismatch here would mean the failure is recorded under a key nothing reads.
func markCredFailureFor(hostID string, sa *storedAuth, kind credKind, reason credReason, status int) {
	markCredFailure(hostID, kind, reason, status)
	if sa != nil {
		if other := cooldownAuthIDFor(sa); other != hostID {
			markCredFailure(other, kind, reason, status)
		}
	}
}

// credSweepLocked drops expired entries. Lock held by the caller.
func credSweepLocked(now time.Time) {
	for k, v := range credTable {
		if !v.Until.After(now) {
			delete(credTable, k)
		}
	}
}

// credBlockedReason returns why the credential is parked. ok=false means
// healthy. The reason matters to callers that only care about parks that will
// NOT clear on their own — see credNeedsLogin.
func credBlockedReason(authID string, kind credKind) (credReason, bool) {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return "", false
	}
	now := credNowFn()
	credMu.Lock()
	defer credMu.Unlock()
	entry, ok := credTable[credKey{AuthID: authID, Kind: kind}]
	if !ok {
		return "", false
	}
	if !entry.Until.After(now) {
		delete(credTable, credKey{AuthID: authID, Kind: kind})
		return "", false
	}
	return entry.Reason, true
}

// credBlocked reports whether the credential is parked right now.
func credBlocked(authID string, kind credKind) bool {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return false
	}
	now := credNowFn()
	credMu.Lock()
	defer credMu.Unlock()
	entry, ok := credTable[credKey{AuthID: authID, Kind: kind}]
	if !ok {
		return false
	}
	if !entry.Until.After(now) {
		delete(credTable, credKey{AuthID: authID, Kind: kind})
		return false
	}
	return true
}

// credBlockedFor is the credential-scoped twin of riskBlocksAuth: it consults
// both identifiers so a park recorded under either one is honoured.
func credBlockedFor(hostID string, sa *storedAuth, kind credKind) bool {
	if credBlocked(hostID, kind) {
		return true
	}
	if sa != nil {
		return credBlocked(cooldownAuthIDFor(sa), kind)
	}
	return false
}

// credEntryFor renders one credential's state for the panel; ok=false means
// healthy (or never failed).
func credEntryFor(authID string, kind credKind) (map[string]any, bool) {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return nil, false
	}
	now := credNowFn()
	credMu.Lock()
	defer credMu.Unlock()
	entry, ok := credTable[credKey{AuthID: authID, Kind: kind}]
	if !ok || !entry.Until.After(now) {
		return nil, false
	}
	return map[string]any{
		"kind":        string(kind),
		"reason":      string(entry.Reason),
		"until":       entry.Until.Format("2006-01-02 15:04:05"),
		"remaining":   int(entry.Until.Sub(now).Seconds()),
		"status":      entry.Status,
		"failures":    entry.Failures,
		"last_fail":   entry.LastAt.Format("2006-01-02 15:04:05"),
		"needs_login": entry.Reason == credReasonAuth,
	}, true
}

// credNeedsLogin reports a park that will not clear on its own — a rejected
// credential, which only a re-login (or an operator's clear) ends. A rate limit
// or a captcha challenge is excluded on purpose: those clear themselves, and
// treating them as "this account is done" would take a healthy account out of
// rotation for a minute of throttling.
func credNeedsLogin(hostID string, sa *storedAuth, kind credKind) bool {
	if reason, ok := credBlockedReason(hostID, kind); ok && reason == credReasonAuth {
		return true
	}
	if sa != nil {
		if other := cooldownAuthIDFor(sa); other != hostID {
			if reason, ok := credBlockedReason(other, kind); ok && reason == credReasonAuth {
				return true
			}
		}
	}
	return false
}

// credCannotServe reports whether NOTHING on this account can serve a request
// without operator action.
//
// A start-plan account lives entirely on the JWT lane (the coding plane rejects
// that tier outright — see credFallbackBody), so its JWT alone decides. A
// coding-plan account keeps working on whichever credential is still good, so it
// takes both.
func credCannotServe(hostID string, sa *storedAuth) bool {
	jwtDead := credNeedsLogin(hostID, sa, credKindJWT)
	if sa != nil && authPlanFor(sa) == planStart {
		return jwtDead
	}
	return jwtDead && credNeedsLogin(hostID, sa, credKindKey)
}

// credSnapshotForAuth renders both credentials of one account.
func credSnapshotForAuth(hostID string, sa *storedAuth) map[string]any {
	out := map[string]any{}
	for _, kind := range []credKind{credKindJWT, credKindKey} {
		entry, ok := credEntryFor(hostID, kind)
		if !ok && sa != nil {
			entry, ok = credEntryFor(cooldownAuthIDFor(sa), kind)
		}
		if ok {
			out[string(kind)] = entry
		}
	}
	return out
}

// clearCredState drops one credential's park, or both when kind is empty.
func clearCredState(authID string, kind credKind) int {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return 0
	}
	credMu.Lock()
	defer credMu.Unlock()
	removed := 0
	for _, k := range []credKind{credKindJWT, credKindKey} {
		if kind != "" && k != kind {
			continue
		}
		key := credKey{AuthID: authID, Kind: k}
		if _, ok := credTable[key]; ok {
			delete(credTable, key)
			removed++
		}
	}
	return removed
}

// clearAllCredState drops every park, both credentials of every account. The
// operator's "I fixed it, stop guessing" button — see handleCredStateClear.
func clearAllCredState() int {
	credMu.Lock()
	defer credMu.Unlock()
	n := len(credTable)
	credTable = map[credKey]credEntry{}
	return n
}

// clearCredStateForAuth drops state under both identifiers.
func clearCredStateForAuth(hostID string, sa *storedAuth) int {
	n := clearCredState(hostID, "")
	if sa != nil {
		if other := cooldownAuthIDFor(sa); other != hostID {
			n += clearCredState(other, "")
		}
	}
	return n
}

// credSnapshotAll lists every parked credential, most-failing first.
func credSnapshotAll() []map[string]any {
	now := credNowFn()
	credMu.Lock()
	credSweepLocked(now)
	rows := make([]map[string]any, 0, len(credTable))
	for k, v := range credTable {
		rows = append(rows, map[string]any{
			"auth_id":   k.AuthID,
			"kind":      string(k.Kind),
			"reason":    string(v.Reason),
			"until":     v.Until.Format("2006-01-02 15:04:05"),
			"remaining": int(v.Until.Sub(now).Seconds()),
			"status":    v.Status,
			"failures":  v.Failures,
		})
	}
	credMu.Unlock()
	// Deterministic order, most failures first, then by id — a map walk would
	// reshuffle the panel on every refresh.
	sort.Slice(rows, func(i, j int) bool {
		fi, _ := rows[i]["failures"].(int)
		fj, _ := rows[j]["failures"].(int)
		if fi != fj {
			return fi > fj
		}
		ai, _ := rows[i]["auth_id"].(string)
		aj, _ := rows[j]["auth_id"].(string)
		if ai != aj {
			return ai < aj
		}
		ki, _ := rows[i]["kind"].(string)
		kj, _ := rows[j]["kind"].(string)
		return ki < kj
	})
	return rows
}

// -----------------------------------------------------------------------------
// failure classification
// -----------------------------------------------------------------------------

// credFailureFor classifies an upstream chat failure into a credential reason,
// or ok=false when the failure says nothing about the credential.
//
// The exclusions are the point of this function:
//
//	quota exhaustion (1113 family, 402) — the plan quota belongs to the ACCOUNT,
//	  so the other credential shares it. Retrying would spend a request to learn
//	  the same thing, and this is the failure the EXISTING coding->JWT fallback
//	  is for; it must not trigger the reverse.
//	risk control (3012) — the gateway's content/identity gate, which rejects
//	  ahead of model selection and is booked against the account (risk.go). A
//	  different credential on a different host does not change the verdict.
//	request-level rejections (400 without a credential code, 413, oversize
//	  input) — the request is the problem, not the credential.
func credFailureFor(status int, body string, challenged bool) (credReason, bool) {
	// The verification layer's own answer: the credential is fine, the call
	// needs a captcha. Treated as a credential park because the anthropic lane
	// is the only one with this gate.
	if challenged {
		return credReasonChallenge, true
	}
	if isHardQuotaError(status, body) || isRiskControlBody(body) {
		return "", false
	}
	switch status {
	case 401, 403:
		return credReasonAuth, true
	case 429:
		// 429 with quota semantics was already excluded above.
		return credReasonRate, true
	}
	if status >= 500 {
		return credReasonTransport, true
	}
	if status == 0 {
		// No HTTP answer at all (transport-level failure).
		return credReasonTransport, true
	}
	switch extractBizErrorCode(body) {
	case "3007", "3001":
		return credReasonAuth, true
	case "3002", "3008", "3009", "3010":
		return credReasonRate, true
	}
	if isSoftRateLimit(status, body) {
		return credReasonRate, true
	}
	return "", false
}

// -----------------------------------------------------------------------------
// fallback accounting
// -----------------------------------------------------------------------------

// credFallbackStat counts dual-credential fallback attempts and how many of them
// turned a failing JWT-lane call into a served one. The "helped" half is what
// tells an operator whether the coding plane can actually serve a model the
// harvest routed to the JWT lane — the one question this plugin cannot answer
// from the outside.
type credFallbackStat struct {
	Attempts  int64
	Helped    int64
	LastAt    time.Time
	LastPlane string
}

var (
	credFbMu   sync.Mutex
	credFbStat credFallbackStat
)

func recordCredFallback() {
	credFbMu.Lock()
	credFbStat.Attempts++
	credFbStat.LastAt = credNowFn()
	credFbMu.Unlock()
}

// noteCredFallbackHelped is called only once the retry has actually produced a
// usable answer, for the same reason the entitlement fallback memoizes on
// success rather than on acceptance: a merely-accepted request is not a served
// one.
func noteCredFallbackHelped(plane string) {
	credFbMu.Lock()
	credFbStat.Helped++
	credFbStat.LastPlane = plane
	credFbStat.LastAt = credNowFn()
	credFbMu.Unlock()
}

func credFallbackSnapshot() map[string]any {
	credFbMu.Lock()
	defer credFbMu.Unlock()
	out := map[string]any{
		"attempts": credFbStat.Attempts,
		"helped":   credFbStat.Helped,
	}
	if !credFbStat.LastAt.IsZero() {
		out["last_at"] = credFbStat.LastAt.Format("2006-01-02 15:04:05")
	}
	if credFbStat.LastPlane != "" {
		out["last_plane"] = credFbStat.LastPlane
	}
	return out
}

// credStateSnapshotForPanel is the management view: what is parked, and how the
// fallback has been doing.
func credStateSnapshotForPanel() map[string]any {
	return map[string]any{
		"parked":   credSnapshotAll(),
		"fallback": credFallbackSnapshot(),
		"note":     "状态存在插件进程内存里，重启清零；重启后第一条失败请求会重新学到。",
	}
}

// credResetForTest clears all state. Test-only, like resetRiskForTest.
func credResetForTest() {
	credMu.Lock()
	credTable = map[credKey]credEntry{}
	credMu.Unlock()
	credFbMu.Lock()
	credFbStat = credFallbackStat{}
	credFbMu.Unlock()
}
