// risk_test.go covers the account-scoped risk-control ladder (risk.go) and the
// two places it changes behaviour: upstream-failure routing and the per-credential
// model catalog the host schedules against.
package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// riskClock pins the injectable clock and clears the table, returning an
// advance function so a test can walk the ladder across the 24h window.
func riskClock(t *testing.T) func(time.Duration) {
	t.Helper()
	resetRiskForTest()
	t.Cleanup(resetRiskForTest)
	base := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	now := base
	riskNowFn = func() time.Time { return now }
	return func(d time.Duration) { now = now.Add(d) }
}

func TestRecordRiskControlLadder(t *testing.T) {
	advance := riskClock(t)

	// Strike 1: a short pause, because one malformed request is the common case.
	e := recordRiskControl("u-1", "glm-5.3", riskControlCode)
	if e.Quarantined {
		t.Fatalf("one strike must not quarantine: %+v", e)
	}
	if want := riskFirstCooldown; e.Until.Sub(riskNowFn()) != want {
		t.Fatalf("first pause = %v, want %v", e.Until.Sub(riskNowFn()), want)
	}
	if !riskBlocksAuth("u-1") {
		t.Fatal("a paused account must be blocked")
	}

	// Strike 2 still only pauses — the ladder is deliberately coarse.
	advance(time.Minute)
	e = recordRiskControl("u-1", "glm-5.3", riskControlCode)
	if len(e.Strikes) != 2 {
		t.Fatalf("strikes = %d, want 2", len(e.Strikes))
	}
	if want := riskFirstCooldown; e.Until.Sub(riskNowFn()) != want {
		t.Fatalf("second pause = %v, want %v (no escalation yet)", e.Until.Sub(riskNowFn()), want)
	}

	// Strike 3 inside the window: stop for the day.
	advance(time.Minute)
	e = recordRiskControl("u-1", "glm-5.3", riskControlCode)
	if want := riskThirdCooldown; e.Until.Sub(riskNowFn()) != want {
		t.Fatalf("third pause = %v, want %v", e.Until.Sub(riskNowFn()), want)
	}

	// Strikes 4 and 5 on the way to quarantine; 4 stays at the 24h rung.
	advance(time.Minute)
	e = recordRiskControl("u-1", "glm-5.3", riskControlCode)
	if e.Quarantined {
		t.Fatal("four strikes must not quarantine")
	}
	advance(time.Minute)
	e = recordRiskControl("u-1", "glm-5.3", riskControlCode)
	if !e.Quarantined {
		t.Fatalf("five strikes must quarantine: %+v", e)
	}
	if !e.Until.IsZero() {
		t.Fatalf("a quarantine must have no clock, got until=%v", e.Until)
	}
}

// A quarantine has no clock, so no amount of waiting clears it — that is the
// whole point of the terminal rung.
func TestQuarantineIsNotClearedByTime(t *testing.T) {
	advance := riskClock(t)
	for i := 0; i < riskQuarantineAt; i++ {
		recordRiskControl("u-q", "glm-5.3", riskControlCode)
	}
	if !riskBlocksAuth("u-q") {
		t.Fatal("quarantined account must be blocked")
	}
	advance(30 * 24 * time.Hour)
	if !riskBlocksAuth("u-q") {
		t.Fatal("a quarantine must survive the strike window expiring")
	}
	// It is also not swept away as "aged out".
	riskMu.Lock()
	riskSweepLocked(riskNowFn())
	_, alive := riskTable["u-q"]
	riskMu.Unlock()
	if !alive {
		t.Fatal("the sweep must not drop a quarantined account")
	}
	if n := clearRisk("u-q"); n != 1 {
		t.Fatalf("clearRisk = %d, want 1", n)
	}
	if riskBlocksAuth("u-q") {
		t.Fatal("clearing must lift the quarantine")
	}
}

func TestRiskStrikesAgeOutOfTheWindow(t *testing.T) {
	advance := riskClock(t)
	recordRiskControl("u-2", "glm-5.3", riskControlCode)
	recordRiskControl("u-2", "glm-5.3", riskControlCode)

	// Past the window the old strikes stop counting, so the next challenge is
	// treated as a first strike rather than tripping the 24h rung.
	advance(riskStrikeWindow + time.Minute)
	e := recordRiskControl("u-2", "glm-5.3", riskControlCode)
	if len(e.Strikes) != 1 {
		t.Fatalf("strikes = %d, want 1 after the window expired", len(e.Strikes))
	}
	if want := riskFirstCooldown; e.Until.Sub(riskNowFn()) != want {
		t.Fatalf("pause = %v, want the first-strike rung %v", e.Until.Sub(riskNowFn()), want)
	}
}

func TestRiskPauseLapses(t *testing.T) {
	advance := riskClock(t)
	recordRiskControl("u-3", "glm-5.3", riskControlCode)
	if !riskBlocksAuth("u-3") {
		t.Fatal("must be blocked during the pause")
	}
	advance(riskFirstCooldown + time.Second)
	if riskBlocksAuth("u-3") {
		t.Fatal("must be routable after the pause lapses")
	}
	// ...but the strike history survives inside the window, so a second
	// challenge still escalates on schedule.
	e := recordRiskControl("u-3", "glm-5.3", riskControlCode)
	if len(e.Strikes) != 2 {
		t.Fatalf("strikes = %d, want 2 (history outlives the pause)", len(e.Strikes))
	}
}

func TestRiskUnknownAndEmptyIDs(t *testing.T) {
	riskClock(t)
	if riskBlocksAuth("nobody") {
		t.Fatal("an unknown account must not be blocked")
	}
	if s := riskSummaryFor("nobody"); s != nil {
		t.Fatalf("unknown account must have no summary, got %+v", s)
	}
	// An empty auth ID is not an account: booking under it would block the
	// zero value for every caller that forgot to pass an ID.
	if e := recordRiskControl("", "glm-5.3", riskControlCode); !e.LastAt.IsZero() {
		t.Fatalf("empty auth id must be ignored, got %+v", e)
	}
	if len(riskForTest()) != 0 {
		t.Fatalf("table = %v, want empty", riskForTest())
	}
}

func TestClearRiskScopes(t *testing.T) {
	riskClock(t)
	recordRiskControl("u-a", "glm-5.3", riskControlCode)
	recordRiskControl("u-b", "glm-5.3", riskControlCode)
	if n := clearRisk("u-absent"); n != 0 {
		t.Fatalf("clearing an absent account = %d, want 0", n)
	}
	if n := clearRisk("u-a"); n != 1 {
		t.Fatalf("clearRisk(u-a) = %d, want 1", n)
	}
	if riskBlocksAuth("u-a") {
		t.Fatal("u-a must be clear")
	}
	if !riskBlocksAuth("u-b") {
		t.Fatal("clearing one account must not disturb another")
	}
	if n := clearRisk(""); n != 1 {
		t.Fatalf("clear-all = %d, want 1 remaining", n)
	}
	if len(riskForTest()) != 0 {
		t.Fatalf("table = %v, want empty", riskForTest())
	}
}

func TestSweepForgetsAgedAndLapsedAccounts(t *testing.T) {
	advance := riskClock(t)
	recordRiskControl("u-old", "glm-5.3", riskControlCode)
	advance(riskStrikeWindow + time.Hour)

	riskMu.Lock()
	riskSweepLocked(riskNowFn())
	riskMu.Unlock()

	if len(riskForTest()) != 0 {
		t.Fatalf("table = %v, want the aged account swept", riskForTest())
	}
}

func TestIsRiskControlBody(t *testing.T) {
	yes := []string{
		`{"code":3012}`,
		`{"code":"3012"}`,
		`{"error":{"code":"3012","message":"method not allowed"}}`,
		`{"error":{"code":3012}}`,
		`{"code": "3012"}`,
		`<html>risk {"code":3012}</html>`,
	}
	for _, body := range yes {
		if !isRiskControlBody(body) {
			t.Fatalf("isRiskControlBody(%q) = false, want true", body)
		}
	}
	no := []string{
		"",
		"   ",
		`{"code":30120}`,
		`{"code":301}`,
		`{"code":1113,"message":"Insufficient balance"}`,
		`{"error":{"code":"3007"}}`,
		"plain text",
	}
	for _, body := range no {
		if isRiskControlBody(body) {
			t.Fatalf("isRiskControlBody(%q) = true, want false", body)
		}
	}
}

// The account/model split is the point of the whole module: a 3012 must book
// account-level state and must NOT freeze the one model it happened to ride.
func TestRecordUpstreamFailureRoutes3012ToAccountScope(t *testing.T) {
	riskClock(t)
	oldNow := cooldownNowFn
	cooldownNowFn = func() time.Time { return time.Unix(1000000, 0) }
	defer func() { cooldownNowFn = oldNow }()

	recordUpstreamFailure("acct-risk", "glm-5", 405, `{"error":{"code":"3012","message":"method not allowed"}}`)

	if !riskBlocksAuth("acct-risk") {
		t.Fatal("3012 must pause the account")
	}
	if modelIsCooling("acct-risk", "glm-5") {
		t.Fatal("3012 must not cool the model — the gate rejects before model selection, so a model cooldown would just move the failure along the catalog")
	}
	clearModelCooldown("acct-risk", "")

	// A 429 still rides the model-scoped path and leaves risk state alone.
	recordUpstreamFailure("acct-rate", "glm-5", 429, "too many requests")
	if !modelIsCooling("acct-rate", "glm-5") {
		t.Fatal("429 must still cool the pair")
	}
	if riskBlocksAuth("acct-rate") {
		t.Fatal("429 must not pause the account")
	}
	clearModelCooldown("acct-rate", "")
}

// The coding plane answers 429 with a business code and no prose; the text scan
// alone missed it, so the pair never cooled.
func TestSoftRateLimitRecognisesBusinessCodes(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{`{"error":{"code":"3002"}}`, true},
		{`{"code":1302}`, true},
		{`{"code":1303}`, true},
		{`{"code":"1305"}`, true},
		{`{"code":"1312"}`, true},
		{`{"error":{"code":"3012","message":"method not allowed"}}`, false},
		{`{"code":1113,"message":"Insufficient balance"}`, false},
		{`{"code":3001}`, false},
	}
	for _, c := range cases {
		if got := isSoftRateLimit(500, c.body); got != c.want {
			t.Fatalf("isSoftRateLimit(500, %q) = %v, want %v", c.body, got, c.want)
		}
	}
}

// The dashboard lists the host's record ID while the executor reports the
// UID-derived one; a lookup that only tried the first would show "no risk
// state" for an account that is actually paused.
func TestRiskSummaryForAuthFallsBackToCooldownID(t *testing.T) {
	riskClock(t)
	sa := &storedAuth{
		Auth:    zcodeTokens{Provider: providerZai},
		Account: zcodeAccount{UID: "uid-fallback"},
	}
	recordRiskControl(cooldownAuthIDFor(sa), "glm-5.3", riskControlCode)

	if s := riskSummaryFor("host-record-id"); s != nil {
		t.Fatalf("the host ID is not the key here, got %+v", s)
	}
	s := riskSummaryForAuth("host-record-id", sa)
	if s == nil || !s.Paused {
		t.Fatalf("riskSummaryForAuth = %+v, want the paused state via the cooldown ID", s)
	}
	if n := clearRiskForAuth("host-record-id", sa); n != 1 {
		t.Fatalf("clearRiskForAuth = %d, want 1", n)
	}
	if riskBlocksAuth(cooldownAuthIDFor(sa)) {
		t.Fatal("clearing through the host ID must clear the cooldown-ID key too")
	}
}

func TestRiskSnapshotAllSevereFirst(t *testing.T) {
	riskClock(t)
	recordRiskControl("u-paused", "glm-5.3", riskControlCode) // 1 strike → paused
	for i := 0; i < riskQuarantineAt; i++ {
		recordRiskControl("u-quarantined", "glm-5.3", riskControlCode)
	}

	rows := riskSnapshotAll()
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2: %v", len(rows), rows)
	}
	if rows[0]["auth_id"] != "u-quarantined" || rows[0]["quarantined"] != true {
		t.Fatalf("most severe must sort first, got %v", rows[0])
	}
	if rows[1]["auth_id"] != "u-paused" || rows[1]["paused"] != true {
		t.Fatalf("second row = %v", rows[1])
	}
	if rows[0]["strikes"] != riskQuarantineAt {
		t.Fatalf("strikes = %v, want %d", rows[0]["strikes"], riskQuarantineAt)
	}
	if rows[0]["last_code"] != riskControlCode {
		t.Fatalf("last_code = %v", rows[0]["last_code"])
	}
}

// A healthy account must produce no risk field at all, so the panel can omit
// the badge without a second condition.
func TestRiskSummaryAbsentForHealthyAccount(t *testing.T) {
	advance := riskClock(t)
	recordRiskControl("u-healthy", "glm-5.3", riskControlCode)
	advance(riskStrikeWindow + time.Hour)
	if s := riskSummaryFor("u-healthy"); s != nil {
		t.Fatalf("summary = %+v, want nil once the history aged out", s)
	}
}

// ---------------------------------------------------------------------------
// routing surface
// ---------------------------------------------------------------------------

// handleModelForAuth returning zero models is how the host learns a credential
// has nothing to serve — the pause takes effect through the catalog rather than
// by flipping the operator's disabled flag.
func TestHandleModelForAuthDropsCatalogWhileRiskPaused(t *testing.T) {
	riskClock(t)
	sa := &storedAuth{
		Auth: zcodeTokens{
			AccessToken: "k.s", OAuthToken: "o", JWT: "j",
			Provider: providerZai, Plan: planCoding,
		},
		Account: zcodeAccount{UID: "uid-catalog"},
	}
	storage, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := json.Marshal(pluginapi.AuthModelRequest{
		AuthID: "uid-catalog", AuthProvider: providerName, StorageJSON: storage,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	modelsForAuth := func(t *testing.T) []pluginapi.ModelInfo {
		t.Helper()
		out, err := handleModelForAuth(req)
		if err != nil {
			t.Fatalf("handleModelForAuth: %v", err)
		}
		var env envelope
		if err := json.Unmarshal(out, &env); err != nil {
			t.Fatalf("envelope: %v", err)
		}
		if !env.OK {
			t.Fatalf("not ok: %s", out)
		}
		var resp pluginapi.ModelResponse
		if err := json.Unmarshal(env.Result, &resp); err != nil {
			t.Fatalf("model response: %v", err)
		}
		return resp.Models
	}

	if got := modelsForAuth(t); len(got) == 0 {
		t.Fatal("precondition: a healthy account must serve a catalog")
	}

	recordRiskControl(cooldownAuthIDFor(sa), "glm-5.3", riskControlCode)
	if got := modelsForAuth(t); len(got) != 0 {
		t.Fatalf("a paused account must serve no models, got %d", len(got))
	}

	// Lifting the pause restores the catalog, so the pause is not a dead end.
	clearRisk(cooldownAuthIDFor(sa))
	if got := modelsForAuth(t); len(got) == 0 {
		t.Fatal("clearing the pause must restore the catalog")
	}
}

func TestHandleRiskListAndClear(t *testing.T) {
	riskClock(t)
	f := newFakeHostAuthStore(t)
	f.add(t, "idx-1", "auth-1", "zcode-zai-uid-risk.json", "uid-risk", providerZai, nil)
	recordRiskControl("uid-risk", "glm-5.3", riskControlCode)

	out := handleRiskList(pluginapi.ManagementRequest{})
	if out["count"] != 1 {
		t.Fatalf("count = %v, want 1: %v", out["count"], out)
	}

	// Clearing by the host's record ID has to reach the key the risk table
	// actually holds, which is why the handler resolves through the auth store.
	cleared := handleRiskClear(pluginapi.ManagementRequest{Body: []byte(`{"auth_id":"idx-1"}`)})
	if cleared["removed"] != 1 {
		t.Fatalf("removed = %v, want 1: %v", cleared["removed"], cleared)
	}
	if riskBlocksAuth("uid-risk") {
		t.Fatal("the account must be routable again")
	}
	if out := handleRiskList(pluginapi.ManagementRequest{}); out["count"] != 0 {
		t.Fatalf("count = %v, want 0", out["count"])
	}
}

func TestHandleRiskClearAllWhenAuthIDEmpty(t *testing.T) {
	riskClock(t)
	newFakeHostAuthStore(t)
	recordRiskControl("uid-a", "glm-5.3", riskControlCode)
	recordRiskControl("uid-b", "glm-5.3", riskControlCode)

	out := handleRiskClear(pluginapi.ManagementRequest{Body: []byte(`{}`)})
	if out["removed"] != 2 {
		t.Fatalf("removed = %v, want 2", out["removed"])
	}
	if len(riskForTest()) != 0 {
		t.Fatalf("table = %v, want empty", riskForTest())
	}
}
