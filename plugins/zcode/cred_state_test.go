// cred_state_test.go covers the per-credential health layer and the
// dual-credential fallback built on it.
//
// The two properties most of these tests exist to pin down:
//
//   - A failure is classified before it is allowed to park anything. The
//     failures that say nothing about a credential (quota exhaustion, risk
//     control, request-level rejections) must not park it, because the other
//     credential of the same account shares every one of them — retrying would
//     spend a request to learn the same answer, and parking would take a healthy
//     lane out of rotation for someone else's fault.
//   - The two credentials are independent. A park on the JWT must not stop the
//     coding plane, and vice versa; only when BOTH are beyond self-recovery does
//     the account stop offering models.
package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// credClock resets cred state and installs a controllable clock, returning an
// advancer.
func credClock(t *testing.T) func(time.Duration) {
	t.Helper()
	credResetForTest()
	t.Cleanup(credResetForTest)
	base := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	now := base
	credNowFn = func() time.Time { return now }
	return func(d time.Duration) { now = now.Add(d) }
}

// codingAuth is a coding-plan credential carrying both credentials — the shape
// the fallback is for.
func codingAuth(uid string) *storedAuth {
	return &storedAuth{
		Auth: zcodeTokens{
			AccessToken: "k.s", OAuthToken: "o", JWT: "j",
			Provider: providerZai, Plan: planCoding,
		},
		Account: zcodeAccount{UID: uid},
	}
}

// startAuth is a start-plan credential: the coding plane does not serve that
// tier at all, so it has exactly one lane to lose.
func startAuth(uid string) *storedAuth {
	sa := codingAuth(uid)
	sa.Auth.Plan = planStart
	return sa
}

// jwtPlaneRoute is the anthropic lane carrying the plan JWT.
func jwtPlaneRoute() chatRoute {
	return chatRoute{
		endpoint:     startPlanAnthropicEndpoint,
		anthropic:    true,
		applyHeaders: applyStartPlanChatHeaders,
		plane:        planeJWTAnthropic,
	}
}

// offPeakPlaneRoute is anthropic-dialect too, but authenticates with the
// resolved key plus a ticket — a failure there is NOT about the JWT.
func offPeakPlaneRoute(ticket string) chatRoute {
	r := jwtPlaneRoute()
	r.offPeakTicketID = ticket
	r.plane = planeOffPeak
	return r
}

// openAIPayload is a minimal client request; the fallback rebuilds the
// coding-plane body from this rather than reusing the anthropic one.
func openAIPayload(t *testing.T, stream bool) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"model":    "glm-5.3",
		"stream":   stream,
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// classification
// ---------------------------------------------------------------------------

func TestCredFailureForClassifiesCredentialScopedFailures(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		challenged bool
		want       credReason
	}{
		{"401 is a rejected credential", http.StatusUnauthorized, `{"error":{"message":"unauthorized"}}`, false, credReasonAuth},
		{"403 is a rejected credential", http.StatusForbidden, `{"error":{"message":"forbidden"}}`, false, credReasonAuth},
		{"biz 3007 is a rejected credential", http.StatusOK, `{"error":{"code":"3007","message":"invalid token"}}`, false, credReasonAuth},
		{"biz 3001 is a rejected credential", http.StatusOK, `{"error":{"code":"3001","message":"login required"}}`, false, credReasonAuth},
		{"a captcha challenge parks the lane that has the gate", http.StatusOK, `{}`, true, credReasonChallenge},
		{"429 without quota semantics is throttling", http.StatusTooManyRequests, `{"error":{"message":"too many requests"}}`, false, credReasonRate},
		{"biz 3002 is throttling", http.StatusOK, `{"error":{"code":"3002","message":"rate limited"}}`, false, credReasonRate},
		{"biz 3008 is throttling", http.StatusOK, `{"error":{"code":"3008","message":"rate limited"}}`, false, credReasonRate},
		{"503 is transport", http.StatusServiceUnavailable, `upstream unavailable`, false, credReasonTransport},
		{"no answer at all is transport", 0, ``, false, credReasonTransport},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := credFailureFor(tc.status, tc.body, tc.challenged)
			if !ok {
				t.Fatalf("not classified at all (status %d, body %q)", tc.status, tc.body)
			}
			if got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCredFailureForExcludesAccountWideFailures(t *testing.T) {
	// Everything here belongs to the ACCOUNT (or the request), so the other
	// credential shares the verdict: retrying on it would only spend a request.
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{
			// The existing coding->JWT fallback owns this one; the reverse
			// fallback must not react to it.
			"no resource package (1113) is the account's quota",
			http.StatusTooManyRequests,
			`{"error":{"code":"1113","message":"Insufficient balance or no resource package. Please recharge."}}`,
		},
		{
			"402 with the no-package body is the account's quota",
			http.StatusPaymentRequired,
			`{"error":{"code":"1113","message":"Insufficient balance or no resource package."}}`,
		},
		{
			"risk control (3012) is account-wide",
			http.StatusOK,
			`{"error":{"code":"3012","message":"risk control"}}`,
		},
		{
			"a plain 400 is the request's problem",
			http.StatusBadRequest,
			`{"error":{"message":"invalid parameter: temperature"}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := credFailureFor(tc.status, tc.body, false)
			if ok {
				t.Fatalf("classified as %q; must be excluded so the other credential is not blamed", reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parking
// ---------------------------------------------------------------------------

func TestCredParkExpiresItself(t *testing.T) {
	advance := credClock(t)

	markCredFailure("uid-a", credKindKey, credReasonRate, http.StatusTooManyRequests)
	if !credBlocked("uid-a", credKindKey) {
		t.Fatal("a fresh park must block")
	}
	// The other credential of the same account is untouched: that is the whole
	// point of the layer.
	if credBlocked("uid-a", credKindJWT) {
		t.Fatal("parking the key must not park the JWT")
	}
	advance(credTTL[credReasonRate] - time.Second)
	if !credBlocked("uid-a", credKindKey) {
		t.Fatal("still inside the TTL")
	}
	advance(2 * time.Second)
	if credBlocked("uid-a", credKindKey) {
		t.Fatal("a rate park must clear on its own")
	}
}

func TestCredBlockedReasonSeparatesRecoverableFromNeedsLogin(t *testing.T) {
	credClock(t)

	markCredFailure("uid-a", credKindKey, credReasonRate, http.StatusTooManyRequests)
	if reason, ok := credBlockedReason("uid-a", credKindKey); !ok || reason != credReasonRate {
		t.Fatalf("reason = %q ok=%v, want rate", reason, ok)
	}
	if credNeedsLogin("uid-a", nil, credKindKey) {
		t.Fatal("a rate park clears itself and must not read as a dead credential")
	}

	markCredFailure("uid-b", credKindJWT, credReasonAuth, http.StatusUnauthorized)
	if !credNeedsLogin("uid-b", nil, credKindJWT) {
		t.Fatal("a rejected credential needs a re-login")
	}
}

func TestMarkCredFailureForMarksBothIdentifiers(t *testing.T) {
	credClock(t)
	sa := codingAuth("uid-both")
	hostID := cooldownAuthIDFor(sa)
	if hostID == "executor-id" {
		t.Fatal("test needs two distinct identifiers")
	}

	markCredFailureFor(hostID, sa, credKindKey, credReasonAuth, http.StatusUnauthorized)
	// Reading through the OTHER identifier must see the park: a failure
	// recorded under a key nothing reads is the bug this guards against.
	if !credBlockedFor("executor-id", sa, credKindKey) {
		t.Fatal("the park must be visible under the executor's auth id too")
	}
	if !credBlockedFor(hostID, sa, credKindKey) {
		t.Fatal("the park must be visible under the host id")
	}
	if got := clearCredStateForAuth(hostID, sa); got == 0 {
		t.Fatal("clearing both identifiers must remove something")
	}
	if credBlockedFor("executor-id", sa, credKindKey) {
		t.Fatal("cleared")
	}
}

func TestCredCannotServe(t *testing.T) {
	credClock(t)

	// A coding-plan account keeps working on whichever credential is still
	// good, so one dead lane is not a dead account.
	sa := codingAuth("uid-coding")
	markCredFailure(cooldownAuthIDFor(sa), credKindJWT, credReasonAuth, http.StatusUnauthorized)
	if credCannotServe(cooldownAuthIDFor(sa), sa) {
		t.Fatal("coding plane is still healthy; the account can serve")
	}
	markCredFailure(cooldownAuthIDFor(sa), credKindKey, credReasonAuth, http.StatusUnauthorized)
	if !credCannotServe(cooldownAuthIDFor(sa), sa) {
		t.Fatal("both credentials rejected: nothing can serve")
	}

	// A start-plan account has exactly one lane.
	start := startAuth("uid-start")
	markCredFailure(cooldownAuthIDFor(start), credKindJWT, credReasonAuth, http.StatusUnauthorized)
	if !credCannotServe(cooldownAuthIDFor(start), start) {
		t.Fatal("a start-plan account rides the JWT lane only")
	}
}

func TestCredCannotServeIgnoresSelfClearingParks(t *testing.T) {
	credClock(t)
	start := startAuth("uid-start-selfclear")
	markCredFailure(cooldownAuthIDFor(start), credKindJWT, credReasonRate, http.StatusTooManyRequests)
	if credCannotServe(cooldownAuthIDFor(start), start) {
		t.Fatal("a throttled credential is not a dead one")
	}
}

func TestCatalogEmptiesWhenNothingCanServe(t *testing.T) {
	withCleanModelPolicy(t)
	credClock(t)

	start := startAuth("uid-catalog-cred")
	if got := catalogFor(t, start, pluginapi.HostConfigSummary{}); len(got) == 0 {
		t.Fatal("a healthy start-plan account must advertise its bucket models")
	}
	markCredFailure(cooldownAuthIDFor(start), credKindJWT, credReasonAuth, http.StatusUnauthorized)
	if got := catalogFor(t, start, pluginapi.HostConfigSummary{}); len(got) != 0 {
		t.Fatalf("advertised %v while its only lane is rejected", got)
	}

	// And the coding-plan account must NOT be emptied by the same park alone.
	credResetForTest()
	coding := codingAuth("uid-catalog-coding")
	markCredFailure(cooldownAuthIDFor(coding), credKindJWT, credReasonAuth, http.StatusUnauthorized)
	if got := catalogFor(t, coding, pluginapi.HostConfigSummary{}); len(got) == 0 {
		t.Fatal("a coding-plan account with a live key must keep serving")
	}
}

// ---------------------------------------------------------------------------
// route -> credential
// ---------------------------------------------------------------------------

func TestCredKindForRoute(t *testing.T) {
	if got := credKindForRoute(jwtPlaneRoute()); got != credKindJWT {
		t.Fatalf("jwt lane -> %q", got)
	}
	// Anthropic dialect but key-authenticated: the odd one.
	if got := credKindForRoute(offPeakPlaneRoute("tk-1")); got != credKindKey {
		t.Fatalf("off-peak lane -> %q, want key", got)
	}
	sa := codingAuth("uid-kind")
	if got := credKindForRoute(credFallbackRoute(sa)); got != credKindKey {
		t.Fatalf("coding lane -> %q", got)
	}
}

func TestNoteRouteFailureParksTheRoutesCredential(t *testing.T) {
	credClock(t)
	sa := codingAuth("uid-note")
	hostID := cooldownAuthIDFor(sa)
	auth := `{"error":{"message":"unauthorized"}}`

	noteRouteFailure(hostID, sa, jwtPlaneRoute(), http.StatusUnauthorized, auth)
	if !credBlocked(hostID, credKindJWT) || credBlocked(hostID, credKindKey) {
		t.Fatal("a failing JWT lane must park the JWT only")
	}
	noteRouteFailure(hostID, sa, offPeakPlaneRoute("tk-1"), http.StatusUnauthorized, auth)
	if !credBlocked(hostID, credKindKey) {
		t.Fatal("the off-peak lane authenticates with the key, so it parks the key")
	}
}

func TestNoteRouteFailureIgnoresUnclassifiableAnswers(t *testing.T) {
	credClock(t)
	sa := codingAuth("uid-note2")
	hostID := cooldownAuthIDFor(sa)

	noteRouteFailure(hostID, sa, jwtPlaneRoute(), http.StatusTooManyRequests,
		`{"error":{"code":"1113","message":"Insufficient balance or no resource package."}}`)
	if credBlocked(hostID, credKindJWT) {
		t.Fatal("a quota rejection is not a credential failure")
	}
}

// ---------------------------------------------------------------------------
// the dual-credential fallback
// ---------------------------------------------------------------------------

func TestCredFallbackBodyRefusesWhenItCannotHelp(t *testing.T) {
	credClock(t)
	payload := openAIPayload(t, false)
	authFail := `{"error":{"message":"unauthorized"}}`

	cases := []struct {
		name   string
		hostID string
		sa     *storedAuth
		route  chatRoute
		status int
		body   string
		wire   func(*storedAuth)
	}{
		{
			name: "start-plan has nothing to fall back to (the coding plane does not serve that tier)",
			sa:   startAuth("uid-fb-start"), route: jwtPlaneRoute(),
			status: http.StatusUnauthorized, body: authFail,
		},
		{
			name: "the request is already on the coding plane",
			sa:   codingAuth("uid-fb-coding"), route: credFallbackRoute(codingAuth("uid-fb-coding")),
			status: http.StatusUnauthorized, body: authFail,
		},
		{
			name: "the off-peak lane is key-authenticated, so a failure there is not about the JWT",
			sa:   codingAuth("uid-fb-offpeak"), route: offPeakPlaneRoute("tk-1"),
			status: http.StatusUnauthorized, body: authFail,
		},
		{
			name: "a quota rejection is the account's, not the credential's",
			sa:   codingAuth("uid-fb-quota"), route: jwtPlaneRoute(),
			status: http.StatusTooManyRequests,
			body:   `{"error":{"code":"1113","message":"Insufficient balance or no resource package."}}`,
		},
		{
			name: "no resolved key to fall back to",
			sa:   codingAuth("uid-fb-nokey"), route: jwtPlaneRoute(),
			status: http.StatusUnauthorized, body: authFail,
			wire: func(sa *storedAuth) { sa.Auth.AccessToken = "" },
		},
		{
			name: "the key is already parked, so the answer is known",
			sa:   codingAuth("uid-fb-parked"), route: jwtPlaneRoute(),
			status: http.StatusUnauthorized, body: authFail,
			wire: func(sa *storedAuth) {
				markCredFailure(cooldownAuthIDFor(sa), credKindKey, credReasonAuth, http.StatusUnauthorized)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			credResetForTest()
			if tc.wire != nil {
				tc.wire(tc.sa)
			}
			before := credFallbackSnapshot()["attempts"]
			route, body, ok := credFallbackBody(cooldownAuthIDFor(tc.sa), tc.sa, tc.route, tc.status, tc.body, nil, payload, "glm-5.3", false)
			if ok {
				t.Fatalf("must refuse, got route %+v body %q", route, body)
			}
			if after := credFallbackSnapshot()["attempts"]; after != before {
				t.Fatalf("a refusal must not count as an attempt (%v -> %v)", before, after)
			}
		})
	}
}

func TestCredFallbackBodyBuildsTheCodingRequest(t *testing.T) {
	credClock(t)
	sa := codingAuth("uid-fb-ok")
	hostID := cooldownAuthIDFor(sa)

	route, body, ok := credFallbackBody(hostID, sa, jwtPlaneRoute(), http.StatusUnauthorized,
		`{"error":{"message":"unauthorized"}}`, nil, openAIPayload(t, true), "glm-5.3", true)
	if !ok {
		t.Fatal("a rejected JWT with a live key is exactly the case this exists for")
	}
	if route.anthropic {
		t.Fatal("the fallback must land on the coding plane's OpenAI dialect")
	}
	if route.plane != planeZaiCoding {
		t.Fatalf("plane = %q, want %q", route.plane, planeZaiCoding)
	}
	if route.endpoint != chatEndpointFor(sa) {
		t.Fatalf("endpoint = %q, want the provider's chat endpoint", route.endpoint)
	}
	// The body is REBUILT from the original payload: the anthropic body the JWT
	// lane just sent cannot be reused across dialects.
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, body)
	}
	if obj["model"] != "glm-5.3" {
		t.Fatalf("model = %v", obj["model"])
	}
	if obj["stream"] != true {
		t.Fatalf("stream = %v, want true (the caller's flag, not a default)", obj["stream"])
	}
	if obj["messages"] == nil {
		t.Fatal("the payload's messages must survive the rebuild")
	}
	if got := credFallbackSnapshot()["attempts"]; got != int64(1) {
		t.Fatalf("attempts = %v, want 1", got)
	}
	if got := credFallbackSnapshot()["helped"]; got != int64(0) {
		t.Fatalf("an attempt is not a success: helped = %v", got)
	}
}

func TestCredFallbackBodyHonoursTheNonStreamFlag(t *testing.T) {
	credClock(t)
	sa := codingAuth("uid-fb-nostream")
	_, body, ok := credFallbackBody(cooldownAuthIDFor(sa), sa, jwtPlaneRoute(), http.StatusUnauthorized,
		`{"error":{"message":"unauthorized"}}`, nil, openAIPayload(t, false), "glm-5.3", false)
	if !ok {
		t.Fatal("refused")
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		t.Fatalf("body: %v", err)
	}
	if obj["stream"] != false {
		t.Fatalf("stream = %v, want false", obj["stream"])
	}
}

func TestCredFallbackBodyUsesBigmodelPlaneForBigmodelCredentials(t *testing.T) {
	credClock(t)
	sa := codingAuth("uid-fb-bigmodel")
	sa.Auth.Provider = providerBigmodel

	route, _, ok := credFallbackBody(cooldownAuthIDFor(sa), sa, jwtPlaneRoute(), http.StatusUnauthorized,
		`{"error":{"message":"unauthorized"}}`, nil, openAIPayload(t, false), "glm-4.6", false)
	if !ok {
		t.Fatal("refused")
	}
	if route.plane != planeBigmodelCoding {
		t.Fatalf("plane = %q, want %q", route.plane, planeBigmodelCoding)
	}
}

func TestCredFallbackBodyTreatsACaptchaChallengeAsCredentialScoped(t *testing.T) {
	credClock(t)
	sa := codingAuth("uid-fb-captcha")
	hdrs := http.Header{}
	hdrs.Set("x-aliyun-captcha-verify-param", "abc123")

	route, _, ok := credFallbackBody(cooldownAuthIDFor(sa), sa, jwtPlaneRoute(), http.StatusOK,
		`{"error":{"code":"3007","message":"captcha required"}}`, hdrs, openAIPayload(t, false), "glm-5.3", false)
	if !ok {
		t.Fatal("the anthropic lane's verification gate is the one failure the other credential can sidestep")
	}
	if route.anthropic {
		t.Fatal("must land on the coding plane")
	}
}

func TestCredFallbackHelpedCountsOnlyServedRequests(t *testing.T) {
	credClock(t)
	noteCredFallbackHelped(planeZaiCoding)
	snap := credFallbackSnapshot()
	if snap["helped"] != int64(1) {
		t.Fatalf("helped = %v", snap["helped"])
	}
	if snap["last_plane"] != planeZaiCoding {
		t.Fatalf("last_plane = %v", snap["last_plane"])
	}
	// The panel needs a timestamp to tell a live bet from a stale one.
	if _, ok := snap["last_at"]; !ok {
		t.Fatal("last_at missing")
	}
}

// ---------------------------------------------------------------------------
// management surface
// ---------------------------------------------------------------------------

func TestCredSnapshotAllIsDeterministicallyOrdered(t *testing.T) {
	credClock(t)
	markCredFailure("uid-b", credKindJWT, credReasonAuth, http.StatusUnauthorized)
	markCredFailure("uid-b", credKindJWT, credReasonAuth, http.StatusUnauthorized)
	markCredFailure("uid-a", credKindKey, credReasonRate, http.StatusTooManyRequests)
	markCredFailure("uid-c", credKindJWT, credReasonTransport, http.StatusServiceUnavailable)

	rows := credSnapshotAll()
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	// Most failures first, then by id, then kind — a map walk would reshuffle the
	// panel on every refresh.
	if rows[0]["auth_id"] != "uid-b" || rows[0]["failures"] != 2 {
		t.Fatalf("first row = %#v, want the twice-failing uid-b", rows[0])
	}
	if rows[1]["auth_id"] != "uid-a" || rows[2]["auth_id"] != "uid-c" {
		t.Fatalf("order = %v, %v", rows[1]["auth_id"], rows[2]["auth_id"])
	}
}

func TestCredSnapshotForAuthReportsBothKinds(t *testing.T) {
	credClock(t)
	sa := codingAuth("uid-snap")
	hostID := cooldownAuthIDFor(sa)
	markCredFailure(hostID, credKindJWT, credReasonAuth, http.StatusUnauthorized)
	markCredFailure(hostID, credKindKey, credReasonRate, http.StatusTooManyRequests)

	snap := credSnapshotForAuth(hostID, sa)
	jwt, ok := snap[string(credKindJWT)].(map[string]any)
	if !ok {
		t.Fatalf("jwt missing: %#v", snap)
	}
	if jwt["needs_login"] != true {
		t.Fatalf("needs_login = %v", jwt["needs_login"])
	}
	key, ok := snap[string(credKindKey)].(map[string]any)
	if !ok {
		t.Fatalf("key missing: %#v", snap)
	}
	if key["needs_login"] != false {
		t.Fatalf("a rate park does not need a login: %#v", key)
	}
	if key["reason"] != string(credReasonRate) {
		t.Fatalf("reason = %v", key["reason"])
	}
}

func TestHandleCredStateClear(t *testing.T) {
	credClock(t)
	markCredFailure("uid-clear", credKindJWT, credReasonAuth, http.StatusUnauthorized)
	markCredFailure("uid-clear", credKindKey, credReasonRate, http.StatusTooManyRequests)

	// kind filters: clearing the JWT must leave the key parked.
	body, _ := json.Marshal(map[string]string{"auth_id": "uid-clear", "kind": "jwt"})
	out := handleCredStateClear(pluginapi.ManagementRequest{Body: body})
	if out["removed"] != 1 {
		t.Fatalf("removed = %v, want 1", out["removed"])
	}
	if credBlocked("uid-clear", credKindJWT) {
		t.Fatal("jwt should be cleared")
	}
	if !credBlocked("uid-clear", credKindKey) {
		t.Fatal("key should still be parked")
	}

	// An unknown kind is refused rather than silently treated as "both".
	bad, _ := json.Marshal(map[string]string{"auth_id": "uid-clear", "kind": "everything"})
	if _, ok := handleCredStateClear(pluginapi.ManagementRequest{Body: bad})["error"]; !ok {
		t.Fatal("an unknown kind must be rejected")
	}
	if !credBlocked("uid-clear", credKindKey) {
		t.Fatal("a rejected request must not clear anything")
	}

	// Empty auth_id is the "I fixed it upstream" button.
	out = handleCredStateClear(pluginapi.ManagementRequest{Body: []byte(`{}`)})
	if out["removed"] != 1 {
		t.Fatalf("removed = %v, want 1", out["removed"])
	}
	if len(credSnapshotAll()) != 0 {
		t.Fatal("everything should be cleared")
	}
}

func TestCredStateSnapshotForPanelShape(t *testing.T) {
	credClock(t)
	markCredFailure("uid-panel", credKindJWT, credReasonAuth, http.StatusUnauthorized)
	snap := credStateSnapshotForPanel()
	if _, ok := snap["parked"]; !ok {
		t.Fatalf("panel snapshot missing parked: %#v", snap)
	}
	if _, ok := snap["fallback"]; !ok {
		t.Fatalf("panel snapshot missing fallback: %#v", snap)
	}
	// The panel has to be able to say why a badge clears by itself, so the note
	// states the process-local lifetime.
	if note, _ := snap["note"].(string); !strings.Contains(note, "重启") {
		t.Fatalf("note = %q, want the process-local lifetime spelled out", note)
	}
}
