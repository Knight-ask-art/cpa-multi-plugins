// resource_limit_test.go pins v0.8.79: the qoder queue/throttle family
// (10605 RESOURCE_LIMIT) becomes a 429 with the upstream's wait, and cools
// the (account, model) pair for exactly that long so scheduling moves off it.
package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// liveResourceLimitBody is the exact 2026-10-24 upstream body (wrapped the
// way the gateway delivers it, with message as a JSON-string).
const liveResourceLimitBody = `{"code":"10605","message":"{\"isQueued\":true,\"modelKey\":\"qfmodel\",\"queueCount\":0,\"queueType\":\"p3\",\"retryAfterSeconds\":30,\"serviceAvailable\":false,\"subCode\":\"RESOURCE_LIMIT\",\"waitTime\":30}","subCode":"RESOURCE_LIMIT"}`

func TestIsResourceLimitFailure(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"live 10605 body", liveResourceLimitBody, true},
		{"inner object only", `{"isQueued":true,"subCode":"RESOURCE_LIMIT"}`, true},
		{"code plus queue facts", `{"code":10605,"isQueued":false,"queueCount":3}`, true},
		{"bare 10605 without queue facts", `{"code":10605,"message":"unrelated"}`, false},
		{"plan gate", `{"code":"112","message":"plan_gate"}`, false},
		{"generic 403", `forbidden`, false},
		{"empty", ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isResourceLimitFailure(tc.body); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestResourceLimitRetryAfter(t *testing.T) {
	cases := []struct {
		name string
		body string
		want time.Duration
	}{
		{"seconds", `{"retryAfterSeconds":45}`, 45 * time.Second},
		{"snake seconds", `{"retry_after_seconds":12}`, 12 * time.Second},
		{"wait time fallback", `{"waitTime":20}`, 20 * time.Second},
		{"milliseconds", `{"retryAfterMs":9000}`, 9 * time.Second},
		{"absent default", `{"subCode":"RESOURCE_LIMIT"}`, resourceLimitRetryAfterDefault},
		{"clamped low", `{"retryAfterSeconds":1}`, resourceLimitRetryAfterMin},
		{"clamped high", `{"retryAfterSeconds":99999}`, resourceLimitRetryAfterMax},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resourceLimitRetryAfter(tc.body); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

// TestResourceLimitErrorIsStatusLess: the throttled request must not carry a
// 4xx status. The host's stream bootstrap retries 403/429 pre-first-chunk
// until the budget is spent and then answers a bare server_error; a plain error
// cools the pair and lets the host answer 503 + Retry-After instead.
func TestResourceLimitErrorIsStatusLess(t *testing.T) {
	upstreamErr := chatUpstreamError(http.StatusForbidden, liveResourceLimitBody)
	err := upstreamStatusError(http.StatusForbidden, upstreamErr)
	var se *statusError
	if errors.As(err, &se) {
		t.Fatalf("resource limit must be status-less, got %d", se.StatusCode())
	}
	// The actionable facts survive (wait + the raw body the RPC layer reads).
	if !strings.Contains(err.Error(), "RESOURCE_LIMIT") || !strings.Contains(err.Error(), "30s") {
		t.Fatalf("message lost the actionable facts: %s", err.Error())
	}
	if got := resourceLimitRetryAfter(err.Error()); got != 30*time.Second {
		t.Fatalf("wait hint = %v, want 30s", got)
	}
	raw := errorEnvelopeFor(err)
	var env envelope
	if json.Unmarshal(raw, &env) != nil || env.Error == nil {
		t.Fatalf("envelope: %s", raw)
	}
	if env.Error.HTTPStatus != 0 {
		t.Fatalf("http_status = %d, want none", env.Error.HTTPStatus)
	}
	// A plain 403 (no marker) is untouched as before.
	plain := upstreamStatusError(http.StatusForbidden, errors.New("forbidden"))
	var plainSE *statusError
	if errors.As(plain, &plainSE) {
		t.Fatalf("plain 403 must stay status-less, got %d", plainSE.StatusCode())
	}
}

func TestResourceLimitCoolsPairForUpstreamWait(t *testing.T) {
	base := time.Date(2026, 10, 24, 3, 0, 0, 0, time.UTC)
	restore := withCooldownNow(t, base)
	defer restore()

	recordUpstreamFailure("q-cn", "qunmodel", http.StatusForbidden, liveResourceLimitBody)
	until := modelCoolingUntil("q-cn", "qunmodel")
	if until.IsZero() {
		t.Fatal("resource_limit must cool the pair")
	}
	if got := until.Sub(base); got != 30*time.Second {
		t.Fatalf("cooldown = %v, want the upstream's 30s", got)
	}
	rows := cooldownSnapshotFor("q-cn")
	if len(rows) != 1 || rows[0]["reason"] != string(cooldownReasonResourceLimit) {
		t.Fatalf("snapshot = %+v", rows)
	}
	// Another account is unaffected, so scheduling can move there at once.
	if modelIsCooling("q-intl", "qunmodel") {
		t.Fatal("resource_limit leaked to another account")
	}
	// After the wait the pair is offered again.
	restore()
	restore2 := withCooldownNow(t, base.Add(31*time.Second))
	defer restore2()
	if modelIsCooling("q-cn", "qunmodel") {
		t.Fatal("pair still cooling after the upstream's wait")
	}
}

// TestResourceLimitParkVerdict: the streaming pump parks a throttled request
// instead of failing it, and the hand-off recognises the park.
func TestResourceLimitParkVerdict(t *testing.T) {
	g := newStreamHeadGate(time.Second)
	if g == nil {
		t.Fatal("gate unexpectedly disabled")
	}
	if !isResourceLimitFailure(liveResourceLimitBody) {
		t.Fatal("live body not classified")
	}
	g.abort(0, errParkedResourceLimit)
	v, decided := g.awaitHandoff(time.Second)
	if !decided || !isParkedVerdict(v) {
		t.Fatalf("park verdict lost: decided=%v v=%+v", decided, v)
	}
	// A normal failure verdict is not mistaken for a park.
	if isParkedVerdict(headVerdict{status: 429, err: errors.New("x")}) {
		t.Fatal("failure verdict read as park")
	}
	if err := resourceLimitUnavailableError(); err == nil {
		t.Fatal("park error missing")
	} else if strings.Contains(err.Error(), "RESOURCE_LIMIT") == false && !strings.Contains(err.Error(), "throttled") {
		t.Fatalf("park error lost its reason: %s", err.Error())
	}
}

// TestPublicChatPathNeverCarriesStatus pins why the fix for the 500 cannot be
// "send 429 from the plugin": the host's stream bootstrap treats 4xx (and
// 403/429 specifically) as retryable and drops the executor status, so the
// client ends up with a bare server_error. Streamed and sync chat errors for
// this family must therefore be status-less; only the non-stream path, where
// the host's executionErrorMessage keeps the status, reports 429.
func TestPublicChatPathNeverCarriesStatus(t *testing.T) {
	upstreamErr := chatUpstreamError(http.StatusForbidden, liveResourceLimitBody)
	if err := upstreamStatusError(http.StatusForbidden, upstreamErr); err != nil {
		var se *statusError
		if errors.As(err, &se) {
			t.Fatalf("chat path carries %d — the host bootstrap retry will mask it as 500", se.StatusCode())
		}
	}
}
