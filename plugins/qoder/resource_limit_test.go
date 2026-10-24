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

func TestResourceLimitBecomes429WithRetryHint(t *testing.T) {
	upstreamErr := chatUpstreamError(http.StatusForbidden, liveResourceLimitBody)
	err := upstreamStatusError(http.StatusForbidden, upstreamErr)
	var se *statusError
	if !errors.As(err, &se) {
		t.Fatalf("resource limit must carry a status, got %T", err)
	}
	if se.status != http.StatusForbidden {
		t.Fatalf("status = %d, want the upstream's 403 (host routing)", se.status)
	}
	if !strings.Contains(err.Error(), "RESOURCE_LIMIT") || !strings.Contains(err.Error(), `"retryAfterSeconds\":30`) {
		t.Fatalf("message lost the actionable facts: %s", err.Error())
	}
	raw := errorEnvelopeFor(err)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Error == nil {
		t.Fatalf("envelope: %v %s", err, raw)
	}
	if env.Error.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("http_status = %d, want 429", env.Error.HTTPStatus)
	}
	if env.Error.RetryAfter != 30 {
		t.Fatalf("retry_after = %d, want 30", env.Error.RetryAfter)
	}
	// The generic 403 shape keeps its old behaviour: no status, no hint.
	// (A plain 403 without the marker is still status-less for the host.)
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
