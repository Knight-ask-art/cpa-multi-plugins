// resource_limit.go — v0.8.79: the qoder queue/throttle family (10605).
//
// Measured 2026-10-24 on both qoder accounts, one after the other:
//
//	qwen3-8-flash -> HTTP 403 body {"code":"10605","message":
//	  "{\"isQueued\":true,\"modelKey\":\"qfmodel\",\"subCode\":\"RESOURCE_LIMIT\",
//	    \"retryAfterSeconds\":30,\"serviceAvailable\":false,\"queueType\":\"p3\"}"}
//
// Two things were wrong with treating that as a plain 403:
//
//  1. The client got "server_error" / HTTP 500: 403 is deliberately NOT in
//     upstreamStatusError's account-level set (there is no evidenced qoder
//     business-403 family), so no status crossed the RPC boundary at all. But
//     this one is not an auth failure — the upstream says "wait 30 seconds",
//     which is exactly a 429.
//  2. Both credentials were tried back to back against the same throttled
//     model, and nothing told the host to skip it for a while: 429 drives the
//     host's quota backoff (credential-scoped, escalating from seconds), while
//     the pair-scoped table below only knew "rate_limit" with a fixed TTL.
//
// So the family is classified here instead of by status:
//   - isResourceLimitFailure keys on the subCode / code marker (and the
//     queue-ish fields) in the body;
//   - resourceLimitRetryAfter reads retryAfterSeconds / waitTime (seconds) or
//     retryAfterMs, defaulting to 30s and clamped to [5s, 10m] — the upstream
//     controls the number, but a hostile body must not pin the pair for hours;
//   - the pair cooldown uses that duration (reason resource_limit), the
//     credential-level envelope reports 429 + retryAfter, and the model leaves
//     the per-credential catalog while cooling, so scheduling moves to the
//     other qoder account / region instead of colliding with the same wall.
package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// resourceLimitCode is the gateway's queue / resource business code.
	resourceLimitCode = "10605"
	// resourceLimitRetryAfterDefault is used when the body quotes no wait.
	resourceLimitRetryAfterDefault = 30 * time.Second
	resourceLimitRetryAfterMin     = 5 * time.Second
	resourceLimitRetryAfterMax     = 10 * time.Minute
)

// isResourceLimitFailure reports the qoder throttle family. Keys on the
// subCode / numeric code marker rather than the HTTP status: the same
// rejection is observed as 403 on the chat path (and has been reported as a
// 200-OK envelope for streamed frames).
func isResourceLimitFailure(body string) bool {
	if strings.TrimSpace(body) == "" {
		return false
	}
	lower := strings.ToLower(body)
	if strings.Contains(lower, "resource_limit") || strings.Contains(lower, "resourcelimit") {
		return true
	}
	if !strings.Contains(body, resourceLimitCode) {
		return false
	}
	// The bare code also appears in unrelated payloads only rarely; require a
	// queue-ish companion so a chat body quoting "10605" cannot cool a pair.
	return strings.Contains(lower, "isqueued") ||
		strings.Contains(lower, "queuecount") ||
		strings.Contains(lower, "queuetype") ||
		strings.Contains(lower, "serviceavailable")
}

// resourceLimitWaitFields pulls the numeric wait hints out of a qoder body.
// Decoded rather than pattern-matched: the gateway wraps the real object in a
// JSON string under "message", so both layers are walked, and no regexp
// corner cases (or escaping) can swallow a hint.
func resourceLimitWaitFields(body string) map[string]int64 {
	out := map[string]int64{}
	walk := func(raw string) {
		var m map[string]any
		if json.Unmarshal([]byte(raw), &m) != nil {
			return
		}
		var nested string
		for k, v := range m {
			switch n := v.(type) {
			case float64:
				if n > 0 {
					out[k] = int64(n)
				}
			case string:
				if k == "message" || k == "details" {
					nested = n
				}
			}
		}
		if nested != "" {
			var inner map[string]any
			if json.Unmarshal([]byte(nested), &inner) == nil {
				for k, v := range inner {
					if n, ok := v.(float64); ok && n > 0 {
						if _, seen := out[k]; !seen {
							out[k] = int64(n)
						}
					}
				}
			}
		}
	}
	walk(strings.TrimSpace(body))
	return out
}

// resourceLimitRetryAfter reads the wait the upstream quoted. Unparseable or
// absent → the default; clamped so one bad body cannot freeze a model.
func resourceLimitRetryAfter(body string) time.Duration {
	wait := time.Duration(0)
	fields := resourceLimitWaitFields(body)
	for _, key := range []string{"retryAfterSeconds", "retry_after_seconds", "waitTime", "wait_time"} {
		if n := fields[key]; n > 0 {
			wait = time.Duration(n) * time.Second
			break
		}
	}
	if wait == 0 {
		for _, key := range []string{"retryAfterMs", "retry_after_ms"} {
			if n := fields[key]; n > 0 {
				wait = time.Duration(n) * time.Millisecond
				break
			}
		}
	}
	if wait <= 0 {
		return resourceLimitRetryAfterDefault
	}
	if wait < resourceLimitRetryAfterMin {
		return resourceLimitRetryAfterMin
	}
	if wait > resourceLimitRetryAfterMax {
		return resourceLimitRetryAfterMax
	}
	return wait
}

// resourceLimitErrorMessage renders the family as one actionable line, with
// the queue facts the upstream actually sent (model key, queue type, wait).
func resourceLimitErrorMessage(body string, wait time.Duration) string {
	var facts struct {
		QueueType string `json:"queueType"`
		ModelKey  string `json:"modelKey"`
	}
	for _, src := range []string{body, unwrapQuotedJSON(body)} {
		if json.Unmarshal([]byte(src), &facts) == nil && (facts.QueueType != "" || facts.ModelKey != "") {
			break
		}
	}
	line := "qoder 上游模型级排队/限流（RESOURCE_LIMIT 10605）"
	if facts.ModelKey != "" {
		line += fmtModelKey(facts.ModelKey)
	}
	if facts.QueueType != "" {
		line += " queue=" + facts.QueueType
	}
	line += "：上游要求 " + strconv.Itoa(int(wait/time.Second)) + "s 后重试，当前账号的这个模型已临时冷却，会换其他账号/模型继续。"
	return line
}

// fmtModelKey renders the upstream key as "（qfmodel）" when present.
func fmtModelKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	return "（" + key + "）"
}

// unwrapQuotedJSON turns the gateway's JSON-string-in-message shape into the
// object it quotes; unrelated input is returned unchanged.
func unwrapQuotedJSON(body string) string {
	var s string
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &s) != nil {
		return body
	}
	return s
}

// resourceLimitCarrier is rebuilt from the 429 statusError by
// errorEnvelopeFor so the host's MarkResult sees both the status and the
// upstream's retry hint (retryAfterFromError keys on RetryAfter()).
type resourceLimitCarrier struct {
	*statusError
	wait time.Duration
}

// RetryAfter returns the upstream-quoted wait, so the host applies exactly
// that duration instead of its own escalating default.
func (e *resourceLimitCarrier) RetryAfter() *time.Duration {
	if e == nil || e.wait <= 0 {
		return nil
	}
	w := e.wait
	return &w
}

// asResourceLimitCarrier unwraps a statusError chain into the carrier form;
// nil when the error does not describe a resource-limit 403.
//
// v0.8.79: the chat slice treats an errored upstream response as "fall back
// for this credential", not as a request failure — the dedicated chat error
// path (which is what turns 403 RESOURCE_LIMIT into 429) is therefore not
// guaranteed to be reached, and the host then sees the generic in-band error.
// The wait hint is recovered from the statusError's message instead, which
// keeps the raw upstream body.
func asResourceLimitCarrier(err error) *resourceLimitCarrier {
	var se *statusError
	if !errors.As(err, &se) || se == nil || se.status != http.StatusForbidden {
		return nil
	}
	var carrier *resourceLimitCarrier
	if errors.As(err, &carrier) && carrier != nil {
		return carrier
	}
	msg := se.Error()
	if !isResourceLimitFailure(msg) && len(resourceLimitWaitFields(msg)) == 0 {
		return nil
	}
	return &resourceLimitCarrier{statusError: se, wait: resourceLimitRetryAfter(msg)}
}
