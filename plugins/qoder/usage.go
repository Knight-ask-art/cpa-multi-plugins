// usage.go implements the UsagePlugin capability: the host calls handleUsage
// after every request with a canonical record, and we forward to CPAMP. The
// legacy publishUsage path is kept for hosts without UsagePlugin wiring.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// handleUsage is the UsagePlugin entry point. The host calls this after every
// request with the canonical usage record (it also records to its own
// DefaultManager, so we don't need to). Our job is just to forward to CPAMP.
//
// v0.7.0 compliance: this replaces the old pattern where each executor path
// called publishUsage directly (which both skipped the host audit and forced
// every call site to remember to publish).
func handleUsage(raw []byte) ([]byte, error) {
	var record pluginapi.UsageRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, err
	}
	// Only forward qoderwork's own records; the host will route other plugins'
	// usage to their own UsagePlugin.
	if record.Provider != "" && record.Provider != providerName {
		return okEnvelope(map[string]any{"forwarded": false})
	}
	detail := usage.Detail{
		InputTokens:         record.Detail.InputTokens,
		OutputTokens:        record.Detail.OutputTokens,
		ReasoningTokens:     record.Detail.ReasoningTokens,
		CachedTokens:        record.Detail.CachedTokens,
		CacheReadTokens:     record.Detail.CacheReadTokens,
		CacheCreationTokens: record.Detail.CacheCreationTokens,
		TotalTokens:         record.Detail.TotalTokens,
	}
	started := record.RequestedAt
	if started.IsZero() {
		started = time.Now().Add(-record.Latency)
	}
	// v0.8.28: local per-credential ledger feeding the credential-card usage
	// summary in the host's local credential management (note field). Async —
	// the host's usage pump must never block on note-write RPCs.
	usageLedgerObserve(record.AuthIndex, record.AuthID, detail.TotalTokens, record.Failed, started)
	go usageNoteRefreshSoon(record.AuthIndex, record.AuthID)
	forwardUsageToCPAMP(
		record.Alias,
		record.Model,
		record.AuthID,
		started,
		detail,
		record.Failed,
		record.Failure.StatusCode,
		record.Failure.Body,
	)
	return okEnvelope(map[string]any{"forwarded": true})
}

// publishUsage is kept for backward compatibility with existing call sites
// inside the executor. After v0.7.0 the host calls UsagePlugin.HandleUsage
// itself after every request, so executor-side publish is redundant. We
// forward to CPAMP here too so that hosts WITHOUT UsagePlugin wiring (older
// CPA builds) still emit usage; hosts with the wiring will trigger HandleUsage
// separately, but forwardUsageToCPAMP is idempotent at the CPAMP ingestion
// layer (NDJSON import dedups on timestamp+auth+model+total_tokens).
func publishUsage(requestedModel, upstreamModel, authID string, started time.Time, detail usage.Detail, failed bool, statusCode int, errBody string) {
	model := strings.TrimSpace(upstreamModel)
	if model == "" {
		model = strings.TrimSpace(requestedModel)
	}
	alias := strings.TrimSpace(requestedModel)
	if alias == "" {
		alias = model
	}
	// Fire-and-forget so the executor hot path never blocks on the CPAMP
	// round-trip. handleUsage (the host-driven path) is synchronous because the
	// host already runs it on its own goroutine after the request completes.
	go forwardUsageToCPAMP(alias, model, authID, started, normalizeUsageDetail(detail), failed, statusCode, errBody)
}

// forwardUsageToCPAMP POSTs one NDJSON line to CPAMP usage/import.
// Silent on misconfig / network errors — never blocks chat.
//
// v0.7.0: routed via host.http.do so the call is captured by request-log and
// uses host transport policy (proxy, timeout). Was: raw http.Client.
func forwardUsageToCPAMP(alias, model, authID string, started time.Time, detail usage.Detail, failed bool, statusCode int, errBody string) {
	usageReportMu.RLock()
	url := strings.TrimSpace(usageReportURL)
	key := strings.TrimSpace(usageReportKey)
	usageReportMu.RUnlock()
	if url == "" || key == "" {
		return
	}
	ts := started
	if ts.IsZero() {
		ts = time.Now()
	}
	latencyMs := int64(0)
	if !started.IsZero() {
		latencyMs = time.Since(started).Milliseconds()
		if latencyMs < 0 {
			latencyMs = 0
		}
	}
	total := detail.TotalTokens
	if total == 0 {
		total = detail.InputTokens + detail.OutputTokens + detail.ReasoningTokens
	}
	failBody := ""
	failCode := 200
	if failed {
		failCode = statusCode
		if failCode <= 0 {
			failCode = 502
		}
		failBody = truncate(redactSecrets(errBody), 512)
	}
	payload := map[string]any{
		"timestamp":     ts.UTC().Format(time.RFC3339Nano),
		"latency_ms":    latencyMs,
		"source":        "qoderwork",
		"auth_index":    strings.TrimSpace(authID),
		"provider":      providerName,
		"model":         model,
		"alias":         alias,
		"endpoint":      "POST /v1/chat/completions",
		"auth_type":     "oauth",
		"executor_type": "qoderwork",
		"generate":      true,
		"failed":        failed,
		"tokens": map[string]any{
			"input_tokens":          detail.InputTokens,
			"output_tokens":         detail.OutputTokens,
			"reasoning_tokens":      detail.ReasoningTokens,
			"cached_tokens":         detail.CachedTokens,
			"cache_read_tokens":     detail.CacheReadTokens,
			"cache_creation_tokens": detail.CacheCreationTokens,
			"total_tokens":          total,
		},
		"fail": map[string]any{
			"status_code": failCode,
			"body":        failBody,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	body = append(body, '\n')
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := hostHTTPDo(req)
	if err != nil {
		return
	}
	_ = resp.Body
}

func normalizeUsageDetail(d usage.Detail) usage.Detail {
	if d.TotalTokens == 0 {
		if total := d.InputTokens + d.OutputTokens + d.ReasoningTokens; total > 0 {
			d.TotalTokens = total
		}
	}
	return d
}

// usageDetailFromMap converts an OpenAI-style "usage" JSON object into a
// usage.Detail, tolerating both snake_case naming and numeric jitter.
func usageDetailFromMap(m map[string]any) usage.Detail {
	if len(m) == 0 {
		return usage.Detail{}
	}
	num := func(keys ...string) int64 {
		return positiveNumberFrom(m, keys...)
	}
	d := usage.Detail{
		InputTokens:  num("prompt_tokens", "input_tokens"),
		OutputTokens: num("completion_tokens", "output_tokens"),
		TotalTokens:  num("total_tokens"),
		// v0.8.64: cache-view rule shared with workbuddy 0.9.61 — several
		// Qoder backends report the hit as prompt_cache_hit_tokens (or a read
		// count in cache_read_input_tokens) while cached_tokens stays 0.
		CachedTokens:    num("cached_tokens", "cache_read_input_tokens", "prompt_cache_hit_tokens"),
		CacheReadTokens: num("cache_read_input_tokens", "cached_tokens", "prompt_cache_hit_tokens"),
	}
	if ct, ok := m["completion_tokens_details"].(map[string]any); ok {
		if v, ok2 := ct["reasoning_tokens"].(float64); ok2 {
			d.ReasoningTokens = int64(v)
		}
	}
	return d
}

// positiveNumberFrom returns the first positive value among keys, or 0.
// Zero-valued keys never shadow a populated sibling.
func positiveNumberFrom(m map[string]any, keys ...string) int64 {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch n := v.(type) {
			case float64:
				if n > 0 {
					return int64(n)
				}
			case int64:
				if n > 0 {
					return n
				}
			case json.Number:
				if i, err := n.Int64(); err == nil && i > 0 {
					return i
				}
			}
		}
	}
	return 0
}

// alignCacheUsage rewrites an OpenAI-shaped "usage" object so the canonical
// cache fields carry the value the upstream actually reported (workbuddy
// 0.9.61 parity). An upstream that fills prompt_cache_hit_tokens — or a read
// count in cache_read_input_tokens — while leaving cached_tokens /
// prompt_tokens_details.cached_tokens at 0 would otherwise be recorded as a
// full miss: CPA's collectors read cached_tokens through gjson Exists().
// Absent keys are filled; reported positive values are never overwritten; a
// genuine miss comes back untouched; token accounting is left alone.
func alignCacheUsage(obj map[string]any) bool {
	m, ok := obj["usage"].(map[string]any)
	if !ok || len(m) == 0 {
		return false
	}
	cached := positiveNumberFrom(m, "cached_tokens", "cache_read_input_tokens", "prompt_cache_hit_tokens")
	if cached == 0 {
		if d, ok := m["prompt_tokens_details"].(map[string]any); ok {
			cached = positiveNumberFrom(d, "cached_tokens")
		}
	}
	if cached == 0 {
		return false
	}
	changed := false
	for _, k := range []string{"cached_tokens", "cache_read_input_tokens"} {
		if positiveNumberFrom(m, k) == 0 {
			m[k] = cached
			changed = true
		}
	}
	details, _ := m["prompt_tokens_details"].(map[string]any)
	if details == nil {
		details = map[string]any{}
		m["prompt_tokens_details"] = details
		changed = true
	}
	if positiveNumberFrom(details, "cached_tokens") == 0 {
		details["cached_tokens"] = cached
		changed = true
	}
	if cd, ok := m["completion_tokens_details"].(map[string]any); ok && positiveNumberFrom(cd, "cached_tokens") == 0 {
		cd["cached_tokens"] = cached
		changed = true
	}
	return changed
}

// usageDetailFromCompletion extracts the usage block from an aggregated
// non-streaming chat.completion payload.
func usageDetailFromCompletion(payload []byte) usage.Detail {
	var obj map[string]any
	if json.Unmarshal(payload, &obj) != nil {
		return usage.Detail{}
	}
	m, _ := obj["usage"].(map[string]any)
	return usageDetailFromMap(m)
}

// sseUsageCollector scans upstream SSE chunks and keeps the last "usage"
// object seen (QoderWork emits it on the terminal chunk).
type sseUsageCollector struct {
	last map[string]any
}

func (c *sseUsageCollector) feed(rawJSON string) {
	var chunk map[string]any
	if json.Unmarshal([]byte(rawJSON), &chunk) != nil {
		return
	}
	if u, ok := chunk["usage"].(map[string]any); ok && len(u) > 0 {
		c.last = u
	}
}

func (c *sseUsageCollector) detail() usage.Detail {
	return usageDetailFromMap(c.last)
}
