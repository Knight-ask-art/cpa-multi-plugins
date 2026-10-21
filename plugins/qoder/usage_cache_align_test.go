package main

import (
	"encoding/json"
	"testing"
)

func usageOfJSON(t *testing.T, cleaned string) map[string]any {
	t.Helper()
	var chunk map[string]any
	if err := json.Unmarshal([]byte(cleaned), &chunk); err != nil {
		t.Fatalf("cleaned chunk is not JSON: %v (%s)", err, cleaned)
	}
	m, _ := chunk["usage"].(map[string]any)
	if m == nil {
		t.Fatalf("usage missing after cleaning: %s", cleaned)
	}
	return m
}

// v0.8.64: a backend that reports the hit only in prompt_cache_hit_tokens
// (cached_tokens hard-coded 0) must reach clients with cached_tokens filled.
func TestCleanChunkJSON_AlignsPromptCacheHit(t *testing.T) {
	raw := `{"choices":[],"usage":{"prompt_tokens":7213,"completion_tokens":1,"total_tokens":7214,"cached_tokens":0,"prompt_cache_hit_tokens":7040,"prompt_cache_miss_tokens":173}}`
	m := usageOfJSON(t, cleanChunkJSON(raw))
	if m["cached_tokens"] != float64(7040) {
		t.Fatalf("cached_tokens=%v want 7040", m["cached_tokens"])
	}
	details, _ := m["prompt_tokens_details"].(map[string]any)
	if details == nil || details["cached_tokens"] != float64(7040) {
		t.Fatalf("prompt_tokens_details.cached_tokens not aligned: %v", details)
	}
	if m["prompt_tokens"] != float64(7213) {
		t.Fatalf("prompt accounting must not change: %v", m["prompt_tokens"])
	}
}

func TestCleanChunkJSON_CacheMissStaysZero(t *testing.T) {
	raw := `{"choices":[],"usage":{"prompt_tokens":12,"cached_tokens":0,"prompt_cache_hit_tokens":0}}`
	m := usageOfJSON(t, cleanChunkJSON(raw))
	if m["cached_tokens"] != float64(0) {
		t.Fatalf("a genuine miss must stay 0: %v", m)
	}
}

func TestCleanChunkJSON_ReportedCachedNotOverwritten(t *testing.T) {
	raw := `{"choices":[{"index":0,"delta":{"content":"hi"}}],"usage":{"prompt_tokens":100,"total_tokens":105,"cached_tokens":80}}`
	m := usageOfJSON(t, cleanChunkJSON(raw))
	if m["cached_tokens"] != float64(80) {
		t.Fatalf("reported cached_tokens changed: %v", m["cached_tokens"])
	}
	if m["cache_read_input_tokens"] != float64(80) {
		t.Fatalf("absent cache_read_input_tokens should mirror cached_tokens: %v", m["cache_read_input_tokens"])
	}
}

func TestUsageDetailFromMap_PromptCacheHit(t *testing.T) {
	d := usageDetailFromMap(map[string]any{
		"prompt_tokens": float64(500), "cached_tokens": float64(0), "prompt_cache_hit_tokens": float64(400),
	})
	if d.CachedTokens != 400 || d.CacheReadTokens != 400 {
		t.Fatalf("cached=%d read=%d want 400/400", d.CachedTokens, d.CacheReadTokens)
	}
}
