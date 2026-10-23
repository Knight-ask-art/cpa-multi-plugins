package main

import (
	"encoding/json"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// TestHiddenCauseNamesTheStaleEntry pins v0.8.77: a row hidden by an entry
// written against an OLD spelling must name that entry and be flagged stale.
// The live case: dfmodel was renamed to deepseek-v4.1-flash while
// hidden_models still said "deepseek-flash"; the panel showed a bare 已隐藏
// and offered no way to see (or undo) the cause.
func TestHiddenCauseNamesTheStaleEntry(t *testing.T) {
	defer setLocalizeConfig(true, false, map[string]string{})
	setLocalizeConfig(true, false, map[string]string{"dfmodel": "deepseek-v4.1-flash"})
	seedDisplay("dfmodel", "DeepSeek-Flash")
	defer setHiddenModels(nil)

	setHiddenModels([]string{"deepseek-flash", "glm-5-3"})

	// The renamed row: hidden via the raw key, but the entry the operator
	// wrote names no current id.
	by, via := hiddenCause("dfmodel", "deepseek-v4.1-flash")
	if len(by) != 1 || by[0] != "deepseek-flash" {
		t.Fatalf("hiddenCause(renamed) = %v via %v, want [deepseek-flash]", by, via)
	}
	if matchesFacing(by, "deepseek-v4.1-flash") {
		t.Fatalf("stale entry reported as matching the current facing id")
	}

	// An unrelated model keeps only its own entry.
	by2, _ := hiddenCause("gmodel", "glm-5-3")
	if len(by2) != 1 || by2[0] != "glm-5-3" {
		t.Fatalf("hiddenCause(glm) = %v, want [glm-5-3]", by2)
	}

	// The panel gets the operator's spelling back, not the raw key.
	if snap := hiddenEntriesSnapshot(); len(snap) != 2 || snap[0] != "deepseek-flash" {
		t.Fatalf("hiddenEntriesSnapshot = %v, want the config spellings", snap)
	}
}

// TestRemoveHiddenModelsAppliesLive: 取消隐藏 must take effect in-process and
// hand back the replacement YAML block (config.yaml is never rewritten).
func TestRemoveHiddenModelsAppliesLive(t *testing.T) {
	defer setLocalizeConfig(true, false, map[string]string{})
	setLocalizeConfig(true, false, map[string]string{"dfmodel": "deepseek-v4.1-flash"})
	seedDisplay("dfmodel", "DeepSeek-Flash")
	setHiddenModels([]string{"deepseek-flash", "glm-5-3"})
	defer setHiddenModels(nil)

	remaining, removed := removeHiddenModels([]string{"deepseek-flash"})
	if len(removed) != 1 || removed[0] != "deepseek-flash" {
		t.Fatalf("removed = %v", removed)
	}
	if len(remaining) != 1 || remaining[0] != "glm-5-3" {
		t.Fatalf("remaining = %v, want [glm-5-3]", remaining)
	}
	// The live filter no longer hides the row.
	if hiddenRawSet()["dfmodel"] {
		t.Fatalf("dfmodel still hidden after removal")
	}
	block := hiddenModelsYAMLBlock(remaining)
	want := "hidden_models:" + newlineChar + `    - "glm-5-3"`
	if block != want {
		t.Fatalf("yaml block = %q, want %q", block, want)
	}

	// Removing an entry that is not there is a no-op, not an error.
	again, none := removeHiddenModels([]string{"kimi-k3"})
	if len(none) != 0 || len(again) != 1 {
		t.Fatalf("no-op removal changed the list: remaining=%v removed=%v", again, none)
	}
}

// TestHandleHiddenModelsRejectsEmpty: the endpoint must not silently accept a
// request with nothing to remove.
func TestHandleHiddenModelsRejectsEmpty(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"remove": []string{}})
	res := handleHiddenModels(pluginapi.ManagementRequest{Method: "POST", Body: body})
	if _, ok := res["error"]; !ok {
		t.Fatalf("empty remove accepted: %v", res)
	}
}
