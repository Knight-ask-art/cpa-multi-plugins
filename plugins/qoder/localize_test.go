package main

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestLocalizeSlug(t *testing.T) {
	cases := map[string]string{
		"Qwen3.8-Flash":        "qwen3-8-flash",
		"GLM-5.3":              "glm-5-3",
		"DeepSeek-V4-Pro":      "deepseek-v4-pro",
		"MiniMax-M3":           "minimax-m3",
		"Kimi-K2.8-Preview":    "kimi-k2-8-preview",
		"  Qwen3.8-Max  ":      "qwen3-8-max",
		"GLM-5.3-Flash":        "glm-5-3-flash",
		"":                     "",
		"!!!":                  "",
		"Qwen/3.8 (Flash) Max": "qwen-3-8-flash-max",
	}
	for in, want := range cases {
		if got := localizeSlug(in); got != want {
			t.Errorf("localizeSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func seedDisplay(raw, name string) {
	localizeMu.Lock()
	localizeDisplay[raw] = name
	localizeMu.Unlock()
}

func TestLocalizedModelsRewritesAndKeepsUpstream(t *testing.T) {
	setLocalizeConfig(true, false, map[string]string{})
	seedDisplay("qfmodel", "Qwen3.8-Flash")
	seedDisplay("gmodel", "GLM-5.3")
	in := []pluginapi.ModelInfo{
		{ID: "qfmodel", Name: "Qwen3.8-Flash"},
		{ID: "gmodel", Name: "GLM-5.3"},
		{ID: "auto", Name: "Auto"},
	}
	out := localizedModels(in)
	if len(out) != 3 {
		t.Fatalf("len = %d, want 3", len(out))
	}
	if out[0].ID != "qwen3-8-flash" || out[0].Name != "qfmodel" {
		t.Fatalf("entry 0 = %+v, want id=qwen3-8-flash name=qfmodel", out[0])
	}
	// resolveLocalizedModel maps the slug back to the raw key.
	if got := resolveLocalizedModel("qwen3-8-flash"); got != "qfmodel" {
		t.Fatalf("resolve qwen3-8-flash = %q, want qfmodel", got)
	}
	// A raw key passes through unchanged.
	if got := resolveLocalizedModel("gmodel"); got != "gmodel" {
		t.Fatalf("resolve gmodel = %q, want gmodel", got)
	}
	// Unknown ids pass through too.
	if got := resolveLocalizedModel("deepseek-v4.1-flash"); got != "deepseek-v4.1-flash" {
		t.Fatalf("unknown model rewritten: %q", got)
	}
}

func TestLocalizedModelsOffKeepsRaw(t *testing.T) {
	seedDisplay("qfmodel", "Qwen3.8-Flash")
	setLocalizeConfig(false, false, nil)
	defer setLocalizeConfig(true, false, nil)
	in := []pluginapi.ModelInfo{{ID: "qfmodel", Name: "Qwen3.8-Flash"}}
	out := localizedModels(in)
	if out[0].ID != "qfmodel" {
		t.Fatalf("localize off must keep raw id, got %q", out[0].ID)
	}
}

func TestLocalizedModelsOverrideAndCollision(t *testing.T) {
	setLocalizeConfig(true, false, map[string]string{"qfmodel": "qwen-flash"})
	defer setLocalizeConfig(true, false, map[string]string{})
	seedDisplay("qfmodel", "Qwen3.8-Flash")
	seedDisplay("qmodel_38max", "Qwen3.8-Flash")
	in := []pluginapi.ModelInfo{
		{ID: "qfmodel", Name: "Qwen3.8-Flash"},
		{ID: "qmodel_38max", Name: "Qwen3.8-Flash"}, // same display name → collision
	}
	out := localizedModels(in)
	if out[0].ID != "qwen-flash" {
		t.Fatalf("override lost: %q", out[0].ID)
	}
	if out[1].ID != "qwen3-8-flash" {
		t.Fatalf("colliding entry keeps the slug for the second raw key, got %q", out[1].ID)
	}
	// The duplicate 1017 collision case: same slug twice must never publish.
	out = localizedModels([]pluginapi.ModelInfo{
		{ID: "qfmodel", Name: "Qwen3.8-Flash"},
		{ID: "qmodel_38max", Name: "Qwen3.8-Flash"},
		{ID: "kmodel", Name: "Qwen3.8-Flash"},
	})
	seen := map[string]bool{}
	for _, m := range out {
		if seen[m.ID] {
			t.Fatalf("duplicate id %q published", m.ID)
		}
		seen[m.ID] = true
	}
}

func TestLocalizedModelsKeepOriginals(t *testing.T) {
	// Previous tests may have set an override; reset the table first.
	setLocalizeConfig(true, true, map[string]string{})
	resetLocalizeState()
	localizeOn, localizeKeep = true, true // resetLocalizeState restores the default switch
	seedDisplay("qfmodel", "Qwen3.8-Flash")
	defer setLocalizeConfig(true, false, map[string]string{})
	out := localizedModels([]pluginapi.ModelInfo{{ID: "qfmodel", Name: "Qwen3.8-Flash"}})
	if len(out) != 2 || out[0].ID != "qfmodel" || out[1].ID != "qwen3-8-flash" {
		t.Fatalf("keep-originals shape = %+v", out)
	}
	if got := resolveLocalizedModel("qfmodel"); got != "qfmodel" {
		t.Fatalf("raw key with keep-originals = %q", got)
	}
}

// A raw key whose "display name" is the key itself (static fallback label)
// must not get a hyphenated alias like "qmodel-38max".
func TestNoteCatalogDisplaysSkipsSelfNamed(t *testing.T) {
	resetLocalizeState()
	noteCatalogDisplays([]pluginapi.ModelInfo{{ID: "qmodel_38max", Name: "qmodel_38max"}})
	if got := resolveLocalizedModel("qmodel_38max"); got != "qmodel_38max" {
		t.Fatalf("self-named model must stay raw, got %q", got)
	}
	noteCatalogDisplays([]pluginapi.ModelInfo{{ID: "qfmodel", DisplayName: "Qwen3.8-Flash"}})
	if got := resolveLocalizedModel("qwen3-8-flash"); got != "qfmodel" {
		t.Fatalf("display-named model must localize, got %q", got)
	}
}

// The published catalog carries the friendly id AND the raw key, so clients
// still sending qfmodel are routed instead of getting "unknown provider".
func TestPublishCatalogKeepsRawKeys(t *testing.T) {
	resetLocalizeState()
	localizeOn, localizeKeep = true, true
	seedDisplay("qfmodel", "Qwen3.8-Flash")
	out := publishCatalog([]pluginapi.ModelInfo{{ID: "qfmodel", DisplayName: "Qwen3.8-Flash"}})
	ids := map[string]bool{}
	for _, m := range out {
		ids[m.ID] = true
	}
	if !ids["qwen3-8-flash"] || !ids["qfmodel"] {
		t.Fatalf("published ids = %v, want both friendly and raw", ids)
	}
	lm := localizeMapLocked(knownRawModelsCached())
	if lm["qfmodel"] != "qwen3-8-flash" {
		t.Fatalf("mapping lost: %v", lm)
	}
}

func TestModelIDOverridesBeatSlugAndWorkWithLocalizeOff(t *testing.T) {
	resetLocalizeState()
	setLocalizeConfig(true, false, map[string]string{})
	setModelIDOverrides(map[string]string{"qfmodel": "my-flash", "gmodel": "my-glm"})
	seedDisplay("qfmodel", "Qwen3.8-Flash")
	seedDisplay("gmodel", "GLM-5.3")
	if got := localizeFacingFor("qfmodel"); got != "my-flash" {
		t.Fatalf("override lost: %q", got)
	}
	if got := resolveLocalizedModel("my-glm"); got != "gmodel" {
		t.Fatalf("custom id must resolve back: %q", got)
	}
	// Overrides survive localize off (they are explicit id changes).
	setLocalizeConfig(false, true, map[string]string{})
	if got := localizeFacingFor("qfmodel"); got != "my-flash" {
		t.Fatalf("override must apply with localize off, got %q", got)
	}
	setLocalizeConfig(true, true, map[string]string{})
	setModelIDOverrides(map[string]string{})
}

func TestSyncListToRawIds(t *testing.T) {
	resetLocalizeState()
	seedDisplay("qfmodel", "Qwen3.8-Flash")
	got, changed := syncListToRawIds([]string{"qwen3-8-flash", "auto", "gmodel"})
	if !changed || len(got) != 3 || got[0] != "qfmodel" || got[1] != "auto" || got[2] != "gmodel" {
		t.Fatalf("sync = %v changed=%v", got, changed)
	}
	// Already raw: nothing changes.
	if _, changed := syncListToRawIds([]string{"qfmodel", "auto"}); changed {
		t.Fatal("raw list reported as changed")
	}
}

func TestParseModelIDTable(t *testing.T) {
	m := parseModelIDTable(map[string]any{"qfmodel": "my-flash"})
	if m["qfmodel"] != "my-flash" {
		t.Fatalf("map form: %v", m)
	}
	m = parseModelIDTable([]any{map[string]any{"id": "gmodel", "alias": "my-glm"}})
	if m["gmodel"] != "my-glm" {
		t.Fatalf("list form: %v", m)
	}
}

func TestApplyHiddenModelsByFacingAndRaw(t *testing.T) {
	resetLocalizeState()
	seedDisplay("qfmodel", "Qwen3.8-Flash")
	setHiddenModels([]string{"qwen3-8-flash", "gmodel"})
	in := []pluginapi.ModelInfo{
		{ID: "qfmodel", DisplayName: "Qwen3.8-Flash"},
		{ID: "gmodel", DisplayName: "GLM-5.3"},
		{ID: "qwen3-8-max", Name: "qmodel_38max"},
	}
	out := applyHiddenModels(in)
	if len(out) != 1 || out[0].ID != "qwen3-8-max" {
		t.Fatalf("hidden filter kept %+v", out)
	}
	setHiddenModels(nil)
}

func TestParseStringList(t *testing.T) {
	if got := parseStringList([]any{"a", " b "}); len(got) != 2 || got[1] != "b" {
		t.Fatalf("list: %v", got)
	}
	if got := parseStringList("[x, \"y\"]"); len(got) != 2 || got[1] != "y" {
		t.Fatalf("inline: %v", got)
	}
}

// localize_keep_originals=false must drop the raw keys from the published
// catalog, not just from the localize pass.
func TestPublishCatalogDropsRawWhenKeepOff(t *testing.T) {
	resetLocalizeState()
	setModelIDOverrides(map[string]string{})
	setLocalizeConfig(true, false, map[string]string{})
	seedDisplay("qfmodel", "Qwen3.8-Flash")
	seedDisplay("auto", "auto") // self-named: keeps its raw id
	out := publishCatalog([]pluginapi.ModelInfo{
		{ID: "qfmodel", DisplayName: "Qwen3.8-Flash"},
		{ID: "auto", Name: "auto"},
	})
	ids := map[string]bool{}
	for _, m := range out {
		ids[m.ID] = true
	}
	if ids["qfmodel"] {
		t.Fatalf("raw key published with keep off: %v", ids)
	}
	if !ids["qwen3-8-flash"] || !ids["auto"] {
		t.Fatalf("expected friendly id and the unfriendly raw id: %v", ids)
	}
	setLocalizeConfig(true, true, map[string]string{})
}

// The panel list marks plugin-hidden models instead of dropping them, so the
// admin can always see what is hidden and restore it.
func TestModelGroupEntriesMarksHidden(t *testing.T) {
	resetLocalizeState()
	seedDisplay("qfmodel", "Qwen3.8-Flash")
	seedDisplay("gmodel", "GLM-5.3")
	setHiddenModels([]string{"gmodel"})
	got := modelGroupEntries("cn", []pluginapi.ModelInfo{
		{ID: "qfmodel", DisplayName: "Qwen3.8-Flash"},
		{ID: "gmodel", DisplayName: "GLM-5.3"},
	})
	if got[0].Hidden || got[0].ID != "qwen3-8-flash" {
		t.Fatalf("unhidden entry = %+v", got[0])
	}
	if !got[1].Hidden || got[1].Upstream != "gmodel" {
		t.Fatalf("hidden entry = %+v", got[1])
	}
	setHiddenModels(nil)
}
