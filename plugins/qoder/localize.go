// localize.go — v0.8.69: human-facing model ids for the qoder channel.
//
// Qoder's upstream catalog uses opaque keys (qfmodel, qmodel_38max, keyed by
// model_display_name: Qwen3.8-Flash, GLM-5.3 …). Clients, logs and the panel
// kept showing the opaque key. With `localize` on (default) the plugin:
//
//   - publishes the catalog under the display-name slug (qwen3-8-flash,
//     glm-5-3, …) to the host, and
//
//   - maps an incoming slug request back to the raw upstream key.
//
//     config.yaml → plugins.configs.qoder:
//     localize: true                 # default; false restores the raw keys
//     localize_keep_originals: false # true keeps qfmodel etc. as extra ids
//     models:                        # optional manual overrides
//
//   - {id: qfmodel, alias: qwen3.8-flash}
//
// CPA's own `oauth-model-alias` table is not used on purpose: it only
// renames a model when the client already asked for an id it knows, so it
// cannot replace an id wholesale (and the host keys that table by its
// internal auth kind, not by the plugin id).
package main

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var (
	localizeMu            sync.RWMutex
	localizeOn            = true
	localizeKeep          = true
	localizeConfig        = map[string]string{} // raw id → configured alias
	localizeDisplay       = map[string]string{} // raw id → display name (catalog)
	localizeOnce          sync.Once
	localizePackageLogged sync.Map
)

// localizeEnabled reports the effective switch (QD_LOCALIZE overrides config).
func localizeEnabled() bool {
	localizeOnce.Do(func() {
		if v, ok := os.LookupEnv("QD_LOCALIZE"); ok {
			localizeMu.Lock()
			localizeOn = parseBoolish(v)
			localizeMu.Unlock()
			logLocalizeOnce("qoder: localize set by QD_LOCALIZE=" + v)
		}
	})
	localizeMu.RLock()
	defer localizeMu.RUnlock()
	return localizeOn
}

func parseBoolish(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// localizeSlug turns a display name into a request-safe model id:
// lower-case, every non-alphanumeric run collapsed to '-', edge dashes
// trimmed. "Qwen3.8-Flash" → "qwen3-8-flash", "GLM-5.3" → "glm-5-3".
func localizeSlug(name string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// knownRawModels is the set of upstream keys the plugin knows about (static
// table + the refreshed catalog). A display name is only localized for these:
// a generic label like "Auto" must neither create an "auto" alias collision
// nor hide the raw key.
func knownRawModels() map[string]bool {
	out := map[string]bool{}
	for _, m := range wbModels() {
		out[strings.ToLower(m.ID)] = true
	}
	// Persisted snapshots of every qoder credential (the panel's source too).
	if files, err := hostAuthListFn(); err == nil {
		for _, f := range files {
			if !strings.HasPrefix(strings.ToLower(f.Name), providerName+"-") {
				continue
			}
			raw, gerr := hostAuthGetByIndex(f.AuthIndex)
			if gerr != nil {
				continue
			}
			if snap := readModelCacheDoc(raw); snap != nil {
				for _, m := range snap.Models {
					out[strings.ToLower(m.ID)] = true
				}
			}
		}
	}
	return out
}

// localizeMapLocked builds raw → facing from the current state. Caller holds
// localizeMu.
var (
	localizeKnownMu    sync.Mutex
	localizeKnownSet   map[string]bool
	localizeKnownCount int
)

// knownRawModelsCached caches the raw-key set; it refreshes when the catalog
// grows. host RPCs run without localizeMu held (they are not cheap).
func knownRawModelsCached() map[string]bool {
	localizeKnownMu.Lock()
	defer localizeKnownMu.Unlock()
	cur := knownRawModels()
	if localizeKnownSet == nil || len(cur) != localizeKnownCount {
		localizeKnownSet = cur
		localizeKnownCount = len(cur)
	}
	return localizeKnownSet
}

func localizeMapLocked(known map[string]bool) map[string]string {
	out := map[string]string{}
	used := map[string]string{}
	for raw, display := range localizeDisplay {
		if !known[strings.ToLower(raw)] {
			continue
		}
		facing := ""
		if a := strings.TrimSpace(localizeConfig[raw]); a != "" {
			facing = a
		} else if s := localizeSlug(display); s != "" {
			facing = s
		}
		if facing == "" {
			continue
		}
		key := strings.ToLower(facing)
		if other, dup := used[key]; dup && !strings.EqualFold(other, raw) {
			continue // collision: first raw key keeps the slug
		}
		used[key] = raw
		out[raw] = facing
	}
	// Manual overrides always win, even when the display name is unknown.
	for raw, a := range localizeConfig {
		if a = strings.TrimSpace(a); a != "" {
			out[raw] = a
		}
	}
	return out
}

// modelIDOverrides holds the user's raw → facing id table (config
// `model_ids`). An override beats the display-name slug and also applies
// with localize off (it is an id change, not a localize).
var (
	modelIDsMu       sync.RWMutex
	modelIDOverrides = map[string]string{}
)

// modelIDMapLocked applies overrides on top of the localize map.
func modelIDMapLocked(known map[string]bool) map[string]string {
	lm := localizeMapLocked(known)
	modelIDsMu.RLock()
	defer modelIDsMu.RUnlock()
	for raw, custom := range modelIDOverrides {
		raw, custom = strings.TrimSpace(raw), strings.TrimSpace(custom)
		if raw != "" && custom != "" {
			lm[raw] = custom
		}
	}
	return lm
}

// rawExcludedForHost is the host exclusion set with every id mapped back to
// the raw key, so a list written as qwen3-8-flash (or with a custom id)
// hides qfmodel too.
func rawExcludedForHost(host pluginapi.HostConfigSummary, keys ...string) []string {
	out, _ := syncListToRawIds(excludedModelsForKeys(host, keys...))
	return out
}

// syncListToRawIds translates client-facing ids in a hidden/excluded list
// back to the raw upstream keys the plugin filters with. Reporting `changed`
// lets a caller persist the normalized form; nothing here writes config.
func syncListToRawIds(ids []string) (out []string, changed bool) {
	known := knownRawModelsCached()
	localizeMu.RLock()
	lm := modelIDMapLocked(known)
	localizeMu.RUnlock()
	byFacing := make(map[string]string, len(lm))
	for raw, facing := range lm {
		byFacing[strings.ToLower(facing)] = raw
	}
	out = make([]string, 0, len(ids))
	for _, id := range ids {
		t := strings.TrimSpace(id)
		if t == "" {
			continue
		}
		if raw, ok := byFacing[strings.ToLower(t)]; ok {
			if raw != t {
				changed = true
			}
			out = append(out, raw)
			continue
		}
		out = append(out, t)
	}
	return out, changed
}

// setModelIDOverrides installs the config `model_ids` table (raw → custom).
func setModelIDOverrides(overrides map[string]string) {
	modelIDsMu.Lock()
	if overrides != nil {
		modelIDOverrides = overrides
	}
	modelIDsMu.Unlock()
}

// modelIDOverridesSnapshot copies the live table (v0.8.73) so a panel save can
// tell whether it actually changed anything before restarting CPA.
func modelIDOverridesSnapshot() map[string]string {
	modelIDsMu.RLock()
	defer modelIDsMu.RUnlock()
	out := make(map[string]string, len(modelIDOverrides))
	for k, v := range modelIDOverrides {
		out[k] = v
	}
	return out
}

// sameStringTable reports whether two raw→custom tables are identical.
func sameStringTable(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// modelIDOverridesSummary renders the override table for logs.
func modelIDOverridesSummary() string {
	modelIDsMu.RLock()
	defer modelIDsMu.RUnlock()
	keys := make([]string, 0, len(modelIDOverrides))
	for k := range modelIDOverrides {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+modelIDOverrides[k])
	}
	return strings.Join(parts, ",")
}

// localizeFacingFor returns the client-facing id for a raw key.
func localizeFacingFor(raw string) string {
	known := knownRawModelsCached()
	if !localizeEnabled() {
		// Explicit ids still apply; display-name slugs do not.
		modelIDsMu.RLock()
		custom := strings.TrimSpace(modelIDOverrides[raw])
		modelIDsMu.RUnlock()
		if custom != "" {
			return custom
		}
		return raw
	}
	localizeMu.RLock()
	defer localizeMu.RUnlock()
	if f, ok := modelIDMapLocked(known)[raw]; ok {
		return f
	}
	return raw
}

// publishCatalog prepares a plugin catalog for the host: records display
// names, then publishes both the friendly ids and the raw keys (v0.8.69
// default) so existing clients keep working — the host only routes ids the
// plugin registered, so a raw key that is not published is simply unknown.
func publishCatalog(models []pluginapi.ModelInfo) []pluginapi.ModelInfo {
	noteCatalogDisplays(models)
	models = applyHiddenModels(models)
	localized := localizedModels(models)
	if !localizeEnabled() {
		return localized
	}
	localizeMu.RLock()
	keep := localizeKeep
	localizeMu.RUnlock()
	seen := make(map[string]bool, len(localized))
	out := make([]pluginapi.ModelInfo, 0, len(localized)+len(models))
	for _, m := range localized {
		seen[strings.ToLower(m.ID)] = true
		out = append(out, m)
	}
	if !keep {
		// v0.8.71: localize_keep_originals=false means the raw keys are NOT
		// published — this second pass used to append them unconditionally,
		// so qfmodel/qmodel_38max stayed in /v1/models. Only raw ids that
		// have no friendly form get appended here.
		for _, m := range models {
			if m.ID == "" || seen[strings.ToLower(m.ID)] {
				continue
			}
			if !strings.EqualFold(localizeFacingFor(m.ID), m.ID) {
				continue
			}
			seen[strings.ToLower(m.ID)] = true
			out = append(out, m)
		}
		return out
	}
	for _, m := range models {
		if m.ID == "" || seen[strings.ToLower(m.ID)] {
			continue
		}
		seen[strings.ToLower(m.ID)] = true
		out = append(out, m)
	}
	return out
}

// resolveLocalizedModel maps a client-facing slug (or a configured alias) back
// to the raw upstream key. Raw keys and unknown ids pass through unchanged.
func resolveLocalizedModel(model string) string {
	m := strings.TrimSpace(model)
	if m == "" {
		return model
	}
	known := knownRawModelsCached()
	localizeMu.RLock()
	defer localizeMu.RUnlock()
	lm := modelIDMapLocked(known)
	for raw, facing := range lm {
		if strings.EqualFold(facing, m) {
			return raw
		}
	}
	if _, ok := lm[m]; ok {
		return m // already a raw key that has a facing
	}
	return model
}

// localizedModels rewrites a provider catalog for publication: ID becomes the
// client-facing id, DisplayName becomes the display name and Name becomes the
// raw upstream key (the host sends it back as the upstream model). Entries
// without a display-name mapping keep their raw id.
func localizedModels(models []pluginapi.ModelInfo) []pluginapi.ModelInfo {
	if !localizeEnabled() || len(models) == 0 {
		return models
	}
	localizeMu.RLock()
	keep := localizeKeep
	localizeMu.RUnlock()
	out := make([]pluginapi.ModelInfo, 0, len(models)*2)
	seen := map[string]bool{}
	for _, m := range models {
		raw := m.ID
		if raw == "" {
			continue
		}
		facing := localizeFacingFor(raw)
		if keep && !strings.EqualFold(facing, raw) && !seen[strings.ToLower(raw)] {
			seen[strings.ToLower(raw)] = true
			out = append(out, m)
		}
		clone := m
		clone.ID = facing
		clone.Name = raw
		if strings.EqualFold(facing, raw) {
			clone.Name = m.Name
		}
		if seen[strings.ToLower(clone.ID)] {
			continue
		}
		seen[strings.ToLower(clone.ID)] = true
		out = append(out, clone)
		if !strings.EqualFold(facing, raw) {
			logLocalizeOnce(fmt.Sprintf("qoder: localize %s → %s (rest of the table logged once)", raw, facing))
		}
	}
	return out
}

func logLocalizeOnce(msg string) {
	if _, loaded := localizePackageLogged.LoadOrStore(msg, true); !loaded {
		log.Printf("%s", msg)
	}
}

// noteCatalogDisplays records raw id → display name from a served catalog so
// requests can be mapped back before any discovery ran this process.
func noteCatalogDisplays(models []pluginapi.ModelInfo) {
	if len(models) == 0 {
		return
	}
	localizeMu.Lock()
	defer localizeMu.Unlock()
	for _, m := range models {
		if m.ID == "" {
			continue
		}
		if _, done := localizeDisplay[m.ID]; done {
			continue
		}
		name := m.DisplayName
		if strings.TrimSpace(name) == "" {
			name = m.Name
		}
		// v0.8.69: only names that differ from the raw key are display names.
		// The static table spells the fallback label as the key and
		// auto-discovery may report the key as its own label; localizing
		// either would churn ids for nothing.
		if strings.TrimSpace(name) != "" && !strings.EqualFold(strings.TrimSpace(name), m.ID) {
			localizeDisplay[m.ID] = name
		}
	}
}

// setLocalizeConfig stores the effective switch and overrides (configure()).
func setLocalizeConfig(on, keep bool, overrides map[string]string) {
	localizeMu.Lock()
	localizeOn, localizeKeep = on, keep
	if overrides != nil {
		localizeConfig = overrides
	}
	localizeMu.Unlock()
	if !on {
		logLocalizeOnce("qoder: localize off — raw upstream model ids are published")
	}
	if s := localizeOverridesSummary(); s != "" {
		logLocalizeOnce("qoder: localize overrides " + s)
	}
}

// localizeOverridesSummary renders the override table for logs/tests.
func localizeOverridesSummary() string {
	localizeMu.RLock()
	defer localizeMu.RUnlock()
	keys := make([]string, 0, len(localizeConfig))
	for k := range localizeConfig {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+localizeConfig[k])
	}
	return strings.Join(parts, ",")
}

// resetLocalizeState clears the cached catalog mapping (tests).
func resetLocalizeState() {
	localizeMu.Lock()
	localizeDisplay = map[string]string{}
	localizeConfig = map[string]string{}
	localizeOn, localizeKeep = true, true
	localizeMu.Unlock()
}

// parseLocalizeOverrides reads the config `models` list into raw→alias pairs.
// Accepts [{id,name,alias}] or a raw `[]any` from YAML; entries without a
// usable alias are ignored.
func parseLocalizeOverrides(v any) map[string]string {
	out := map[string]string{}
	addOne := func(id, alias string) {
		id, alias = strings.TrimSpace(id), strings.TrimSpace(alias)
		if id != "" && alias != "" {
			out[id] = alias
		}
	}
	switch t := v.(type) {
	case []any:
		for _, it := range t {
			if m, ok := it.(map[string]any); ok {
				addOne(configScalarString(m["id"]), configScalarString(m["alias"]))
			}
		}
	case map[string]any:
		for id, alias := range t {
			addOne(id, configScalarString(alias))
		}
	}
	return out
}

// normalizedHiddenList translates a hidden-model list to raw keys for the
// admin rewrite (client only: nothing here touches config).
func normalizedHiddenList(ids []string) []string {
	out, _ := syncListToRawIds(ids)
	return out
}

// parseModelIDTable reads `model_ids` (raw → custom facing id). Accepts a YAML
// map or a list of {id|name, alias|id}.
func parseModelIDTable(v any) map[string]string {
	out := map[string]string{}
	addOne := func(raw, custom string) {
		raw, custom = strings.TrimSpace(raw), strings.TrimSpace(custom)
		if raw != "" && custom != "" {
			out[raw] = custom
		}
	}
	switch t := v.(type) {
	case map[string]any:
		for raw, custom := range t {
			addOne(raw, configScalarString(custom))
		}
	case []any:
		for _, it := range t {
			m, ok := it.(map[string]any)
			if !ok {
				continue
			}
			raw := configScalarString(m["id"])
			if raw == "" {
				raw = configScalarString(m["name"])
			}
			custom := configScalarString(m["alias"])
			if custom == "" {
				custom = configScalarString(m["id_to"])
			}
			if custom == "" {
				custom = configScalarString(m["to"])
			}
			addOne(raw, custom)
		}
	}
	return out
}

// Hidden-model support (v0.8.70): `hidden_models` is a plugin-level list that
// is applied to every catalog the plugin publishes, in addition to the
// host's oauth-excluded-models. Entries may be client-facing ids; they are
// mapped back to raw keys before filtering.
var (
	hiddenMu      sync.RWMutex
	hiddenModels  []string
	hiddenApplied = map[string]bool{}
)

func setHiddenModels(ids []string) {
	out, _ := syncListToRawIds(ids)
	hiddenMu.Lock()
	hiddenModels = out
	hiddenMu.Unlock()
	if len(out) > 0 {
		log.Printf("qoder: hidden_models=%v (raw keys)", out)
	}
}

// hiddenRawSet returns the hidden raw keys, translating any client-facing ids
// lazily (the catalog may not be known when config loads).
func hiddenRawSet() map[string]bool {
	hiddenMu.RLock()
	cur := hiddenModels
	hiddenMu.RUnlock()
	if len(cur) == 0 {
		return nil
	}
	out := make(map[string]bool, len(cur))
	for _, id := range cur {
		for _, raw := range hiddenToRaw(id) {
			out[raw] = true
		}
	}
	return out
}

// hiddenToRaw expands one hidden entry to every raw key it denotes. A
// display-name slug hides its raw key; a raw key hides itself; the slug
// derived from a raw key (qmodel_38max → qwen3-8-max) is also honoured so a
// hand-written list works before discovery has seen the catalog.
func hiddenToRaw(entry string) []string {
	e := strings.ToLower(strings.TrimSpace(entry))
	if e == "" {
		return nil
	}
	res := []string{e}
	localizeMu.RLock()
	for raw, display := range localizeDisplay {
		facing := localizeSlug(display)
		if facing != "" && facing == e && !strings.EqualFold(raw, e) {
			res = append(res, strings.ToLower(raw))
		}
	}
	localizeMu.RUnlock()
	return res
}

// applyHiddenModels drops hidden raw keys from a catalog (identity-derived
// ids are matched through the same map, so hiding qfmodel hides its slug).
func applyHiddenModels(models []pluginapi.ModelInfo) []pluginapi.ModelInfo {
	set := hiddenRawSet()
	if len(set) == 0 || len(models) == 0 {
		return models
	}
	// Only raw keys of KNOWN models count: hiding "auto" (a label the upstream
	// also uses) must not swallow every alias-derived "auto" entry — the
	// static table spells those ids exactly as their display names.
	known := knownRawModelsCached()
	out := make([]pluginapi.ModelInfo, 0, len(models))
	for _, m := range models {
		raw := m.ID
		if m.Name != "" && !strings.EqualFold(m.Name, m.ID) {
			raw = m.Name // localized/published entry: Name carries the raw key
		}
		if set[strings.ToLower(raw)] || (known[strings.ToLower(raw)] && set[strings.ToLower(m.ID)] && strings.EqualFold(raw, m.ID)) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// parseStringList reads a YAML list of scalars into a []string.
func parseStringList(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, it := range t {
			if s := strings.TrimSpace(configScalarString(it)); s != "" {
				out = append(out, s)
			}
		}
	case string:
		// YAML inline list ("[a, b]") or comma-separated.
		s := strings.TrimSpace(t)
		s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
		for _, p := range strings.Split(s, ",") {
			if x := strings.Trim(strings.TrimSpace(p), "\"'"); x != "" {
				out = append(out, x)
			}
		}
	}
	return out
}
