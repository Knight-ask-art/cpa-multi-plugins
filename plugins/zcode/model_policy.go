// model_policy.go is the layer between the pinned upstream catalog (models.go)
// and the names a client sees: what the catalog advertises (model_prefix), what
// those names mean upstream (model_map), and how many output tokens a request
// may ask for (max_tokens).
//
// It exists because two needs conflict at that boundary. The CLIENT wants names
// it already knows — a tool configured for "gpt-4o" should just work — while the
// UPSTREAM accepts only its own ids. Resolving that at the edge, in one place,
// beats teaching the translator about aliases.
//
// Both halves are required and neither works alone. An alias missing from the
// catalog is a model the client cannot select (and, on most CPA setups, a
// request the host rejects before it reaches the executor); an alias in the
// catalog that the executor does not translate is a request the upstream 404s.
// So one table feeds both: withAliases publishes it, resolveUpstreamModel
// consumes it.
//
// The prefix is the other half of naming. CPA front-ends routinely display
// several providers side by side, and two of them offering "glm-5.3" is a
// routing ambiguity the user has to resolve by hand; a prefix makes the origin
// part of the name. stripProviderPrefix already removes any "<x>/" segment, so
// the executor needed no change to accept prefixed ids — only the catalog had
// to start emitting them.
package main

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var (
	modelPolicyMu  sync.RWMutex
	modelPrefix    = ""
	modelAliases   = map[string]string{}
	modelMaxTokens int64
)

// modelPolicyConfig is the decoded model policy, one field per config key.
type modelPolicyConfig struct {
	prefix    string
	aliases   map[string]string
	maxTokens int64
}

// configureModelPolicy installs a decoded policy. Called from configure() on
// every register/reconfigure.
func configureModelPolicy(cfg modelPolicyConfig) {
	aliases := cfg.aliases
	if aliases == nil {
		aliases = map[string]string{}
	}
	modelPolicyMu.Lock()
	modelPrefix = strings.TrimSpace(cfg.prefix)
	modelAliases = aliases
	modelMaxTokens = cfg.maxTokens
	modelPolicyMu.Unlock()
}

// loadedModelPolicy returns a copy of the current policy, so a caller iterating
// the alias table cannot race a reconfigure.
func loadedModelPolicy() modelPolicyConfig {
	modelPolicyMu.RLock()
	defer modelPolicyMu.RUnlock()
	aliases := make(map[string]string, len(modelAliases))
	for k, v := range modelAliases {
		aliases[k] = v
	}
	return modelPolicyConfig{prefix: modelPrefix, aliases: aliases, maxTokens: modelMaxTokens}
}

// loadedModelMaxTokens is the output-token ceiling; 0 means none.
func loadedModelMaxTokens() int64 {
	modelPolicyMu.RLock()
	defer modelPolicyMu.RUnlock()
	return modelMaxTokens
}

// normalizeModelAlias canonicalizes an alias key. Aliases are matched
// case-insensitively because model ids in the wild are written every which way
// ("GPT-4o", "gpt-4o") and a mapping that silently misses on case would be
// indistinguishable from a mapping that was never configured.
func normalizeModelAlias(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// catalogModelIDs is the pinned catalog as a lowercase set, built once. It is
// what lets resolveUpstreamModel refuse to let an alias shadow a real model id.
var catalogModelIDs = sync.OnceValue(func() map[string]struct{} {
	ids := zcodeModels()
	out := make(map[string]struct{}, len(ids))
	for _, m := range ids {
		out[strings.ToLower(m.ID)] = struct{}{}
	}
	return out
})

// isCatalogModelID reports whether name is one of the pinned upstream ids.
func isCatalogModelID(name string) bool {
	_, ok := catalogModelIDs()[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// modelAliasLookup resolves a client-facing name to its upstream model id.
func modelAliasLookup(name string) (string, bool) {
	key := normalizeModelAlias(name)
	if key == "" {
		return "", false
	}
	modelPolicyMu.RLock()
	defer modelPolicyMu.RUnlock()
	target, ok := modelAliases[key]
	return target, ok
}

// resolveUpstreamModel turns the model the client asked for into the id the
// upstream is given: strip the display prefix, then apply the alias table.
//
// The alias lookup is tried against the RAW name FIRST. An alias may itself be
// namespaced ("openai/gpt-4o"), and stripping before the lookup would make that
// entry unreachable — the strip is unconditional (stripProviderPrefix removes
// any "<x>/" segment), so it cannot tell an operator's alias from a provider
// prefix. Falling back to the stripped form afterwards covers the ordinary case
// where the client sends "<prefix>/<alias>".
//
// A real catalog id is NEVER rewritten, even when the alias table names it. The
// catalog would keep advertising the genuine model (withAliases refuses a
// colliding alias too), so rewriting here would mean the panel said "glm-4.6"
// while the upstream received "glm-5.3" — the one failure mode a mapping layer
// must not have. It also makes this function idempotent for catalog ids, which
// matters because cooldown keys pass through it twice on some paths.
//
// Resolution is single-hop by construction: the returned target is not looked up
// again, so a→b, b→c cannot chain.
func resolveUpstreamModel(requested string) string {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return requested
	}
	isCatalog := isCatalogModelID(requested)
	if !isCatalog {
		if target, ok := modelAliasLookup(requested); ok {
			return target
		}
	}
	bare := stripProviderPrefix(requested)
	if bare == requested {
		return requested
	}
	if !isCatalog && !isCatalogModelID(bare) {
		if target, ok := modelAliasLookup(bare); ok {
			return target
		}
	}
	return bare
}

// withAliases publishes the alias table in the catalog: one entry per alias
// whose TARGET is still present in models.
//
// The target check is what keeps an alias from smuggling a model back into a
// catalog that intentionally dropped it — a start-plan credential must not be
// offered "gpt-4o" merely because gpt-4o was mapped to glm-5.3, when glm-5.3
// itself was filtered out by the plan tier. Callers therefore inject aliases
// AFTER the plan/off-peak filters, never before.
//
// The alias entry inherits the target's context window and output ceiling so a
// client's own validation sees a coherent model record, and it gets the target's
// name in parentheses so the panel's exclusion picker shows what it resolves to.
func withAliases(models []pluginapi.ModelInfo, aliases map[string]string) []pluginapi.ModelInfo {
	if len(aliases) == 0 || len(models) == 0 {
		return models
	}
	byID := make(map[string]pluginapi.ModelInfo, len(models))
	for _, m := range models {
		byID[strings.ToLower(m.ID)] = m
	}
	// Sorted so the catalog is stable across calls — map order would reshuffle
	// the host's model list on every request.
	names := make([]string, 0, len(aliases))
	for alias := range aliases {
		names = append(names, alias)
	}
	sort.Strings(names)

	out := make([]pluginapi.ModelInfo, 0, len(models)+len(names))
	out = append(out, models...)
	for _, alias := range names {
		target, ok := byID[alias]
		if ok {
			// The alias collides with a real model id; the real one wins, since
			// hiding it would make the model unselectable.
			_ = target
			continue
		}
		spec, ok := byID[normalizeModelAlias(aliases[alias])]
		if !ok {
			continue
		}
		entry := spec
		entry.ID = alias
		entry.Name = alias + " (" + spec.Name + ")"
		entry.OwnedBy = providerName
		out = append(out, entry)
	}
	return out
}

// applyModelPrefix namespaces every catalog id with the configured prefix.
func applyModelPrefix(models []pluginapi.ModelInfo, prefix string) []pluginapi.ModelInfo {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || len(models) == 0 {
		return models
	}
	prefix = strings.TrimSuffix(prefix, "/") + "/"
	out := make([]pluginapi.ModelInfo, 0, len(models))
	for _, m := range models {
		// Idempotent: an id that already carries the prefix is left alone, so a
		// second pass cannot produce "p/p/glm-5.3".
		if !strings.HasPrefix(m.ID, prefix) {
			m.ID = prefix + m.ID
		}
		out = append(out, m)
	}
	return out
}

// decorateCatalog applies the whole naming policy to a credential's catalog.
// Order matters and is the reason this is one function rather than two calls at
// each site: aliases must be injected while the filters' decisions are still
// visible (see withAliases), then the prefix renames what survived.
func decorateCatalog(models []pluginapi.ModelInfo) []pluginapi.ModelInfo {
	policy := loadedModelPolicy()
	return applyModelPrefix(withAliases(models, policy.aliases), policy.prefix)
}

// -----------------------------------------------------------------------------
// output-token ceiling
// -----------------------------------------------------------------------------

// parseTokenCount reads a JSON number that may have arrived as int64 (built by
// the anthropic translator), float64 (goes through interface{}), or json.Number.
func parseTokenCount(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case int:
		return int64(t), true
	case float64:
		return int64(t), true
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return n, true
		}
	}
	return 0, false
}

// clampBodyMaxTokens lowers the output ceiling in a raw chat-completions body.
//
// Only ever LOWERS: a cap that raised a small request's max_tokens would change
// what the model produces, not just how much of it. A body with no max_tokens
// is left alone for the same reason — the upstream's own default is a better
// answer than one this plugin invents.
//
// max_completion_tokens is clamped alongside max_tokens because newer clients
// send that name for the same field; clamping one and not the other would make
// the cap trivially bypassable.
func clampBodyMaxTokens(obj map[string]json.RawMessage) {
	limit := loadedModelMaxTokens()
	if limit <= 0 {
		return
	}
	for _, key := range []string{"max_tokens", "max_completion_tokens"} {
		raw, present := obj[key]
		if !present {
			continue
		}
		var n int64
		// A null or a non-integer parses to an error or 0; both mean "not a
		// ceiling we can lower", so leave the field untouched.
		if err := json.Unmarshal(raw, &n); err != nil || n <= limit {
			continue
		}
		if b, err := json.Marshal(limit); err == nil {
			obj[key] = b
		}
	}
}

// clampAnthropicMaxTokens lowers max_tokens on a translated anthropic body.
//
// This runs at the END of the start-plan pipeline, after
// applyThinkingTranslation has folded a reasoning budget into max_tokens —
// clamping earlier would let the budget push the total back over the ceiling.
func clampAnthropicMaxTokens(body map[string]any) {
	limit := loadedModelMaxTokens()
	if limit <= 0 {
		return
	}
	n, ok := parseTokenCount(body["max_tokens"])
	if !ok || n <= limit {
		return
	}
	body["max_tokens"] = limit
}

// -----------------------------------------------------------------------------
// config decoding
// -----------------------------------------------------------------------------

// decodeModelPolicy reads model_prefix / model_map / model_max_tokens.
//
// model_map accepts two shapes on purpose. The nested-map form is what a YAML
// author writes naturally:
//
//	model_map:
//	  gpt-4o: glm-4.6
//
// The flat form exists because the raw-line scan can read it, so the key still
// works when the payload is not YAML at all — the same reason identity_* has
// two decode passes:
//
//	model_map: "gpt-4o=glm-4.6, claude-3-5-sonnet=glm-5.3"
//
// model_max_tokens is named for the plugin's model policy rather than reusing
// "max_tokens" so it cannot be mistaken for the per-request chat parameter of
// the same name in the host's config UI.
func decodeModelPolicy(configYAML []byte) modelPolicyConfig {
	var cfg modelPolicyConfig
	m, ok := decodePluginConfigYAML(configYAML)
	if ok {
		if v, present := m["model_prefix"]; present {
			cfg.prefix = configScalarString(v)
		}
		if v, present := m["model_map"]; present {
			cfg.aliases = decodeModelMap(v)
		}
		if v, present := m["model_max_tokens"]; present {
			if n, perr := strconv.ParseInt(configScalarString(v), 10, 64); perr == nil && n > 0 {
				cfg.maxTokens = n
			}
		}
	}
	// Line-scan fallback, for the flat forms only. Nested YAML cannot appear on
	// one line, so model_map's map shape is simply unavailable here — the map
	// pass above is the one that sees it.
	for _, rawLine := range strings.Split(string(configYAML), "\n") {
		line := strings.TrimSpace(rawLine)
		if prefix := "model_prefix:"; strings.HasPrefix(line, prefix) {
			cfg.prefix = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, prefix)), "\"'")
		}
		if prefix := "model_map:"; strings.HasPrefix(line, prefix) {
			raw := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, prefix)), "\"'")
			// A line starting with "{" or "[" is the flow form of a map, which
			// the YAML pass already decoded; re-parsing it here as CSV would
			// produce aliases named `{gpt-4o`.
			if raw != "" && !strings.HasPrefix(raw, "{") {
				if merged := decodeModelMap(raw); len(merged) > 0 {
					if cfg.aliases == nil {
						cfg.aliases = map[string]string{}
					}
					for k, v := range merged {
						cfg.aliases[k] = v
					}
				}
			}
		}
		if prefix := "model_max_tokens:"; strings.HasPrefix(line, prefix) {
			raw := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, prefix)), "\"'")
			if n, perr := strconv.ParseInt(raw, 10, 64); perr == nil && n > 0 {
				cfg.maxTokens = n
			}
		}
	}
	if cfg.aliases == nil {
		cfg.aliases = map[string]string{}
	}
	return cfg
}

// decodeModelMap accepts the map and the flat "alias=target, alias=target" form.
func decodeModelMap(v any) map[string]string {
	out := map[string]string{}
	add := func(alias, target string) {
		alias = normalizeModelAlias(alias)
		target = normalizeModelAlias(target)
		// A self-mapping is a no-op that would still add a duplicate catalog
		// entry, so drop it rather than publish "glm-5.3 (GLM 5.3)".
		if alias == "" || target == "" || alias == target {
			return
		}
		out[alias] = target
	}
	switch t := v.(type) {
	case string:
		for _, pair := range strings.Split(t, ",") {
			alias, target, ok := strings.Cut(pair, "=")
			if !ok {
				continue
			}
			add(alias, target)
		}
	case map[string]any:
		for alias, raw := range t {
			add(alias, configScalarString(raw))
		}
	default:
		// yaml.v3 hands nested maps back as map[string]any; anything else here
		// is a shape we do not claim to support, and silently ignoring it beats
		// guessing at a mapping the operator did not write.
	}
	return out
}

// modelPolicySnapshotForPanel renders the effective policy, including the
// mappings that will do NOTHING. A target that is not in the pinned catalog is
// a config typo that is otherwise completely silent — the alias simply never
// appears — so the panel names it.
func modelPolicySnapshotForPanel() map[string]any {
	policy := loadedModelPolicy()
	known := map[string]string{}
	for _, m := range zcodeModels() {
		known[normalizeModelAlias(m.ID)] = m.Name
	}
	rows := make([]map[string]string, 0, len(policy.aliases))
	unresolved := make([]string, 0)
	aliasNames := make([]string, 0, len(policy.aliases))
	for alias := range policy.aliases {
		aliasNames = append(aliasNames, alias)
	}
	sort.Strings(aliasNames)
	for _, alias := range aliasNames {
		target := policy.aliases[alias]
		name, ok := known[target]
		if !ok {
			unresolved = append(unresolved, alias+" → "+target)
			name = "（不在目录中）"
		}
		rows = append(rows, map[string]string{
			"alias": alias, "target": target, "target_name": name,
		})
	}
	sort.Strings(unresolved)
	return map[string]any{
		"prefix":     policy.prefix,
		"max_tokens": policy.maxTokens,
		"aliases":    rows,
		"count":      len(rows),
		"unresolved": unresolved,
		// Whether a pin is in play at all, so the panel can keep the healthy
		// default (no mapping configured) visually quiet.
		"active": policy.prefix != "" || len(rows) > 0 || policy.maxTokens > 0,
	}
}
