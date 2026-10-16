// models.go implements the ModelProvider capability: the pinned GLM coding
// plan catalog (TriDefender/zcode-api src/provider/models.ts — hardcoded to
// the exact models available on the Z.AI / Bigmodel coding-plan tier), the
// four narrowing filters, and the pipeline that composes them.
//
// The filter ORDER is load-bearing, not incidental. Plan, off-peak and cooling
// all narrow a credential's real serving set and all key on the model ID, so
// they must run BEFORE aliases exist (model_policy.go): an alias carries its own
// ID, so a filter running after injection could not see that the alias's target
// was dropped, and the alias would keep offering a model the credential cannot
// serve. Aliases and the display prefix are therefore applied once the serving
// set is final.
//
// Exclusion is the exception and runs LAST, because it is the one filter whose
// input is text the operator typed rather than state the plugin derived — see
// filterExcludedModels for why that makes it match three spellings at once.
package main

import (
	"encoding/json"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// zcodeModels is the pinned GLM catalog (specs synced to the ZCode 3.11.2
// catalog by the reference project; glm-5.2 kept for forwarding
// compatibility, glm-5.3-flash serves claimed trial plans).
func zcodeModels() []pluginapi.ModelInfo {
	specs := []struct {
		id      string
		name    string
		context int64
		maxOut  int64
		reason  bool
	}{
		{"glm-4.5-air", "GLM 4.5 Air", 131072, 98304, true},
		{"glm-4.6", "GLM 4.6", 200000, 131072, true},
		{"glm-4.6v", "GLM 4.6V", 131072, 32768, false},
		{"glm-4.7", "GLM 4.7", 200000, 131072, true},
		{"glm-5", "GLM 5", 200000, 64000, true},
		{"glm-5-turbo", "GLM 5 Turbo", 200000, 64000, true},
		{"glm-5v-turbo", "GLM 5V Turbo", 200000, 131072, false},
		{"glm-5.1", "GLM 5.1", 200000, 64000, true},
		{"glm-5.2", "GLM 5.2", 1000000, 128000, true},
		{"glm-5.3", "GLM 5.3", 1000000, 128000, true},
		{"glm-5.3-flash", "GLM 5.3 Flash", 1000000, 128000, true},
	}
	out := make([]pluginapi.ModelInfo, 0, len(specs))
	for _, s := range specs {
		out = append(out, pluginapi.ModelInfo{
			ID:                         s.id,
			Name:                       s.name,
			ContextLength:              s.context,
			MaxCompletionTokens:        s.maxOut,
			OwnedBy:                    providerName,
			SupportedGenerationMethods: []string{"chat"},
		})
	}
	return out
}

// filterCoolingModels removes models currently cooling for THIS credential
// (per-model cooldown) so the host's built-in scheduler is never offered a
// degraded (auth, model) pair.
func filterCoolingModels(sa *storedAuth, models []pluginapi.ModelInfo) []pluginapi.ModelInfo {
	authID := cooldownAuthIDFor(sa)
	if authID == "" || len(models) == 0 || len(cooldownSnapshotFor(authID)) == 0 {
		return models
	}
	out := make([]pluginapi.ModelInfo, 0, len(models))
	for _, m := range models {
		if modelIsCooling(authID, m.ID) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// modelIsExcludedBy reports whether the oauth-excluded-models list bans a model.
// Matching is THREE-way on purpose, because the operator types whatever name the
// panel showed them and the catalog can show one model under three:
//
//	id                   the advertised id, e.g. "zcode/gpt-4o"   (panel picker)
//	stripProviderPrefix  the catalog/alias name, e.g. "gpt-4o"    (bare config)
//	resolveUpstreamModel the upstream id, e.g. "glm-4.6"          (Z.AI's own name)
//
// The middle term is what lets banning an alias remove the ALIAS and not its
// target: an alias resolves to its target, but its stripped name is its own. So
// "gpt-4o" bans gpt-4o alone, while "glm-4.6" bans the model and every alias
// pointing at it. One term could not express both, and hand-written bare ids
// (the pre-existing config shape) keep working through the same path.
func modelIsExcludedBy(id string, excluded map[string]struct{}) bool {
	if len(excluded) == 0 || id == "" {
		return false
	}
	for _, name := range []string{id, stripProviderPrefix(id), resolveUpstreamModel(id)} {
		if _, hit := excluded[strings.ToLower(strings.TrimSpace(name))]; hit {
			return true
		}
	}
	return false
}

// filterExcludedModels removes models listed in oauth-excluded-models for the
// zcode provider. The host passes this config via HostConfigSummary.
//
// Run it AFTER decorateCatalog: at that point every model is advertised under
// the name the operator saw when deciding to ban it.
func filterExcludedModels(models []pluginapi.ModelInfo, host pluginapi.HostConfigSummary) []pluginapi.ModelInfo {
	if len(host.ExcludedModels) == 0 {
		return models
	}
	excluded := host.ExcludedModels[providerName]
	if len(excluded) == 0 {
		for channel, list := range host.ExcludedModels {
			if strings.EqualFold(strings.TrimSpace(channel), providerName) {
				excluded = list
				break
			}
		}
	}
	if len(excluded) == 0 {
		return models
	}
	excludeSet := make(map[string]struct{}, len(excluded))
	for _, m := range excluded {
		excludeSet[strings.ToLower(strings.TrimSpace(m))] = struct{}{}
	}
	// Fresh slice — models[:0] would alias the input's backing array (the
	// static catalog) and corrupt it for subsequent callers.
	out := make([]pluginapi.ModelInfo, 0, len(models))
	for _, m := range models {
		if modelIsExcludedBy(m.ID, excludeSet) {
			continue
		}
		out = append(out, m)
	}
	return out
}

func handleModelStatic(raw []byte) ([]byte, error) {
	var req pluginapi.StaticModelRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	models := filterExcludedModels(decorateCatalog(zcodeModels()), req.Host)
	return okEnvelope(pluginapi.ModelResponse{Provider: providerName, Models: models})
}

// filterPlanModels narrows the catalog to the models the credential's plan
// tier actually serves. The start-plan (trial) gateway officially serves
// GLM-5.3-Flash / GLM-5.2 / GLM-5-Turbo (open-source zcode-builtin catalog:
// "start-plan 仅 GLM-5.3-Flash/5.2/5-Turbo — 按 plan 过滤有官方依据");
// coding-plan accounts keep the full pinned catalog.
func filterPlanModels(sa *storedAuth, models []pluginapi.ModelInfo) []pluginapi.ModelInfo {
	if sa == nil || sa.Auth.Plan != planStart {
		return models
	}
	out := make([]pluginapi.ModelInfo, 0, len(models))
	for _, m := range models {
		if _, ok := startPlanModelIDs[strings.ToLower(m.ID)]; ok {
			out = append(out, m)
		}
	}
	return out
}

func handleModelForAuth(raw []byte) ([]byte, error) {
	var req pluginapi.AuthModelRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	// Always return the plugin's canonical provider key — the host skips any
	// response whose Provider doesn't match the auth's provider.
	models := zcodeModels()
	if sa, err := parseStored(req.StorageJSON); err == nil {
		models = filterPlanModels(sa, models)
		// Off-peak lane serves its own (much narrower) model set — narrow the
		// catalog so the host only offers models the ticketed gateway accepts.
		if offPeakEligible(sa) {
			models = filterOffPeakModels(models)
		}
		// Cooling is per-(auth, model) and keyed on the ID, so it too runs
		// before aliases exist. Dropping the target first removes its alias with
		// it, which is the honest catalog: the pair is degraded upstream under
		// whatever name the client uses for it.
		models = filterCoolingModels(sa, models)
		// A risk-control pause is account-wide, so the honest catalog is empty:
		// every model would be rejected by the same gate, ahead of model
		// selection. Returning no models is the host's own "this credential has
		// nothing to serve" signal, which takes the account out of rotation
		// without the plugin touching the operator's disabled flag (risk.go).
		if riskBlocksAuth(cooldownAuthIDFor(sa)) {
			models = nil
		}
		// Both credentials rejected by the upstream and only a re-login clears
		// them (cred_state.go): the honest catalog is empty. Same signal
		// riskBlocksAuth uses, and for the same reason — it takes the account out
		// of rotation without the plugin touching the operator's disabled flag.
		// A park that clears itself (rate limit, captcha challenge) is
		// deliberately NOT included: emptying the catalog for a minute of
		// throttling would fight the cooldown machinery instead of helping it.
		if credCannotServe(cooldownAuthIDFor(sa), sa) {
			models = nil
		}
	}
	// Names first, then the ban list — see filterExcludedModels.
	models = filterExcludedModels(decorateCatalog(models), req.Host)
	return okEnvelope(pluginapi.ModelResponse{Provider: providerName, Models: models})
}
