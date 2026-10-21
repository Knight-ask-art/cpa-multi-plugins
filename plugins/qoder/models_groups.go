// models_groups.go — v0.8.27: per-region model catalog endpoint for the
// panel's model-exclusion picker (GET /plugins/qoder/models/groups). Port of
// the workbuddy v0.9.40 design onto qoder's cn/intl region boundary.
//
// Why: the HOST's global oauth-excluded-models page cannot offer candidate
// lists for plugin channels (model-definitions/:channel is an upstream-static
// 8-channel catalog; unknown channels 400 "unknown channel"), so excluding a
// qoder model there meant hand-typing ids. This endpoint serves the catalog
// from the plugin's OWN knowledge — the per-credential model_cache snapshots
// (v0.8.27) — grouped by region, and the panel renders per-region checkboxes
// that write the host's qoder-<region> sub-keys via PATCH
// /v0/management/oauth-excluded-models. Consumption stays host-config-shaped
// (filterExcludedModelsForRegion), so the global page and this picker drive
// the SAME exclusion map — no parallel truth, nothing plugin-proprietary to
// persist.
//
// Read-only by default: groups are served from the newest model_cache
// snapshot per region (zero upstream calls). ?refresh=1 additionally runs one
// live discovery per region through fetchDynamicModelsFromStorage's full
// chain (cache → discover → peer → persisted), which also re-stamps the
// snapshot — the exact path model.for_auth uses, so what the picker shows and
// what the runtime advertises cannot diverge.
//
// The catalog (snapshot/discovery) is the PRE-exclusion full list, so
// excluded models remain visible and re-checkable — un-excluding never
// requires a lucky upstream round-trip.
package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// modelGroupRegionOrder is the fixed presentation order; a region with zero
// credentials still renders (empty group) so the picker shows every channel.
var modelGroupRegionOrder = []string{"cn", "intl"}

// modelGroupRegionLabel renders the human-facing region title. Keep in sync
// with the login_region enum description in main.go and the panel badges.
func modelGroupRegionLabel(region string) string {
	switch region {
	case "cn":
		return "CN（qoder.com.cn）"
	case "intl":
		return "Intl（qoder.com）"
	default:
		return region
	}
}

// modelGroupEntry is one catalog row. Name carries the display name when the
// snapshot/discovery provided one.
type modelGroupEntry struct {
	// ID is the client-facing id (qwen3-8-flash). It is stable pre-exclusion.
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	// Facing is the id the model is actually registered under right now
	// (v0.8.74). Upstream catalogs carry versioned names — the Intl side
	// reports Qwen3.8-Flash, so the enabled model is qwen3-8-flash while a
	// config list written against Qwen3-Flash says qwen3-flash. The panel
	// must compare config entries against this, not against ID, or every
	// re-save re-appends a stale spelling to the exclusion list.
	Facing string `json:"facing,omitempty"`
	// Upstream is the raw qoder key when ID is a localized id (v0.8.69):
	// the panel tests/refreshes against the real upstream model.
	Upstream string `json:"upstream,omitempty"`
	// Hidden reports that the plugin's hidden_models list hides this model
	// (v0.8.71). Hidden entries stay in the panel list — unchecked and
	// tagged — so the admin can always see and restore them.
	Hidden bool `json:"hidden,omitempty"`
}

// modelGroup is one region's catalog as the panel picker consumes it.
type modelGroup struct {
	Realm        string            `json:"realm"`
	Label        string            `json:"label"`
	Models       []modelGroupEntry `json:"models"`
	Count        int               `json:"count"`
	Source       string            `json:"source,omitempty"`     // snapshot | refreshed
	FetchedAt    string            `json:"fetched_at,omitempty"` // RFC3339 UTC
	NeedsRefresh bool              `json:"needs_refresh"`        // empty catalog → suggest the refresh button
	Credentials  int               `json:"credentials"`          // qoder credentials seen in this region
	Note         string            `json:"note,omitempty"`       // refresh failure reason when a refresh produced nothing
}

type modelGroupsResponse struct {
	Groups []modelGroup `json:"groups"`
	Hint   string       `json:"hint"`
	// Excluded is the host's oauth-excluded-models table for this plugin's
	// keys (v0.8.74). The panel used to read it from the host with the access
	// key and got "invalid management key", so it rendered every box as
	// enabled and "saved" nothing.
	Excluded map[string][]string `json:"excluded,omitempty"`
	// ExcludedOK is false when the host refused the read (bad key, banned IP).
	// The panel then refuses to save instead of rewriting the lists blindly.
	ExcludedOK bool `json:"excluded_ok"`
}

// regionCatalogEntry is one credential's contribution to a region catalog scan.
type regionCatalogEntry struct {
	region   string
	hasToken bool
	storage  []byte // physical credential document (read-only view)
	snapshot *persistedModelCache
}

// handleModelGroupsQuery answers GET /plugins/qoder/models/groups.
// Returns (status, payload); status 200 carries modelGroupsResponse.
func handleModelGroupsQuery(req pluginapi.ManagementRequest) (int, any) {
	refresh := strings.TrimSpace(req.Query.Get("refresh")) == "1"

	files, err := hostAuthListFn()
	if err != nil {
		return http.StatusInternalServerError, map[string]any{"error": "auth list failed: " + err.Error()}
	}

	perRegion := map[string][]*regionCatalogEntry{}
	for _, f := range files {
		phys, err := hostAuthGetPhysicalFn(f.AuthIndex)
		if err != nil || phys == nil || len(phys.JSON) == 0 {
			continue
		}
		sa, err := parseStored(phys.JSON)
		if err != nil || sa == nil {
			continue
		}
		// hostAuthListFn already filtered foreign owners; region resolution
		// mirrors persistedSnapshotForStorage's same-region guard.
		region := authRegion(sa)
		e := &regionCatalogEntry{
			region:   region,
			hasToken: strings.TrimSpace(sa.Auth.AccessToken) != "",
			storage:  phys.JSON,
		}
		if c := readModelCacheDoc(phys.JSON); c != nil && c.Region == region {
			e.snapshot = c
		}
		perRegion[region] = append(perRegion[region], e)
	}

	groups := make([]modelGroup, 0, len(modelGroupRegionOrder))
	for _, region := range modelGroupRegionOrder {
		groups = append(groups, buildModelGroup(region, perRegion[region], refresh))
	}
	// The exclusion lists live in config.yaml; the plugin reads it through
	// the host API on every call so the panel never acts on a stale copy.
	excl, exclOK := fetchHostExcludedModelsChecked(bearerOf(req))
	return http.StatusOK, modelGroupsResponse{
		Groups:     groups,
		Hint:       "勾选=启用；取消勾选保存后该模型从渠道注册列表移除。与 CPA 全局页驱动同一份 oauth-excluded-models 配置。",
		Excluded:   excl,
		ExcludedOK: exclOK,
	}
}

// buildModelGroup resolves one region's catalog: newest same-region snapshot
// first; with refresh=1 a live discovery (via the for_auth chain) takes
// precedence and re-stamps the snapshot. Never serves a cross-region snapshot.
// fetchMergedCatalog is the static registration catalog (v0.8.69): every
// qoder credential's served catalog, unioned by raw id, over the static
// fallback table. Per-credential discovery is cached, so this costs one
// discovery per credential per cache window.
func fetchMergedCatalog() []pluginapi.ModelInfo {
	out := wbModels()
	seen := map[string]bool{}
	for _, m := range out {
		seen[strings.ToLower(m.ID)] = true
	}
	files, err := hostAuthListFiles()
	if err != nil {
		return out
	}
	prefix := providerName + "-"
	for _, f := range files {
		if !strings.HasPrefix(strings.ToLower(f.Name), prefix) {
			continue
		}
		raw, err := hostAuthGetByIndex(f.AuthIndex)
		if err != nil || len(raw) == 0 {
			continue
		}
		for _, m := range fetchDynamicModelsFromStorage(raw) {
			key := strings.ToLower(m.ID)
			if seen[key] || m.ID == "" {
				continue
			}
			seen[key] = true
			out = append(out, m)
		}
	}
	return out
}

// hasUsableSnapshot reports whether any credential in the region carries a
// non-empty catalog snapshot.
func hasUsableSnapshot(entries []*regionCatalogEntry) bool {
	for _, e := range entries {
		if e.snapshot != nil && len(e.snapshot.Models) > 0 {
			return true
		}
	}
	return false
}

func buildModelGroup(region string, entries []*regionCatalogEntry, refresh bool) modelGroup {
	g := modelGroup{
		Realm:       region,
		Label:       modelGroupRegionLabel(region),
		Models:      []modelGroupEntry{},
		Credentials: len(entries),
	}

	// v0.8.69: an explicit refresh discovers live through any credential that
	// can talk to upstream (localization needs display names, and discovery is
	// the only source that carries them). The plain read path keeps the
	// cheap snapshot-first behavior; it only falls through to a live
	// discovery when the region has credentials but no usable snapshot at
	// all — otherwise the panel rendered an empty region after a restart.
	if pick := pickRefreshCredential(entries); pick != nil && (refresh || !hasUsableSnapshot(entries)) {
		// v0.8.69: ask the DISCOVERY seam directly. The function-level ladder
		// (fetchDynamicModelsFromStorage) also returns static guesses and
		// persisted snapshots, which would defeat region isolation here — a
		// live answer exists only if the upstream call succeeded.
		sa, perr := parseStored(pick.storage)
		var dyn []pluginapi.ModelInfo
		var derr error
		if perr == nil && sa != nil {
			dyn, derr = callModelsAPIFn(sa)
		}
		if len(dyn) > 0 {
			storeDynamicModels(modelCatalogAccountKey(sa), dyn)
			persistModelSnapshot(pick.storage, region, dyn)
			g.Models = modelGroupEntries(dyn)
			g.Count = len(g.Models)
			g.Source = "refreshed"
			g.FetchedAt = time.Now().UTC().Format(time.RFC3339)
			return g
		}
		_ = derr
		g.Note = "刷新未获得模型（上游失败或凭证无效）；以下为最近一次落盘目录"
	} else if refresh {
		g.Note = "无可用凭证，无法实时刷新"
	}

	var best *persistedModelCache
	for _, e := range entries {
		if e.snapshot == nil {
			continue
		}
		if best == nil || persistedFetchedAt(e.snapshot) > persistedFetchedAt(best) {
			best = e.snapshot
		}
	}
	if best != nil && len(best.Models) > 0 {
		g.Models = modelGroupEntries(best.Models)
		g.Count = len(g.Models)
		g.Source = "snapshot"
		g.FetchedAt = best.FetchedAt
	}
	if len(g.Models) == 0 {
		g.NeedsRefresh = true
		if g.Note == "" {
			g.Note = "暂无目录：该渠道还没有成功拉取过模型，点「刷新目录」试一次"
		}
	}
	return g
}

// pickRefreshCredential chooses the credential to drive a refresh with:
// token-bearing and enabled first, then any token bearer, then any entry —
// the for_auth chain answers from the persisted snapshot even without a
// token, but a token gives it a real chance at fresh discovery.
func pickRefreshCredential(entries []*regionCatalogEntry) *regionCatalogEntry {
	var any, withToken *regionCatalogEntry
	for _, e := range entries {
		if any == nil {
			any = e
		}
		if !e.hasToken {
			continue
		}
		if withToken == nil {
			withToken = e
		}
	}
	if withToken != nil {
		return withToken
	}
	return any
}

// modelGroupEntries projects ModelInfos into picker rows (id + display name).
func modelGroupEntries(models []pluginapi.ModelInfo) []modelGroupEntry {
	noteCatalogDisplays(models)
	hiddenSet := hiddenRawSet()
	out := make([]modelGroupEntry, 0, len(models))
	for _, m := range models {
		if m.ID == "" {
			continue
		}
		name := m.DisplayName
		if name == "" {
			name = m.Name
		}
		if strings.EqualFold(name, m.ID) {
			name = ""
		}
		// v0.8.69: with localize on, the display-name slug is the id clients
		// and logs will see; the raw key stays the upstream model.
		facing := localizeFacingFor(m.ID)
		upstream := ""
		if !strings.EqualFold(facing, m.ID) {
			upstream = m.ID
		}
		out = append(out, modelGroupEntry{ID: facing, Name: name, Facing: facing, Upstream: upstream,
			Hidden: hiddenSet[strings.ToLower(m.ID)] || hiddenSet[strings.ToLower(facing)]})
	}
	return out
}
