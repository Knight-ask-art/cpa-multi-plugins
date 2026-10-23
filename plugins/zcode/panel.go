// panel.go serves the management dashboard: the aggregated account list the
// web UI consumes (buildDashboardEx) and the embedded HTML page itself.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// zcAccount is one row of the dashboard.
type zcAccount struct {
	AuthIndex string           `json:"auth_index"`
	AuthID    string           `json:"auth_id,omitempty"`
	Name      string           `json:"name"`
	Label     string           `json:"label"`
	Nickname  string           `json:"nickname"`
	UID       string           `json:"uid"`
	Provider  string           `json:"provider"` // zai | bigmodel
	Plan      string           `json:"plan"`     // coding-plan | start-plan
	Status    string           `json:"status"`
	Disabled  bool             `json:"disabled"`
	Exhausted bool             `json:"exhausted"`
	Selected  bool             `json:"selected"`
	Credits   *creditsSummary  `json:"credits,omitempty"`
	Cooling   []map[string]any `json:"cooling,omitempty"`
	Error     string           `json:"error,omitempty"`
	// CanSwitch lists the providers this account holds a stored OAuth token
	// for. Empty means a switch would need a fresh login first (see
	// swappableProviders).
	CanSwitch []string `json:"can_switch,omitempty"`
	// Risk is present only when the upstream risk-control gate has challenged
	// this account (risk.go). Omitted for a healthy account so the card stays
	// clean.
	Risk *riskSummary `json:"risk,omitempty"`
}

// creditsSummary is the shared quota snapshot shape (panel + notes).
type creditsSummary struct {
	TotalRemain int64            `json:"total_remain"`
	TotalUsed   int64            `json:"total_used"`
	TotalSize   int64            `json:"total_size"`
	PackCount   int              `json:"pack_count"`
	FetchedAt   string           `json:"fetched_at,omitempty"`
	Packages    []packageSummary `json:"packages"`
}

type packageSummary struct {
	Name   string `json:"name"`
	Remain int64  `json:"remain"`
	Used   int64  `json:"used"`
	Size   int64  `json:"size"`
}

// fetchPlanName resolves the plan tier display name (best-effort; empty on
// any failure). zcode.z.ai has no dedicated plan endpoint beyond the billing
// snapshot, so the plan comes from the account's own plan field plus the
// balance row count.
func fetchPlanName(sa *storedAuth) string {
	plan := authPlanFor(sa)
	if sa.Auth.JWT == "" {
		return plan + " (no JWT)"
	}
	return plan
}

// buildDashboardEx aggregates the account list. Credits fields are left
// empty on light loads — the panel renders skeletons and fetches them lazily
// via /credits?auth_index=<idx> (avoids stampeding billing on page load).
func buildDashboardEx(force, fetchQuota bool) map[string]any {
	files, err := hostAuthList()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	// Prune cache entries for accounts that no longer exist or expired.
	live := make(map[string]struct{}, len(files))
	for _, f := range files {
		live[f.ID] = struct{}{}
	}
	accountCache.Range(func(key, value any) bool {
		idx, _ := key.(string)
		if _, ok := live[idx]; !ok {
			accountCache.Delete(key)
			lifecycleState.Delete(key)
			return true
		}
		if e, ok := value.(*accountCacheEntry); ok && time.Since(e.fetched) > 4*accountCacheTTL {
			accountCache.Delete(key)
		}
		return true
	})
	pruneLifecycleState(live)
	out := make([]zcAccount, len(files))
	var wg sync.WaitGroup
	for i, f := range files {
		wg.Add(1)
		go func(i int, f pluginapi.HostAuthFileEntry) {
			defer wg.Done()
			acct := zcAccount{
				AuthIndex: f.AuthIndex,
				AuthID:    f.ID,
				Name:      f.Name,
				Label:     f.Label,
				Status:    f.Status,
				Disabled:  f.Disabled,
			}
			sa, phys, err := hostAuthGetBundle(f.AuthIndex)
			if err != nil {
				acct.Error = "load auth: " + err.Error()
				out[i] = acct
				return
			}
			if phys != nil {
				acct.Disabled = phys.Disabled
				if phys.Name != "" {
					acct.Name = phys.Name
				}
			}
			acct.Nickname = sa.Account.Nickname
			acct.UID = sa.Account.UID
			acct.Provider = authProviderFor(sa)
			acct.Plan = authPlanFor(sa)
			acct.CanSwitch = swappableProviders(sa)
			acct.Risk = riskSummaryForAuth(f.ID, sa)
			acct.Cooling = cooldownSnapshotFor(f.ID)
			if fetchQuota {
				_, cr, errs := cachedAccountDetails(f.ID, sa, force)
				acct.Credits = cr
				acct.Exhausted = isCreditsExhausted(cr)
				_ = syncAuthNote(f.AuthIndex, f.ID, sa, cr, acct.Disabled)
				acct.Error = strings.Join(errs, "; ")
			} else {
				if v, ok := accountCache.Load(f.ID); ok {
					if e, ok2 := v.(*accountCacheEntry); ok2 {
						acct.Credits = e.credits
						acct.Exhausted = isCreditsExhausted(e.credits)
						acct.Plan = firstNonEmpty(e.plan, acct.Plan)
					}
				}
			}
			out[i] = acct
		}(i, f)
	}
	wg.Wait()
	var life []map[string]any
	if force && lifecycleEnabled() {
		life = reconcileAllAccounts(true)
		if files2, err2 := hostAuthList(); err2 == nil {
			live2 := make(map[string]struct{}, len(files2))
			disabledBy := make(map[string]bool, len(files2))
			for _, f := range files2 {
				live2[f.AuthIndex] = struct{}{}
				disabledBy[f.AuthIndex] = f.Disabled
			}
			filtered := out[:0]
			for _, a := range out {
				if _, ok := live2[a.AuthIndex]; !ok {
					continue
				}
				if d, ok := disabledBy[a.AuthIndex]; ok {
					a.Disabled = d
				}
				if v, ok := accountCache.Load(a.AuthID); ok {
					if e, ok2 := v.(*accountCacheEntry); ok2 {
						if e.credits != nil {
							a.Credits = e.credits
							a.Exhausted = isCreditsExhausted(e.credits)
						}
						if e.plan != "" {
							a.Plan = e.plan
						}
					}
				}
				filtered = append(filtered, a)
			}
			out = filtered
		}
	}
	activeID := ensureDefaultActiveAuth(out)
	sum := summarizeQuotas(out)
	for i := range out {
		out[i].Selected = out[i].AuthID == activeID
	}
	resp := map[string]any{
		"accounts":       out,
		"active_auth":    activeID,
		"lifecycle_auto": lifecycleEnabled(),
		"login_provider": loadedLoginProvider(),
		"server_time":    time.Now().Format("2006-01-02 15:04:05"),
		"summary":        sum,
		// Which upstream plane actually served the traffic (plane_track.go).
		// Rides /accounts so the panel needs no extra round trip.
		"planes": planeSnapshot(),
		// The effective fingerprint values (identity.go) — see
		// identitySnapshotForPanel for why these are worth surfacing.
		"identity": identitySnapshotForPanel(),
		// The effective model namespace (model_policy.go): alias table, prefix
		// and output ceiling, including entries that resolve to nothing.
		"model_policy": modelPolicySnapshotForPanel(),
		// Per-credential health (cred_state.go): which of an account's two
		// credentials is parked, and how the dual-credential fallback has been
		// doing. Rides /accounts so the card costs no extra round trip.
		"cred_state": credStateSnapshotForPanel(),
	}
	if len(life) > 0 {
		resp["lifecycle"] = life
	}
	return resp
}

// summarizeQuotas aggregates remain/used across dashboard accounts.
func summarizeQuotas(accounts []zcAccount) map[string]any {
	var remain, used, size, zaiRemain, zaiUsed, zaiSize, bmRemain, bmUsed, bmSize int64
	var known, disabledN, exhaustedN, packs int
	for _, a := range accounts {
		if a.Disabled {
			disabledN++
		}
		if a.Exhausted {
			exhaustedN++
		}
		if a.Credits == nil {
			continue
		}
		cr := a.Credits
		if cr.TotalRemain == 0 && cr.TotalUsed == 0 && cr.TotalSize == 0 && len(cr.Packages) == 0 {
			continue
		}
		known++
		remain += cr.TotalRemain
		used += cr.TotalUsed
		size += cr.TotalSize
		packs += cr.PackCount
		if a.Provider == providerBigmodel {
			bmRemain += cr.TotalRemain
			bmUsed += cr.TotalUsed
			bmSize += cr.TotalSize
		} else {
			zaiRemain += cr.TotalRemain
			zaiUsed += cr.TotalUsed
			zaiSize += cr.TotalSize
		}
	}
	total := remain + used
	if size > total {
		total = size
	}
	return map[string]any{
		"account_count":   len(accounts),
		"known_count":     known,
		"disabled_count":  disabledN,
		"exhausted_count": exhaustedN,
		"pack_count":      packs,
		"total_remain":    remain,
		"total_used":      used,
		"total_size":      size,
		"total":           total,
		"zai_remain":      zaiRemain,
		"zai_used":        zaiUsed,
		"zai_size":        zaiSize,
		"bigmodel_remain": bmRemain,
		"bigmodel_used":   bmUsed,
		"bigmodel_size":   bmSize,
	}
}

// -----------------------------------------------------------------------------
// Management API routes + handler
// -----------------------------------------------------------------------------

type managementRoute struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Description string `json:"description,omitempty"`
}

type resourceRoute struct {
	Path        string `json:"path"`
	Menu        string `json:"menu,omitempty"`
	Description string `json:"description,omitempty"`
}

type managementRegistrationResponse struct {
	Routes    []managementRoute `json:"routes,omitempty"`
	Resources []resourceRoute   `json:"resources,omitempty"`
}

var (
	managementBasePathCache   = "/v0/management"
	managementBasePathCacheMu sync.RWMutex
)

func loadedManagementBasePath() string {
	managementBasePathCacheMu.RLock()
	defer managementBasePathCacheMu.RUnlock()
	return managementBasePathCache
}

func setManagementBasePath(p string) {
	p = strings.TrimRight(strings.TrimSpace(p), "/")
	if p == "" {
		return
	}
	managementBasePathCacheMu.Lock()
	managementBasePathCache = p
	managementBasePathCacheMu.Unlock()
}

func managementRegistration() managementRegistrationResponse {
	base := "/plugins/" + providerName
	return managementRegistrationResponse{
		Routes: []managementRoute{
			{Method: http.MethodGet, Path: base + "/accounts", Description: "List ZCode accounts (Z.AI + BigModel) with plan, quota and cooldown status."},
			{Method: http.MethodPost, Path: base + "/refresh", Description: "Force refresh quota/lifecycle for all accounts."},
			{Method: http.MethodGet, Path: base + "/credits", Description: "Get real-time quota for one (auth_index query) or all accounts."},
			{Method: http.MethodPost, Path: base + "/select", Description: "Select the active account card used for chat routing (body: {auth_index})."},
			{Method: http.MethodPost, Path: base + "/plan", Description: "Switch an account's plan routing (body: {auth_index, plan: coding-plan|start-plan})."},
			{Method: http.MethodPost, Path: base + "/provider", Description: "Move an account to the other coding-plane provider, re-resolving its API key from that provider's stored OAuth token (body: {auth_index, provider: zai|bigmodel}). Fails without writing when the token is absent."},
			{Method: http.MethodGet, Path: base + "/cooldowns", Description: "List active per-(account, model) cooldown entries."},
			{Method: http.MethodGet, Path: base + "/models", Description: "Full zcode model catalog for the panel's exclusion picker (PATCH the host's oauth-excluded-models.zcode key)."},
			{Method: http.MethodGet, Path: base + "/planes", Description: "Per-upstream-plane request counters: how many sends rode zai-coding / bigmodel-coding / jwt-anthropic / off-peak, plus reactive JWT-plane fallback activations. In-memory (lost on restart)."},
			{Method: http.MethodGet, Path: base + "/risk", Description: "Accounts the upstream risk-control gate (biz 3012) has challenged, with the strike count and the resulting pause. In-memory (lost on restart)."},
			{Method: http.MethodGet, Path: base + "/identity", Description: "The effective fingerprint values (X-Platform, X-Os-Category, X-Os-Version, app version, title, locale, release channel) and which pin overrides are active. Read-only."},
			{Method: http.MethodGet, Path: base + "/client_credential", Description: "Read-only scan of a locally installed ZCode client (client_data_dir, default ~/.zcode/v2/config.json): which credential fields were found, under which key path, and whether an import is possible. Never writes; available regardless of import_client_credential."},
			{Method: http.MethodPost, Path: base + "/client_credential/import", Description: "Import the credential found by the scan: resolve the coding-plan key from the client's OAuth token and save the account (body: {overwrite}). Refuses when the account uid already exists unless overwrite is true. Requires import_client_credential=true."},
			{Method: http.MethodGet, Path: base + "/model_policy", Description: "The effective model namespace: model_prefix, model_map (alias -> upstream id) and model_max_tokens, including mappings whose target is not in the pinned catalog. Read-only."},
			{Method: http.MethodGet, Path: base + "/cred_state", Description: "Per-credential health (cred_state.go): every parked credential of every account (which of the account two credentials, why, until when, how many consecutive failures) plus the dual-credential fallback counters (attempts, helped, last_plane). In-memory (lost on restart)."},
			{Method: http.MethodPost, Path: base + "/cred_state/clear", Description: "Un-park credentials (body: {auth_id, kind}; empty auth_id clears every account, empty kind clears both credentials of an account). Use after fixing a credential upstream."},
			{Method: http.MethodPost, Path: base + "/risk/clear", Description: "Lift a risk-control pause or quarantine (body: {auth_id}; empty auth_id clears every account)."},
			{Method: http.MethodPost, Path: base + "/cooldowns/clear", Description: "Clear cooldown for one account (auth_id) or one pair (auth_id + model)."},
			{Method: http.MethodGet, Path: base + "/preview", Description: "List claimable trial plans (billing/preview) across accounts plus the v0.2.1 activity probe: the banner feed (system/resource-packages/config), granted buckets (billing/balance) and off-peak admission (off-peak/ticket/availability), each with status/http/items/error so an empty claim list can be told apart from a broken probe. Read-only."},
			{Method: http.MethodPost, Path: base + "/claim", Description: "Claim one trial plan for one account with the panel-minted Aliyun captcha verify param (billing/claim). The captcha challenge runs in the panel page itself."},
			{Method: http.MethodGet, Path: base + "/captcha_pool", Description: "Captcha token pool state (v0.2.0): how many panel-minted Aliyun verify params are stocked for challenged start-plane calls and auto-claims."},
			{Method: http.MethodPost, Path: base + "/captcha_pool", Description: "Add one panel-minted Aliyun captcha verify param to the pool (body: {captcha, region}). One-shot tokens; FIFO; capped."},
			{Method: http.MethodGet, Path: base + "/claim_status", Description: "Auto-claim scheduler state (issue #23): per-account last outcome, hold windows, captcha-needed badges, pool size."},
		},
		Resources: []resourceRoute{
			{Path: "/panel", Menu: "ZCode", Description: "ZCode dashboard (Z.AI + BigModel): plan, quota, cooldowns."},
		},
	}
}

// handleModelCatalog serves the full zcode catalog for the panel's
// exclusion picker (v0.1.8). zcode is a single-channel plugin — the
// provider key IS the channel key in oauth-excluded-models — so one
// group suffices (trae needs per-variant groups; zcode does not). The
// picker saves PATCH the host's oauth-excluded-models.zcode key, the
// same config the global page drives (no second truth); filter-
// ExcludedModels already consumes it in model.static and model.for_auth.
func handleModelCatalog() map[string]any {
	// The ADVERTISED catalog, not the bare one: the picker must offer the exact
	// ids the operator sees in their client, since whatever they pick has to
	// match filterExcludedModels. Offering bare ids under a configured prefix
	// would let a pick silently exclude nothing.
	catalog := decorateCatalog(zcodeModels())
	models := make([]map[string]string, 0, len(catalog)+8)
	for _, m := range catalog {
		models = append(models, map[string]string{"id": m.ID, "name": m.Name})
	}
	group := map[string]any{
		"realm":  providerName,
		"label":  "ZCode",
		"models": models,
		"count":  len(models),
		"source": "catalog",
	}
	return map[string]any{"groups": []map[string]any{group}}
}

func handleManagement(raw []byte) ([]byte, error) {
	var req pluginapi.ManagementRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	path := strings.TrimRight(req.Path, "/")

	// Browser UI resource routes (unauthenticated).
	resPrefix := "/v0/resource/plugins/" + providerName
	if req.Method == http.MethodGet && strings.HasPrefix(path, resPrefix) {
		sub := strings.TrimPrefix(path, resPrefix)
		return okEnvelope(mgmtHTMLResponse(servePanel(sub)))
	}

	// Plugin-layer auth + rate limit for mutating endpoints (defence-in-depth
	// when management_key is configured; host middleware is trusted otherwise).
	if req.Method == http.MethodPost || mutatingManagementPath(path) {
		ip := managementClientIP(req)
		if status, msg := checkManagementAuth(req); status != 0 {
			if !allowManagementRequest(ip) {
				return okEnvelope(mgmtJSONResponse(http.StatusTooManyRequests, map[string]any{
					"error": "rate limit exceeded, try again later",
				}))
			}
			return okEnvelope(mgmtJSONResponse(status, map[string]any{"error": msg}))
		}
	}

	base := loadedManagementBasePath() + "/plugins/" + providerName
	switch {
	case req.Method == http.MethodGet && path == base+"/planes":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, planeSnapshot()))
	case req.Method == http.MethodGet && path == base+"/risk":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleRiskList(req)))
	case req.Method == http.MethodGet && path == base+"/identity":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, identitySnapshotForPanel()))
	case req.Method == http.MethodGet && path == base+"/model_policy":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, modelPolicySnapshotForPanel()))
	case req.Method == http.MethodGet && path == base+"/cred_state":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, credStateSnapshotForPanel()))
	case req.Method == http.MethodPost && path == base+"/cred_state/clear":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleCredStateClear(req)))
	case req.Method == http.MethodGet && path == base+"/client_credential":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleClientCredentialScan()))
	case req.Method == http.MethodPost && path == base+"/client_credential/import":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleClientCredentialImport(req)))
	case req.Method == http.MethodGet && path == base+"/accounts":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, buildDashboardEx(false, false)))
	case req.Method == http.MethodPost && path == base+"/refresh":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, buildDashboardEx(true, true)))
	case req.Method == http.MethodGet && path == base+"/credits":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleCreditsQuery(req)))
	case req.Method == http.MethodPost && path == base+"/select":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleSelectAuth(req)))
	case req.Method == http.MethodPost && path == base+"/plan":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handlePlanSwitch(req)))
	case req.Method == http.MethodPost && path == base+"/provider":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleProviderSwitch(req)))
	case req.Method == http.MethodGet && path == base+"/cooldowns":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleCooldownList(req)))
	case req.Method == http.MethodGet && path == base+"/models":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleModelCatalog()))
	case req.Method == http.MethodPost && path == base+"/cooldowns/clear":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleCooldownClear(req)))
	case req.Method == http.MethodPost && path == base+"/risk/clear":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleRiskClear(req)))
	case req.Method == http.MethodGet && path == base+"/preview":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handlePreviewList()))
	case req.Method == http.MethodPost && path == base+"/claim":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleClaim(req)))
	case req.Method == http.MethodGet && path == base+"/captcha_pool":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleCaptchaPoolGet()))
	case req.Method == http.MethodPost && path == base+"/captcha_pool":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleCaptchaPoolPut(req)))
	case req.Method == http.MethodGet && path == base+"/claim_status":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleClaimStatus()))
	}
	return okEnvelope(mgmtJSONResponse(http.StatusNotFound, map[string]any{"error": "not found: " + path}))
}

// mutatingManagementPath reports whether the path performs a write.
func mutatingManagementPath(path string) bool {
	base := loadedManagementBasePath() + "/plugins/" + providerName
	switch path {
	case base + "/refresh",
		base + "/select",
		base + "/plan",
		base + "/provider",
		base + "/cooldowns/clear",
		base + "/risk/clear",
		base + "/cred_state/clear",
		base + "/claim",
		base + "/captcha_pool",
		base + "/client_credential/import":
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// Plugin-layer management auth + rate limit
// -----------------------------------------------------------------------------

const (
	mgmtRateLimitCapacity = 5                // burst
	mgmtRateLimitRefill   = time.Minute / 10 // 1 token per 6s
	mgmtRateLimitTTL      = 10 * time.Minute // idle entry eviction
)

type mgmtRateEntry struct {
	tokens   float64
	lastSeen time.Time
}

var (
	mgmtRateLimit   = map[string]*mgmtRateEntry{}
	mgmtRateLimitMu sync.Mutex
)

func loadedManagementKey() string {
	managementAPIKeyMu.RLock()
	defer managementAPIKeyMu.RUnlock()
	return managementAPIKey
}

// checkManagementAuth returns an HTTP status + error message when the request
// should be rejected. status=0 means allow (trust host middleware; the
// plugin-layer key is defence-in-depth only).
func checkManagementAuth(req pluginapi.ManagementRequest) (int, string) {
	want := loadedManagementKey()
	if want == "" {
		return 0, ""
	}
	got := strings.TrimSpace(req.Headers.Get("Authorization"))
	if !strings.HasPrefix(got, "Bearer ") {
		return http.StatusUnauthorized, "missing Bearer token"
	}
	token := strings.TrimSpace(strings.TrimPrefix(got, "Bearer "))
	if subtleConstantTimeCompare(token, want) != 1 {
		return http.StatusForbidden, "invalid management key"
	}
	return 0, ""
}

func allowManagementRequest(ip string) bool {
	if ip == "" {
		ip = "_global"
	}
	mgmtRateLimitMu.Lock()
	defer mgmtRateLimitMu.Unlock()
	now := time.Now()
	e, ok := mgmtRateLimit[ip]
	if !ok {
		e = &mgmtRateEntry{tokens: mgmtRateLimitCapacity, lastSeen: now}
		mgmtRateLimit[ip] = e
	}
	elapsed := now.Sub(e.lastSeen)
	e.tokens += float64(elapsed) / float64(mgmtRateLimitRefill)
	if e.tokens > mgmtRateLimitCapacity {
		e.tokens = mgmtRateLimitCapacity
	}
	e.lastSeen = now
	if e.tokens < 1 {
		return false
	}
	e.tokens--
	if len(mgmtRateLimit) > 1024 {
		for k, v := range mgmtRateLimit {
			if now.Sub(v.lastSeen) > mgmtRateLimitTTL {
				delete(mgmtRateLimit, k)
			}
		}
	}
	return true
}

func managementClientIP(req pluginapi.ManagementRequest) string {
	if xff := strings.TrimSpace(req.Headers.Get("X-Forwarded-For")); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return xff
	}
	if xr := strings.TrimSpace(req.Headers.Get("X-Real-Ip")); xr != "" {
		return xr
	}
	return ""
}

func mgmtJSONResponse(status int, v any) pluginapi.ManagementResponse {
	body, _ := json.Marshal(v)
	h := http.Header{}
	h.Set("Content-Type", "application/json; charset=utf-8")
	return pluginapi.ManagementResponse{StatusCode: status, Headers: h, Body: body}
}

func mgmtHTMLResponse(body []byte) pluginapi.ManagementResponse {
	h := http.Header{}
	h.Set("Content-Type", "text/html; charset=utf-8")
	return pluginapi.ManagementResponse{StatusCode: http.StatusOK, Headers: h, Body: body}
}

// -----------------------------------------------------------------------------
// Management endpoint implementations
// -----------------------------------------------------------------------------

// handleSelectAuth sets the panel-selected account used for chat routing.
func handleSelectAuth(req pluginapi.ManagementRequest) map[string]any {
	var body struct {
		AuthIndex string `json:"auth_index"`
	}
	_ = json.Unmarshal(req.Body, &body)
	authIndex := strings.TrimSpace(body.AuthIndex)
	if authIndex == "" {
		return map[string]any{"error": "auth_index is required", "active_auth": getActiveAuthID()}
	}
	files, err := hostAuthList()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	for _, f := range files {
		if f.AuthIndex != authIndex {
			continue
		}
		if f.Disabled {
			return map[string]any{"error": "账号已禁用，无法选中", "auth_index": authIndex}
		}
		sa, err := hostAuthGet(f.AuthIndex)
		if err != nil {
			return map[string]any{"error": err.Error(), "auth_index": authIndex}
		}
		setActiveAuthID(f.ID)
		return map[string]any{
			"ok":          true,
			"active_auth": f.ID,
			"provider":    authProviderFor(sa),
			"plan":        authPlanFor(sa),
			"uid":         sa.Account.UID,
		}
	}
	return map[string]any{"error": "account not found", "auth_index": authIndex}
}

// handlePlanSwitch rewrites an account's plan field (coding-plan ↔ start-plan).
// The executor refuses start-plan traffic until the Anthropic-format upstream
// ships, so this is a visible, deliberate operator action.
func handlePlanSwitch(req pluginapi.ManagementRequest) map[string]any {
	var body struct {
		AuthIndex string `json:"auth_index"`
		Plan      string `json:"plan"`
	}
	_ = json.Unmarshal(req.Body, &body)
	authIndex := strings.TrimSpace(body.AuthIndex)
	plan := normalizePlan(body.Plan)
	if authIndex == "" {
		return map[string]any{"error": "auth_index is required"}
	}
	files, err := hostAuthList()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	for _, f := range files {
		if f.AuthIndex != authIndex {
			continue
		}
		sa, err := hostAuthGet(f.AuthIndex)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		sa.Auth.Plan = plan
		note := displayNote(sa, nil, parseDisabledFromAuthJSON(nil))
		// Preserve on-disk disabled state + note credit segment.
		phys, err := hostAuthGetPhysicalFn(authIndex)
		disabled := false
		if err == nil && phys != nil {
			disabled = phys.Disabled
			note = displayNoteWithPrev(sa, nil, disabled, noteCreditsFromJSON(phys.JSON))
		}
		raw, err := buildAuthFileJSON(sa, disabled, note, nil)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		name, _ := resolveAuthFileTarget(sa, phys)
		if err := hostAuthPersistFn(name, raw); err != nil {
			return map[string]any{"error": err.Error()}
		}
		// The dashboard caches `plan` per auth (cache.go, 45s TTL) and the
		// light path overwrites acct.Plan from that cache — without this the
		// card keeps showing the old plan, and `provider` (not cached) would
		// flip while `plan` lagged, so the two badges disagree. The entitlement
		// snapshot is plan-sensitive too: a start-plan credential routes
		// wholesale to the anthropic plane, so a stale harvest is misleading.
		invalidateAccountCredits(f.ID, sa.Account.UID)
		clearStartPlane(sa.Account.UID)
		// A plan switch moves the credential to a different gateway, so a
		// risk-control pause earned on the other one no longer applies.
		clearRiskForAuth(f.ID, sa)
		// Same argument for the per-credential park (cred_state.go): the park
		// outlives its cause exactly when the credential underneath changes.
		clearCredStateForAuth(f.ID, sa)
		return map[string]any{"ok": true, "auth_index": authIndex, "plan": plan}
	}
	return map[string]any{"error": "account not found", "auth_index": authIndex}
}

// handleProviderSwitch moves an account onto the other coding-plane provider.
//
// This is not a field flip. The provider is baked into the credential at
// login: the key that rides the requests is resolved through a per-provider
// business chain (auth_keyres.go — zai exchanges the OAuth token for a biz
// token and hard-fails unless it comes back with a secretKey, bigmodel posts
// the raw token to bigmodel.cn and copies the secret best-effort), and an
// OAuth token is only valid on the chain that issued it. So the switch
// resolves a FRESH key for the target provider from that provider's stored
// token, and writes only after resolution succeeds — a failure leaves the
// credential byte-identical, which is why this can be offered as a one-click
// button rather than a confirm-then-hope.
//
// The on-disk file name is deliberately left alone. authFileNameFor embeds the
// provider, so re-saving under the new name would create a SECOND file (the
// host ABI has no auth-delete method) and leave two records for one identity.
// The name is cosmetic on the paths that matter: handleParseAuth echoes the
// host's FileName back and blanks ID, so the host derives its record id from
// the path it already has and never sees the mismatch. A file called
// zcode-zai-<uid>.json holding provider=bigmodel is ugly but inert.
func handleProviderSwitch(req pluginapi.ManagementRequest) map[string]any {
	var body struct {
		AuthIndex string `json:"auth_index"`
		Provider  string `json:"provider"`
	}
	_ = json.Unmarshal(req.Body, &body)
	authIndex := strings.TrimSpace(body.AuthIndex)
	if authIndex == "" {
		return map[string]any{"error": "auth_index is required"}
	}
	want, ok := parseProviderArg(body.Provider)
	if !ok {
		return map[string]any{"error": "provider must be zai or bigmodel", "got": body.Provider}
	}
	files, err := hostAuthList()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	for _, f := range files {
		if f.AuthIndex != authIndex {
			continue
		}
		sa, err := hostAuthGet(f.AuthIndex)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		from := authProviderFor(sa)
		if from == want {
			return map[string]any{"ok": true, "auth_index": authIndex, "provider": want, "unchanged": true}
		}
		token := strings.TrimSpace(sa.Auth.AltOAuthTokens[want])
		if token == "" {
			// Either this credential predates the alt slot or the login poll
			// carried only its own provider. Both are fixed the same way.
			return map[string]any{
				"error":         fmt.Sprintf("该账号没有存下 %s 的 OAuth token，无法原地切换；请用 login_provider=%s 重新登录一次（登录会把两家 token 都存下来）", want, want),
				"auth_index":    authIndex,
				"provider":      want,
				"needs_relogin": true,
			}
		}
		// Resolve before mutating: the old credential stays usable if the
		// target chain rejects the token (expired, revoked, or wrong chain).
		newKey, err := resolveCodingPlanKey(token, want)
		if err != nil {
			return map[string]any{
				"error":      fmt.Sprintf("向 %s 解析 key 失败，凭据未改动：%v", want, err),
				"auth_index": authIndex,
				"provider":   want,
			}
		}

		prevToken := sa.Auth.OAuthToken
		sa.Auth.Provider = want
		sa.Auth.AccessToken = newKey
		sa.Auth.OAuthToken = token

		// Park the outgoing provider's token so the switch is reversible
		// without another trip through the browser.
		alt := map[string]string{}
		for k, v := range sa.Auth.AltOAuthTokens {
			if k != want && strings.TrimSpace(v) != "" {
				alt[k] = v
			}
		}
		if prevToken != "" {
			alt[from] = prevToken
		}
		if len(alt) == 0 {
			alt = nil
		}
		sa.Auth.AltOAuthTokens = alt

		note := displayNote(sa, nil, false)
		phys, perr := hostAuthGetPhysicalFn(authIndex)
		disabled := false
		if perr == nil && phys != nil {
			disabled = phys.Disabled
			note = displayNoteWithPrev(sa, nil, disabled, noteCreditsFromJSON(phys.JSON))
		}
		raw, err := buildAuthFileJSON(sa, disabled, note, nil)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		name, _ := resolveAuthFileTarget(sa, phys)
		if err := hostAuthPersistFn(name, raw); err != nil {
			return map[string]any{"error": err.Error()}
		}
		// Three caches keyed on state that just changed. The 45s credits
		// cache also holds `plan`, which the light dashboard path trusts over
		// its own read; the entitlement snapshot is provider-sensitive (a
		// start-plan credential routes wholesale to the anthropic plane); and
		// a per-model cooldown earned against the OLD upstream says nothing
		// about the new one.
		invalidateAccountCredits(f.ID, sa.Account.UID)
		clearStartPlane(sa.Account.UID)
		clearModelCooldown(cooldownAuthIDFor(sa), "")
		// The gate inspects the request and the identity, both of which this
		// switch just changed; a pause earned by the old upstream must not
		// outlive it.
		clearRiskForAuth(f.ID, sa)
		// The provider is baked into the credential, so both credentials were
		// just replaced; a park earned by the old ones is stale by definition.
		clearCredStateForAuth(f.ID, sa)
		return map[string]any{
			"ok":                true,
			"auth_index":        authIndex,
			"provider":          want,
			"previous_provider": from,
			"file_name":         name,
		}
	}
	return map[string]any{"error": "account not found", "auth_index": authIndex}
}

// identitySnapshotForPanel renders the EFFECTIVE identity values, so an
// operator can see exactly what the plugin puts on the wire. The whole point of
// the identity_* overrides is to correct a header, which is impossible while
// the effective value is invisible — and the derived defaults are inferences
// from the mirrored reference, so being able to compare them against a real
// capture is the difference between a guess and a measurement.
func identitySnapshotForPanel() map[string]any {
	id := zcodeIdentity()
	return map[string]any{
		"app_version":     id.appVersion,
		"source_title":    id.sourceTitle,
		"referer":         id.referer,
		"language":        id.language,
		"timezone":        id.timezone,
		"platform":        id.platformValue,
		"os_category":     id.osCategory,
		"os_version":      id.osVersion,
		"release_channel": id.release,
		// The one derived value that is routinely EMPTY and therefore worth
		// flagging: a client on Windows/macOS always reports an OS version.
		"os_version_missing": id.osVersion == "",
		"device_mid_pinned":  id.deviceMid != "",
		"session_id_pinned":  id.sessionID != "",
		"trace_id_pinned":    id.traceID != "",
	}
}

// handleRiskList serves the risk-control view: which accounts the gate has
// challenged, how many strikes, and how long the pause runs.
func handleRiskList(req pluginapi.ManagementRequest) map[string]any {
	entries := riskSnapshotAll()
	return map[string]any{
		"entries":    entries,
		"count":      len(entries),
		"persistent": false,
	}
}

// handleRiskClear lifts a pause or quarantine. An empty auth_id clears every
// account — the escape hatch when the panel and the routing filter disagree
// about an identifier, which is exactly when a per-account clear would fail
// silently.
func handleRiskClear(req pluginapi.ManagementRequest) map[string]any {
	var body struct {
		AuthID string `json:"auth_id"`
	}
	_ = json.Unmarshal(req.Body, &body)
	authID := strings.TrimSpace(body.AuthID)
	if authID == "" {
		return map[string]any{"success": true, "removed": clearRisk("")}
	}
	// Resolve through the auth store so both identifier forms are cleared.
	removed := clearRisk(authID)
	if files, err := hostAuthList(); err == nil {
		for _, f := range files {
			if f.AuthIndex != authID && f.ID != authID {
				continue
			}
			if sa, err := hostAuthGet(f.AuthIndex); err == nil {
				removed += clearRiskForAuth(f.ID, sa)
			}
		}
	}
	return map[string]any{"success": true, "removed": removed}
}

// handleCredStateClear un-parks credentials by hand.
//
// This exists because a park is a GUESS about a failure that may not be about
// the credential at all: a 401 that the operator has since fixed, an upstream
// blip that looked like a rejection, or a credential rotated in a way the plugin
// did not observe. The TTL eventually clears all of those, but waiting 30
// minutes for a false positive is not a reasonable thing to ask.
func handleCredStateClear(req pluginapi.ManagementRequest) map[string]any {
	var body struct {
		AuthID string `json:"auth_id"`
		Kind   string `json:"kind"`
	}
	_ = json.Unmarshal(req.Body, &body)
	authID := strings.TrimSpace(body.AuthID)
	kind := credKind(strings.TrimSpace(body.Kind))
	if kind != "" && kind != credKindJWT && kind != credKindKey {
		return map[string]any{"error": "kind must be jwt, key or empty"}
	}
	if authID == "" {
		return map[string]any{"success": true, "removed": clearAllCredState()}
	}
	// Resolve through the auth store so both identifier forms are cleared.
	removed := clearCredState(authID, kind)
	if files, err := hostAuthList(); err == nil {
		for _, f := range files {
			if f.AuthIndex != authID && f.ID != authID {
				continue
			}
			if sa, err := hostAuthGet(f.AuthIndex); err == nil {
				removed += clearCredStateForAuth(f.ID, sa)
			}
		}
	}
	return map[string]any{"success": true, "removed": removed}
}

// handleCreditsQuery returns real-time quota for one or all accounts.
func handleCreditsQuery(req pluginapi.ManagementRequest) map[string]any {
	authIndex := ""
	if vals := req.Query["auth_index"]; len(vals) > 0 {
		authIndex = strings.TrimSpace(vals[0])
	}
	files, err := hostAuthList()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	// Single-account: return one full account row (like dashboard entry).
	if authIndex != "" {
		for _, f := range files {
			if f.AuthIndex != authIndex {
				continue
			}
			sa, err := hostAuthGet(f.AuthIndex)
			if err != nil {
				return map[string]any{"accounts": []map[string]any{{
					"auth_index": authIndex, "error": "load auth: " + err.Error(),
				}}}
			}
			_, cr, errs := cachedAccountDetails(f.ID, sa, true)
			acct := map[string]any{
				"auth_index": authIndex,
				"nickname":   sa.Account.Nickname,
				"uid":        sa.Account.UID,
				"provider":   authProviderFor(sa),
				"plan":       authPlanFor(sa),
				"name":       f.Name,
				"label":      f.Label,
				"disabled":   f.Disabled,
				"selected":   getActiveAuthID() == f.ID,
			}
			if len(errs) > 0 {
				acct["error"] = strings.Join(errs, "; ")
			}
			if cr != nil {
				acct["credits"] = cr
				acct["exhausted"] = isCreditsExhausted(cr)
			}
			// Propagate the fresh quota into the host auth-file note.
			_ = syncAuthNote(f.AuthIndex, f.ID, sa, cr, f.Disabled)
			return map[string]any{"accounts": []map[string]any{acct}}
		}
		return map[string]any{"error": "account not found"}
	}
	// All accounts: simplified list.
	type acctQuota struct {
		AuthIndex string          `json:"auth_index"`
		Nickname  string          `json:"nickname"`
		UID       string          `json:"uid"`
		Provider  string          `json:"provider"`
		Plan      string          `json:"plan"`
		Credits   *creditsSummary `json:"credits,omitempty"`
		Error     string          `json:"error,omitempty"`
	}
	var out []acctQuota
	for _, f := range files {
		sa, err := hostAuthGet(f.AuthIndex)
		if err != nil {
			out = append(out, acctQuota{AuthIndex: f.AuthIndex, Error: "load auth: " + err.Error()})
			continue
		}
		_, cr, errs := cachedAccountDetails(f.ID, sa, false)
		ac := acctQuota{
			AuthIndex: f.AuthIndex,
			Nickname:  sa.Account.Nickname,
			UID:       sa.Account.UID,
			Provider:  authProviderFor(sa),
			Plan:      authPlanFor(sa),
		}
		if len(errs) > 0 {
			ac.Error = strings.Join(errs, "; ")
		}
		ac.Credits = cr
		_ = syncAuthNote(f.AuthIndex, f.ID, sa, cr, f.Disabled)
		out = append(out, ac)
	}
	return map[string]any{"accounts": out}
}

// Web panel (self-contained HTML, no external assets)

func servePanel(sub string) []byte {
	if sub != "" && sub != "/" && sub != "/panel" && sub != "/panel.html" {
		return []byte("<h1>404</h1>")
	}
	return panelHTML
}

//go:embed panel.html
var panelHTML []byte

// subtleConstantTimeCompare avoids importing crypto/subtle twice.
func subtleConstantTimeCompare(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}
