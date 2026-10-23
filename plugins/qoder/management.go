// management.go implements the QoderWork management API and web panel:
// account dashboard (nickname, credits, plan, check-in streak), manual/auto
// check-in (daily at 09:00 and 21:00 local time), and quota refresh.
package main

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// billingBase hosts the Buddy-gas-station check-in and resource-package APIs.
// (Deprecated: superseded by per-account upstreamBaseFor(sa) region routing.)
// It is a var (not const) so tests can override it with an httptest server.
var billingBase = "https://openapi.qoder.com.cn" // unused legacy var, kept for compat

// If the panel later wants to surface "usage export ready", re-add it and wire
// it into buildDashboardEx's response.

// -----------------------------------------------------------------------------
// Account listing via host auth callbacks
// -----------------------------------------------------------------------------

type creditsSummary struct {
	// TotalRemain is currently usable credits across all active packages.
	TotalRemain int64 `json:"total_remain"`
	// TotalUsed is consumed credits in the current cycle (sum of packages).
	TotalUsed int64 `json:"total_used"`
	// TotalSize is the credit capacity/pool (sum of package sizes). remain+used ≈ size.
	TotalSize int64 `json:"total_size"`
	// PackCount is number of resource packages included in the aggregate.
	PackCount int `json:"pack_count"`
	// FetchedAt is when this snapshot was taken (RFC3339). Upstream billing lag
	// can make remain/used look "stuck" for minutes after chat; compare this
	// timestamp — not only the numbers — when diagnosing frozen credits.
	FetchedAt string           `json:"fetched_at,omitempty"`
	Packages  []packageSummary `json:"packages"`
	// Activity* (v0.8.76) are the activity/campaign grants (daily check-in
	// 100, Pro upgrade pack, SOTA packages) held apart from the subscription
	// pools. They are NOT subtracted from Total*, which keep summing every
	// package — a consumer that treats Total as the subscription allowance
	// would otherwise flip the account to "exhausted" seconds after chat
	// spends the day's grant.
	ActivityRemain int64 `json:"activity_remain"`
	ActivityUsed   int64 `json:"activity_used"`
	ActivitySize   int64 `json:"activity_size"`
	ActivityPacks  int   `json:"activity_packs"`
	// ActivityExpiring is the smallest future expiry among activity packages
	// (RFC3339, +08:00). Empty when nothing is expiring.
	ActivityExpiring string `json:"activity_expiring,omitempty"`
}

// Package kinds — the panel groups rows by these and the quota view keeps
// activity grants out of the subscription numbers.
const (
	packageKindBase     = "base"
	packageKindAddOn    = "addon"
	packageKindActivity = "activity"
	packageKindOrg      = "org"
)

type packageSummary struct {
	Name       string `json:"name"`
	Remain     int64  `json:"remain"`
	Used       int64  `json:"used"`
	Size       int64  `json:"size"`
	CycleStart string `json:"cycle_start"`
	CycleEnd   string `json:"cycle_end"`
	// Kind is the row's provenance (v0.8.76).
	Kind string `json:"kind,omitempty"`
	// Activity marks a row that belongs to the activity-grant subtotal
	// (redundant with Kind=="activity" but cheap for the panel).
	Activity bool `json:"activity,omitempty"`
	// ExpiresAt is the grant's expiry (RFC3339) or empty when none was
	// reported. Upstream's 9999 sentinel is normalised to empty.
	ExpiresAt string `json:"expires_at,omitempty"`
	// NeverExpires is set when upstream reported the no-expiry sentinel.
	NeverExpires bool `json:"never_expires,omitempty"`
	// Expired marks a grant whose expiry has already passed.
	Expired bool `json:"expired,omitempty"`
}

// modelPrice is the upstream credit multiplier for one model (v0.8.76).
// Qoder runs time-boxed promotions — CN DeepSeek-Flash (dfmodel) has been at
// priceFactor 0 since 2026-10-17 — and the multiplier is the only way a
// client can tell "free for now" from "always cheap". Upstream decomposes a
// limited-time free row into priceFactor / originalPriceFactor / a
// Limited-Time-Free tag; the compiled fallback table cannot read tags, so the
// promo end is carried as FreeUntil and the row falls back to the original
// multiplier by itself once it passes (dsh-our-free-model #518).
type modelPrice struct {
	PriceFactor         float64 `json:"price_factor"`
	OriginalPriceFactor float64 `json:"original_price_factor,omitempty"`
	// FreeUntil is the promo end (RFC3339, +08:00) for a 0x row; empty when
	// the row is not a promotion.
	FreeUntil string `json:"free_until,omitempty"`
	// PromoActive is evaluated server-side so every client agrees.
	PromoActive bool `json:"promo_active"`
	// LimitedFree marks a currently-free promotion row.
	LimitedFree bool `json:"limited_free,omitempty"`
	// Regions lists the realms the campaign was observed in ("cn", "intl").
	// A price campaign is an upstream fact per realm: dsh-our-free-model #518
	// documented the CN 0x run, and carrying it onto Intl would advertise a
	// discount that realm never published. Empty = realm unknown, shown
	// everywhere.
	Regions []string `json:"regions,omitempty"`
}

// priceFor returns the price campaign for a catalog row in one realm,
// matching either the raw upstream key or the published facing id. nil = no
// campaign, i.e. upstream regular pricing.
func priceFor(raw, facing, region string) *modelPrice {
	table := pricePromotions(time.Now())
	for _, key := range []string{raw, facing} {
		p, ok := table[strings.ToLower(strings.TrimSpace(key))]
		if !ok {
			continue
		}
		if len(p.Regions) > 0 {
			match := false
			for _, r := range p.Regions {
				if r == strings.ToLower(strings.TrimSpace(region)) {
					match = true
					break
				}
			}
			if !match {
				return nil
			}
		}
		cp := p
		return &cp
	}
	return nil
}

// pricePromotions is the compiled fallback table for time-boxed price
// campaigns. Unknown models report no price at all rather than a guessed one.
func pricePromotions(now time.Time) map[string]modelPrice {
	out := map[string]modelPrice{}
	// CN DeepSeek-Flash 0x activity: regular multiplier 0.1, free from
	// 2026-10-17 until 2026-10-25 00:00 +08:00.
	if until, err := time.Parse(time.RFC3339, "2026-10-25T00:00:00+08:00"); err == nil {
		active := now.Before(until)
		pf := 0.0
		if !active {
			pf = 0.1
		}
		out["dfmodel"] = modelPrice{
			PriceFactor:         pf,
			OriginalPriceFactor: 0.1,
			FreeUntil:           until.Format(time.RFC3339),
			PromoActive:         active,
			LimitedFree:         active,
			Regions:             []string{regionCN},
		}
	}
	return out
}

type checkinSummary struct {
	Active          bool     `json:"active"`
	TodayCheckedIn  bool     `json:"today_checked_in"`
	StreakDays      int64    `json:"streak_days"`
	DailyCredit     int64    `json:"daily_credit"`
	TodayCredit     int64    `json:"today_credit"`
	TotalCredits    int64    `json:"total_credits"`
	WeekCheckinDays int64    `json:"week_checkin_days"`
	ActivityName    string   `json:"activity_name"`
	Season          int64    `json:"season"`
	CheckinDates    []string `json:"checkin_dates,omitempty"`
}

// -----------------------------------------------------------------------------
// Auto check-in scheduler (09:00 / 21:00 local)
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

// managementBasePathCache holds the host-injected BasePath so handleManagement
// doesn't hardcode /v0/management. Falls back to the historical default if the
// host doesn't provide one (older CPA builds).
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
			{Method: http.MethodGet, Path: base + "/accounts", Description: "List Qoder accounts (CN + Intl) with credits, plan and check-in status."},
			{Method: http.MethodPost, Path: base + "/refresh", Description: "Force refresh quota/cache for all accounts."},
			{Method: http.MethodPost, Path: base + "/checkin", Description: "Manually check in one account (auth_index) or all."},
			{Method: http.MethodPost, Path: base + "/checkin/config", Description: "Toggle auto check-in (enabled: true/false)."},
			{Method: http.MethodGet, Path: base + "/credits", Description: "Get real-time credits for one (auth_index query) or all accounts."},
			{Method: http.MethodPost, Path: base + "/import", Description: "Import a QoderWork PAT (pt-...) by exchanging it for a jobToken pair and persisting."},
			{Method: http.MethodPost, Path: base + "/select", Description: "Select the active account card used for chat routing (body: {auth_index})."},
			{Method: http.MethodPost, Path: base + "/keepalive", Description: "Manually refresh access tokens for all accounts (or one with auth_index)."},
			{Method: http.MethodPost, Path: base + "/claim-pro", Description: "Claim one-time Pro upgrade pack for one account (auth_index)."},
			{Method: http.MethodGet, Path: base + "/keepalive/status", Description: "Last keepalive run summary + config."},
			{Method: http.MethodGet, Path: base + "/cooldowns", Description: "List active per-(account, model) cooldown entries."},
			{Method: http.MethodPost, Path: base + "/cooldowns/clear", Description: "Clear cooldown for one account (auth_id) or one pair (auth_id + model)."},
			{Method: http.MethodGet, Path: base + "/models/groups", Description: "Per-region model catalog (model_cache snapshots; ?refresh=1 re-discovers) for the panel's exclusion picker."},
			{Method: http.MethodPost, Path: base + "/model-ids", Description: "v0.8.72: set custom client-facing model ids ({model_ids:{raw_id:custom_id}}). v0.8.73: body may add restart:true to restart CPA so the host registers the new ids; the response carries restart_scheduled and the pre-restart pid."},
			{Method: http.MethodGet, Path: base + "/status", Description: "v0.8.73: plugin/host process status (version, pid, uptime) + restart launcher readiness. The panel polls it after a restart and reloads when the pid changes."},
			{Method: http.MethodGet, Path: base + "/exclusions", Description: "v0.8.74: the host's oauth-excluded-models entries for qoder / qoder-cn / qoder-intl, read by the plugin with the host's own secret-key."},
			{Method: http.MethodPost, Path: base + "/exclusions", Description: "v0.8.74: set one key of that table ({provider, models}); an empty list removes the key."},
			{Method: http.MethodPost, Path: base + "/exclusions/reset?realm=cn|intl", Description: "v0.8.74: remove one region's exclusion key entirely."},
			{Method: http.MethodPost, Path: base + "/hidden-models", Description: "v0.8.77: drop entries from hidden_models in the LIVE process ({remove:[...]}) and return the replacement config.yaml block. config.yaml itself is never rewritten — the operator pastes the returned block so a restart keeps the change."},
		},
		Resources: []resourceRoute{
			{Path: "/panel", Menu: "Qoder", Description: "Qoder dashboard (CN + Intl): credits, check-in, plan, import."},
		},
	}
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

	// Plugin-layer auth + rate limit for mutating endpoints.
	// The rate limiter ONLY guards against brute-force on the management key
	// (repeated auth failures from one IP). Authenticated requests must never
	// be throttled — the panel's normal operation (checkin + reload + claim)
	// can easily exceed 5 POSTs in quick succession.
	base := loadedManagementBasePath() + "/plugins/" + providerName
	// v0.8.74: the exclusion routes forward the caller's credential to the
	// host, which is the authority on whether it is a management key — the
	// host middleware already rejected every other key before the plugin ran.
	panelRoute := path == base+"/exclusions" || path == base+"/exclusions/reset"
	if !panelRoute && (req.Method == http.MethodPost || mutatingManagementPath(path)) {
		ip := managementClientIP(req)
		if status, msg := checkManagementAuth(req); status != 0 {
			// Auth failed — consume a rate-limit token for this IP.
			if !allowManagementRequest(ip) {
				return okEnvelope(mgmtJSONResponse(http.StatusTooManyRequests, map[string]any{
					"error": "rate limit exceeded, try again later",
				}))
			}
			return okEnvelope(mgmtJSONResponse(status, map[string]any{"error": msg}))
		}
	}

	switch {
	case req.Method == http.MethodGet && path == base+"/accounts":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, buildDashboardEx(false, false)))
	case req.Method == http.MethodPost && path == base+"/refresh":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, buildDashboardEx(true, true)))
	case req.Method == http.MethodPost && path == base+"/checkin":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleManualCheckin(req)))
	case req.Method == http.MethodPost && path == base+"/checkin/config":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleCheckinConfig(req)))
	case req.Method == http.MethodGet && path == base+"/credits":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleCreditsQuery(req)))
	case req.Method == http.MethodPost && path == base+"/import":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleImportPAT(req)))
	case req.Method == http.MethodPost && path == base+"/select":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleSelectAuth(req)))
	case req.Method == http.MethodPost && path == base+"/keepalive":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleKeepaliveNow(req)))
	case req.Method == http.MethodPost && path == base+"/claim-pro":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleClaimPro(req)))
	case req.Method == http.MethodGet && path == base+"/keepalive/status":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleKeepaliveStatus()))
	case req.Method == http.MethodGet && path == base+"/cooldowns":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleCooldownList(req)))
	case req.Method == http.MethodPost && path == base+"/cooldowns/clear":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleCooldownClear(req)))
	case req.Method == http.MethodGet && path == base+"/models/groups":
		status, payload := handleModelGroupsQuery(req)
		return okEnvelope(mgmtJSONResponse(status, payload))
	case req.Method == http.MethodPost && path == base+"/model-ids":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleModelIDs(req)))
	case req.Method == http.MethodPost && path == base+"/hidden-models":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleHiddenModels(req)))
	case req.Method == http.MethodGet && path == base+"/status":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, pluginStatus()))
	case req.Method == http.MethodGet && path == base+"/exclusions",
		req.Method == http.MethodPost && (path == base+"/exclusions" || path == base+"/exclusions/reset"):
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleHostExclusions(req)))

	}
	return okEnvelope(mgmtJSONResponse(http.StatusNotFound, map[string]any{"error": "not found: " + path}))
}

// -----------------------------------------------------------------------------
// Plugin-layer management auth + rate limit (v0.6.31)
// -----------------------------------------------------------------------------
//
// When management_key is configured (config_yaml or WB_MANAGEMENT_KEY env), all
// mutating endpoints under /v0/management/plugins/qoderwork/* require a matching
// Bearer token. Read-only GET endpoints (accounts/credits/panel) pass through so
// the panel can render before the user has pasted a key — the panel itself
// supplies the key on every call via Authorization header.
//
// A per-IP token-bucket rate limiter guards against brute-force when the key
// check fails repeatedly.

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
// should be rejected. status=0 means allow.
// checkManagementAuth mirrors the community-plugin convention (grok-panel):
// trust the host middleware. The host already authenticated the request with
// the CPA management key before forwarding to the plugin — re-checking here
// would force operators to configure a second key just for the plugin.
//
// If a management_key is explicitly configured (config_yaml management_key: or
// WB_MANAGEMENT_KEY env), we enforce it as defence-in-depth on top of the
// host check. Otherwise (the default) we return 0 and let the request through.
func checkManagementAuth(req pluginapi.ManagementRequest) (int, string) {
	want := loadedManagementKey()
	if want == "" {
		return 0, "" // trust host middleware (community convention)
	}
	got := strings.TrimSpace(req.Headers.Get("Authorization"))
	if !strings.HasPrefix(got, "Bearer ") {
		return http.StatusUnauthorized, "missing Bearer token"
	}
	token := strings.TrimSpace(strings.TrimPrefix(got, "Bearer "))
	if subtle.ConstantTimeCompare([]byte(token), []byte(want)) != 1 {
		return http.StatusForbidden, "invalid management key"
	}
	return 0, ""
}

// allowManagementRequest applies a per-IP token bucket. ip may be empty when the
// host doesn't forward X-Forwarded-For / RemoteAddr — in that case use a single
// global bucket.
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
	// Refill.
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
	// Lazy eviction of idle entries (don't grow the map forever).
	if len(mgmtRateLimit) > 1024 {
		for k, v := range mgmtRateLimit {
			if now.Sub(v.lastSeen) > mgmtRateLimitTTL {
				delete(mgmtRateLimit, k)
			}
		}
	}
	return true
}

// managementClientIP extracts a best-effort client identifier for rate limiting.
// CPA host doesn't currently forward RemoteAddr, so fall back to X-Forwarded-For
// / X-Real-IP headers if the deployment adds them via a reverse proxy.
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

// mutatingManagementPath reports whether the path performs a write (checkin,
// import, trial claim, select, refresh, config toggle). Read endpoints pass.
func mutatingManagementPath(path string) bool {
	base := loadedManagementBasePath() + "/plugins/" + providerName
	switch path {
	case base + "/refresh",
		base + "/checkin",
		base + "/checkin/config",
		base + "/import",
		base + "/select",
		base + "/keepalive",
		base + "/claim-pro",
		base + "/model-ids",
		base + "/hidden-models",
		base + "/exclusions":
		return true
	}
	return false
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

// checkinLocks serializes per-account manual check-in (B4).
// Entries are pruned during dashboard prune to avoid unbounded growth
// when auth accounts are deleted/rotated.
var (
	checkinLocks sync.Map // auth_index -> *sync.Mutex
)
