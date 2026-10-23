// billing.go owns the upstream billing API surface: check-in status, user
// resource (credits / packages), payment type, and the perform-* call wrappers
// for daily check-in. Includes the shared JSON helpers used to tolerate the
// upstream's loosely-typed response shapes.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// billingBaseOverride is nil in production; tests set it to redirect every
// sash/quota billing call (check-in, campaigns, quota) to an httptest server.
// The upstream base consts are compile-time, so this indirection is the only
// seam an HTTP-level test has.
var billingBaseOverride func(region string) string

// billingBaseFor routes billing calls by the account's region, honoring the
// test override. All sash/api check-in paths must go through this helper —
// a direct upstreamBaseFor(sa) call would bypass the test seam.
func billingBaseFor(sa *storedAuth) string {
	if billingBaseOverride != nil {
		return billingBaseOverride(authRegion(sa))
	}
	return upstreamBaseFor(sa)
}

// billingClientType/Version are the desktop client's Cosy identity headers.
//
// History: v0.8.35 set Cosy-Version to 0.4.3 (asar package.json app version);
// v0.8.47's official-client main.log capture showed 0.3.4 and concluded the
// header was a PROTOCOL version, not the app version. v0.8.59 (H-series live
// isolation, intl_dialect_live_test.go 2026-10-08) proved the campaigns list
// is INSENSITIVE to this value (0.3.4 / 0.4.3 / 0.5.0 return byte-identical
// envelopes — the v0.8.47 "0.3.4 restores the daily row" causality was
// coincidental), and issue #27's captured desktop client sends 0.4.3 on both
// regions. Aligned back to 0.4.3: the value rides every billing request as an
// identity header, and being a full minor behind the shipping client is a
// pointless risk variable.
const (
	billingClientType = "10"
	billingClientVer  = "0.4.3"
)

// billingHeaders sets the shared billing auth + identity headers.
//
// v0.8.46 (asar forensics): the official client's createRequestHeaders →
// YBr builds headers as {Accept, User-Agent, Authorization, Cosy-ClientType,
// Cosy-Version, Cosy-MachineOS, Cosy-MachineHostname, Cosy-MachineId,
// Cosy-MachineToken, Cosy-MachineCode, Cosy-MachineType}. It does NOT set
// Content-Type for GET requests — only POST requests with a body carry it
// (set by the JS fetch call inside the WebView, not by the header builder).
// The old code unconditionally set Content-Type:application/json on every
// request including GETs; some API gateways treat a GET with Content-Type
// as a non-browser request and may apply different filtering. Removing it
// from GET aligns with the official client's wire format.
func billingHeaders(req *http.Request, sa *storedAuth) {
	// QoderWork billing endpoints authenticate with the active token as a
	// plain Bearer — jobToken (jt-) or device token (dt-), both accepted
	// upstream (verified live 2026-07-27). No COSY signing (KNOWLEDGE §2).
	req.Header.Set("Authorization", "Bearer "+sa.Auth.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Qoder")
	req.Header.Set("Cosy-ClientType", billingClientType)
	req.Header.Set("Cosy-Version", billingClientVer)
	// Content-Type is set by the caller for POST requests with a body,
	// NOT here — the official client's header builder doesn't include it
	// in the base headers for GET requests.
	// 0.8.42 (adapted from bfSan f05e9e3): the billing surface additionally
	// expects the web-session cookies (acw_tc / qoder_csrf_token) and the
	// mirrored CSRF header.
	applyBillingSessionHeaders(req, sa)
}

// checkinStatusResponse mirrors GET /sash/api/v1/me/daily-check-in/status
// (plain JSON, no envelope).
type checkinStatusResponse struct {
	Status             string `json:"status"` // CLAIMABLE | CLAIMED
	RewardCredits      int64  `json:"rewardCredits"`
	NextClaimAt        int64  `json:"nextClaimAt"` // s epoch
	CurrentStreakDays  int64  `json:"currentStreakDays"`
	TotalClaimDays     int64  `json:"totalClaimDays"`
	TotalRewardCredits int64  `json:"totalRewardCredits"`
	LastClaimedAt      int64  `json:"lastClaimedAt"`   // s epoch
	RewardExpiresAt    int64  `json:"rewardExpiresAt"` // s epoch
}

// fetchCheckinStatus builds the panel's check-in summary. v0.12.80: BOTH
// regions now claim through the campaigns system — upstream DISABLED the
// legacy CN daily-check-in globally (status reports DISABLED with zero
// streak; claim answers 409 on unclaimed days and grants no credits;
// verified upstream 2026-09-21, cross-checked against the qoder2api
// project's packet capture). Calling the legacy claim only produced false
// "今日已签"/failure toasts on healthy CN accounts — the field report behind
// this change.
//
// The legacy CN status endpoint stays readable, so for CN credentials we
// merge its streak stats into the campaign summary (strictly read-only,
// non-zero values only) — the panel keeps 连续/累计 display while claims ride
// campaigns. Intl has no legacy endpoint; nothing to merge there.
func fetchCheckinStatus(sa *storedAuth) (*checkinSummary, error) {
	sum, err := fetchCampaignCheckinSummary(sa)
	if err != nil {
		return nil, err
	}
	mergeLegacyCheckinStats(sa, sum)
	return sum, nil
}

// fetchLegacyCheckinStatus queries the legacy CN daily-check-in status
// endpoint. READ-ONLY since v0.12.80: its claim sibling is DISABLED upstream
// and must never be called (409 + no grant). Kept as a stats supplement —
// if upstream restores the legacy system, non-zero stats flow back in
// automatically.
func fetchLegacyCheckinStatus(sa *storedAuth) (*checkinStatusResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, billingBaseFor(sa)+"/sash/api/v1/me/daily-check-in/status", nil)
	if err != nil {
		return nil, err
	}
	billingHeaders(req, sa)
	resp, err := hostHTTPDo(req)
	if err != nil {
		return nil, err
	}
	absorbBillingResponse(sa, billingBaseFor(sa), resp)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("checkin status http %d body=%s", resp.StatusCode, truncateRedacted(string(resp.Body), 200))
	}
	var q checkinStatusResponse
	if err := json.Unmarshal(resp.Body, &q); err != nil {
		return nil, fmt.Errorf("checkin status parse: %w", err)
	}
	return &q, nil
}

// mergeLegacyCheckinStats folds legacy CN daily-check-in stats into a
// campaign-derived summary. Only strictly greater non-zero values overwrite:
// the DISABLED legacy system reports zeros, which must never clobber the
// campaign-derived state. No-op for Intl (no legacy endpoint — probing it
// would only 404) and for nil summaries.
func mergeLegacyCheckinStats(sa *storedAuth, sum *checkinSummary) {
	if sum == nil || authRegion(sa) != regionCN {
		return
	}
	q, err := fetchLegacyCheckinStatus(sa)
	if err != nil || q == nil {
		return // best-effort: campaign summary stays authoritative
	}
	if q.CurrentStreakDays > sum.StreakDays {
		sum.StreakDays = q.CurrentStreakDays
	}
	if q.TotalClaimDays > sum.WeekCheckinDays {
		sum.WeekCheckinDays = q.TotalClaimDays
	}
	if q.TotalRewardCredits > sum.TotalCredits {
		sum.TotalCredits = q.TotalRewardCredits
	}
	if sum.DailyCredit == 0 && q.RewardCredits > 0 {
		sum.DailyCredit = q.RewardCredits
	}
}

// quotaUsageResponse mirrors GET /api/v2/quota/usage response (plain JSON,
// no envelope). Both userQuota (base credits) and addOnQuota (one-time pro
// upgrade + checkin packs) are summed for the panel.
type quotaUsageResponse struct {
	UserID               string  `json:"userId"`
	UserType             string  `json:"userType"`
	UsageType            string  `json:"usageType"`
	TotalUsagePercentage float64 `json:"totalUsagePercentage"`
	IsQuotaExceeded      bool    `json:"isQuotaExceeded"`
	ExpiresAt            int64   `json:"expiresAt"` // ms epoch
	UpgradeURL           string  `json:"upgradeUrl"`
	UserQuota            struct {
		Total     float64 `json:"total"`
		Used      float64 `json:"used"`
		Remaining float64 `json:"remaining"`
		Unit      string  `json:"unit"`
	} `json:"userQuota"`
	AddOnQuota struct {
		Total     float64 `json:"total"`
		Used      float64 `json:"used"`
		Remaining float64 `json:"remaining"`
	} `json:"addOnQuota"`
	// v0.8.17 (fork libo0118/qoder-custom review): the quota response also
	// carries dedicated resource packages (check-in / campaign grants) and an
	// organization shared pool. The old two-pool sum silently DROPPED them, so
	// the panel under-reported real credits whenever an account held such a
	// package.
	DedicatedResourcePackages []quotaPool `json:"dedicatedResourcePackages"`
	OrgResourcePackage        *quotaPool  `json:"orgResourcePackage"`
}

// quotaPool is one resource pool in the quota/usage response. Field names
// mirror userQuota's shape (verified against the fork's parsed struct).
// The expiry fields are optional: upstream reports activity grants with one of
// several spellings (ms epoch, s epoch, ISO string) and uses the 9999
// sentinel for "no expiry".
type quotaPool struct {
	Name            string  `json:"name"`
	Total           float64 `json:"total"`
	Used            float64 `json:"used"`
	Remaining       float64 `json:"remaining"`
	ExpiresAt       any     `json:"expiresAt"`
	ExpireAt        any     `json:"expireAt"`
	EndTime         any     `json:"endTime"`
	ExpireTime      any     `json:"expireTime"`
	ExpirationTime  any     `json:"expirationTime"`
	NeverExpires    bool    `json:"neverExpires"`
	UnlimitedExpire bool    `json:"unlimitedExpire"`
}

// noExpirySentinel is upstream's "never expires" marker (dsh-qoder-connect
// #16 documented the same 9999 sentinel on the Intl SOTA package). Any
// seconds/ms value at or above it is treated as "no expiry".
const noExpirySentinel = int64(9999)

// fetchUserResource queries QoderWork's quota endpoint and aggregates base +
// add-on credits into the panel's creditsSummary shape.
func fetchUserResource(sa *storedAuth) (*creditsSummary, error) {
	// billingBaseFor (not upstreamBaseFor): quota/plan ARE billing calls —
	// routing them through the shared seam also makes them interceptable
	// by the billingBaseOverride test seam.
	base := billingBaseFor(sa)
	req, err := http.NewRequest(http.MethodGet, base+"/api/v2/quota/usage", nil)
	if err != nil {
		return nil, err
	}
	billingHeaders(req, sa)
	resp, err := hostHTTPDo(req)
	if err != nil {
		return nil, err
	}
	absorbBillingResponse(sa, base, resp)
	if resp.StatusCode >= 400 {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, &authRejectedError{status: resp.StatusCode, err: fmt.Errorf("quota/usage http %d body=%s", resp.StatusCode, truncateRedacted(string(resp.Body), 200))}
		}
		return nil, fmt.Errorf("quota/usage http %d body=%s", resp.StatusCode, truncateRedacted(string(resp.Body), 200))
	}
	var q quotaUsageResponse
	if err := json.Unmarshal(resp.Body, &q); err != nil {
		return nil, fmt.Errorf("quota/usage parse: %w", err)
	}
	return summarizeQuotaResponse(q), nil
}

// summarizeQuotaResponse folds the parsed quota/usage response into the
// panel's creditsSummary shape. v0.8.17 (fork libo0118/qoder-custom review):
// dedicated resource packages and the org shared pool join the totals AND
// surface as their own package rows — the old two-pool sum silently dropped
// them, under-reporting real credits for accounts holding such packages.
func summarizeQuotaResponse(q quotaUsageResponse) *creditsSummary {
	sum := &creditsSummary{
		TotalRemain: int64(q.UserQuota.Remaining + q.AddOnQuota.Remaining),
		TotalUsed:   int64(q.UserQuota.Used + q.AddOnQuota.Used),
		TotalSize:   int64(q.UserQuota.Total + q.AddOnQuota.Total),
		PackCount:   2,
		Packages: []packageSummary{
			{Name: "基础额度", Kind: packageKindBase, Remain: int64(q.UserQuota.Remaining), Used: int64(q.UserQuota.Used), Size: int64(q.UserQuota.Total)},
			{Name: "赠送/签到额度", Kind: packageKindAddOn, Remain: int64(q.AddOnQuota.Remaining), Used: int64(q.AddOnQuota.Used), Size: int64(q.AddOnQuota.Total)},
		},
	}
	appendPool := func(pool quotaPool, fallbackName, kind string) {
		sum.TotalRemain += int64(pool.Remaining)
		sum.TotalUsed += int64(pool.Used)
		sum.TotalSize += int64(pool.Total)
		name := strings.TrimSpace(pool.Name)
		if name == "" {
			name = fallbackName
		}
		row := packageSummary{Name: name, Kind: kind, Remain: int64(pool.Remaining), Used: int64(pool.Used), Size: int64(pool.Total)}
		row.ExpiresAt, row.NeverExpires, row.Expired = poolExpiry(pool, time.Now())
		if kind == packageKindActivity {
			row.Activity = true
			sum.ActivityRemain += row.Remain
			sum.ActivityUsed += row.Used
			sum.ActivitySize += row.Size
			sum.ActivityPacks++
			// The soonest future expiry drives the panel's "活动积分 X 月底到期"
			// hint; an expired row never becomes the headline.
			if row.ExpiresAt != "" && !row.Expired &&
				(sum.ActivityExpiring == "" || row.ExpiresAt < sum.ActivityExpiring) {
				sum.ActivityExpiring = row.ExpiresAt
			}
		}
		sum.Packages = append(sum.Packages, row)
		sum.PackCount++
	}
	for i, pool := range q.DedicatedResourcePackages {
		appendPool(pool, fmt.Sprintf("专用资源包 %d", i+1), packageKindActivity)
	}
	if q.OrgResourcePackage != nil {
		appendPool(*q.OrgResourcePackage, "组织共享池", packageKindOrg)
	}
	return sum
}

// poolExpiry resolves a pool's expiry into (RFC3339, neverExpires, expired).
// Upstream is inconsistent: ms epoch, s epoch, ISO strings and the 9999
// sentinel all appear across regions and client versions, and a missing
// field must stay missing (empty string) rather than be invented.
func poolExpiry(pool quotaPool, now time.Time) (string, bool, bool) {
	if pool.NeverExpires || pool.UnlimitedExpire {
		return "", true, false
	}
	raw, ok := firstNonNil(pool.ExpiresAt, pool.ExpireAt, pool.EndTime, pool.ExpireTime, pool.ExpirationTime)
	if !ok {
		return "", false, false
	}
	t, never, ok := parsePoolExpiry(raw)
	if !ok {
		// "Present but not an instant" (a bare day counter) is not the same
		// as "field absent"; report unknown rather than invent an expiry.
		return "", false, false
	}
	if never {
		return "", true, false
	}
	return t.Format("2006-01-02T15:04:05+08:00"), false, !t.After(now)
}

func firstNonNil(vals ...any) (any, bool) {
	for _, v := range vals {
		if v != nil {
			return v, true
		}
	}
	return nil, false
}

// parsePoolExpiry accepts the encodings upstream uses and reports the
// no-expiry sentinel separately so the caller can label it honestly.
func parsePoolExpiry(raw any) (time.Time, bool, bool) {
	china := time.FixedZone("UTC+8", 8*3600)
	switch v := raw.(type) {
	case float64:
		return epochToTime(int64(v), china)
	case int64:
		return epochToTime(v, china)
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return time.Time{}, false, false
		}
		return epochToTime(n, china)
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return time.Time{}, false, false
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return epochToTime(n, china)
		}
		for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.In(china), false, true
			}
		}
	}
	return time.Time{}, false, false
}

// epochToTime classifies an epoch as seconds or milliseconds (anything past
// 1e11 is milliseconds). The small-value band (9999, 9999-12-31 in seconds)
// is the "never expires" sentinel family, NOT a real instant — treating it
// as one would render "1970-01-01" for a pack that never expires.
func epochToTime(n int64, loc *time.Location) (time.Time, bool, bool) {
	if n <= 0 {
		return time.Time{}, false, false
	}
	if n == noExpirySentinel || n == 9999999999 || n == 9999999999999 {
		return time.Time{}, true, true
	}
	const sentinelFloor = int64(253402300799) // 9999-12-31 23:59:59 UTC, seconds
	if n < 100000 {
		// A bare day counter (e.g. 30) is a duration, not an instant.
		return time.Time{}, false, false
	}
	if n < 100000000000 { // < 1e11 → seconds
		if n >= sentinelFloor {
			return time.Time{}, true, true
		}
		return time.Unix(n, 0).In(loc), false, true
	}
	if n > sentinelFloor*1000 {
		return time.Time{}, true, true
	}
	return time.UnixMilli(n).In(loc), false, true
}

// planResponse mirrors GET /api/v2/user/plan (plain JSON, no envelope).
type planResponse struct {
	UserType       string          `json:"user_type"`
	PlanTierName   string          `json:"plan_tier_name"`
	IsPersonal     bool            `json:"is_personal_version"`
	IsPaid         bool            `json:"is_paid_plan"`
	IsHighestTier  bool            `json:"is_highest_tier"`
	FeatureAllowed map[string]bool `json:"feature_allowed"`
	StartDate      int64           `json:"start_date"` // ms epoch
	EndDate        int64           `json:"end_date"`   // ms epoch
}

func fetchPaymentType(sa *storedAuth) string {
	base := billingBaseFor(sa)
	req, err := http.NewRequest(http.MethodGet, base+"/api/v2/user/plan", nil)
	if err != nil {
		return ""
	}
	billingHeaders(req, sa)
	resp, err := hostHTTPDo(req)
	if err != nil || resp.StatusCode >= 400 {
		return ""
	}
	absorbBillingResponse(sa, base, resp)
	var p planResponse
	if err := json.Unmarshal(resp.Body, &p); err != nil {
		return ""
	}
	// Prefer plan_tier_name (e.g. "Pro Trial") over the raw user_type string.
	if p.PlanTierName != "" {
		return p.PlanTierName
	}
	return p.UserType
}

// performCheckinCall claims one account's daily benefit. v0.12.80: both
// regions ride the campaigns claim (the only system that actually grants
// credits). The legacy CN daily-check-in/claim endpoint is DISABLED upstream
// — it answers 409 even on unclaimed days and grants nothing (2026-09-21
// upstream verification) — so calling it can only misreport "已签/失败";
// the v0.8.8 ALREADY_CLAIMED normalization here became dead weight and was
// removed with the legacy claim path. If upstream ever restores the legacy
// system, re-add the claim beside the read-only status probe.
func performCheckinCall(sa *storedAuth) (map[string]any, error) {
	return performCampaignCheckin(sa)
}

// isCreditsExhausted is the shared "耗尽" definition for panel + scheduler.
// Exhausted = we have usage signal and no remaining credits.
// Missing credits data is NOT exhausted (unknown).
func isCreditsExhausted(cr *creditsSummary) bool {
	if cr == nil {
		return false
	}
	if cr.TotalRemain > 0 {
		return false
	}
	// remain==0: exhausted only when we know there was/is a package total
	// (used>0, size>0, or packages present). Pure zero with no packages = no data.
	if cr.TotalUsed > 0 || cr.TotalSize > 0 {
		return true
	}
	return len(cr.Packages) > 0
}
