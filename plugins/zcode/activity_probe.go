// activity_probe.go — v0.2.1: "上游有活动、我们这里显示没有" 的第二个来源。
//
// Before this file the plugin only asked ONE question when looking for
// campaigns: billing/preview ("is there a plan I can claim?"). A deployed
// campaign answers that with plans: []; an account that is not eligible
// answers exactly the same, and so does a campaign that ran out of stock.
// Measured 2026-10-23 on the live start-plan account: preview → plans[],
// balance → balances[] — both empty while the account had plan JWT and an
// active coding-plan key. The chat plane itself proves activity grants exist
// (plane.go: weekend/activity buckets name their covered models), so the
// silence is a blind spot, not proof.
//
// So: probe every other endpoint that can announce a campaign, and always
// report the probe itself — the panel shows "没有可领取的活动" only together
// with WHEN and HOW it was checked. Endpoints:
//
//	GET  {zcodeAPIBase}/zcode-plan/billing/preview   claimable plans (existing)
//	GET  {zcodeAPIBase}/zcode-plan/billing/balance   granted buckets (existing)
//	GET  {offPeakBase}/api/v1/off-peak/ticket/availability
//	                                               off-peak lane admission
//	GET  {zcodeAPIBase}/api/v1/system/resource-packages/config?host=zcode.z.ai
//	                                               the desktop client's activity
//	                                               banner feed (open-source client:
//	                                               packages/services/.../resourcePackage.ts)
//
// A probe error is a finding ("问了，但上游没答"), never a silent empty
// list; a bare 404 page (no JSON envelope) means the route does not exist
// on this deployment and is reported as "route absent".
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	probeStatusOK      = "ok"
	probeStatusEmpty   = "empty"
	probeStatusMissing = "route_absent"
	probeStatusNoAuth  = "skipped"
	probeStatusError   = "error"

	resourcePackagesTimeout = 12 * time.Second
	previewTimeout          = 15 * time.Second
	offPeakProbeTimeout     = 10 * time.Second
)

// resourcePackagesPath is the desktop client's campaign feed. It sits at
// the site root (not under zcodeAPIBase's /api/v1), so it is joined onto the
// origin instead of the API base.
const (
	resourcePackagesPath = "/api/v1/system/resource-packages/config"
	// sweepAPIBase is the root under which the probe's non-billing routes live.
	sweepAPIBase = "/api/v1"
)

// resourcePackageActivity is one banner item (title/summary/period), kept
// loose: the live server may rename fields, and an empty item is still
// better than a disappeared banner.
type resourcePackageActivity struct {
	ID       string `json:"id,omitempty"`
	Title    string `json:"title,omitempty"`
	Summary  string `json:"summary,omitempty"`
	Image    string `json:"image,omitempty"`
	Link     string `json:"link,omitempty"`
	StartsAt int64  `json:"starts_at,omitempty"`
	EndsAt   int64  `json:"ends_at,omitempty"`
	Raw      string `json:"raw,omitempty"`
}

// activityProbe is one endpoint's outcome.
type activityProbe struct {
	Name       string                    `json:"name"`
	URL        string                    `json:"url"`
	Status     string                    `json:"status"`
	HTTPStatus int                       `json:"http_status,omitempty"`
	Items      int                       `json:"items"`
	Note       string                    `json:"note,omitempty"`
	Error      string                    `json:"error,omitempty"`
	CheckedAt  string                    `json:"checked_at"`
	DurationMS int64                     `json:"duration_ms"`
	Activities []resourcePackageActivity `json:"activities,omitempty"`
}

// activityProbeCache keeps the last non-empty campaign feed per account for
// a short while: a flaky fetch must not turn "有一个活动" into "没有活动".
type probeCacheEntry struct {
	at         time.Time
	activities []resourcePackageActivity
}

var (
	probeCacheMu sync.Mutex
	probeCache   = map[string]probeCacheEntry{}
)

func probeCacheGet(key string) ([]resourcePackageActivity, time.Time, bool) {
	probeCacheMu.Lock()
	defer probeCacheMu.Unlock()
	e, ok := probeCache[key]
	return e.activities, e.at, ok
}

func probeCachePut(key string, list []resourcePackageActivity) {
	probeCacheMu.Lock()
	defer probeCacheMu.Unlock()
	if len(list) == 0 {
		return
	}
	probeCache[key] = probeCacheEntry{at: time.Now(), activities: list}
}

// resourcePackagesEndpoint builds the banner-feed URL for the configured
// app version; host defaults to the billing host.
func resourcePackagesEndpoint(id identityConfigSnapshot) string {
	q := url.Values{}
	q.Set("host", "zcode.z.ai")
	if id.appVersion != "" {
		q.Set("app_version", id.appVersion)
	}
	if id.platformValue != "" {
		q.Set("platform", id.platformValue)
	}
	return zcodeOrigin() + sweepAPIBase + strings.TrimPrefix(resourcePackagesPath, sweepAPIBase) + "?" + q.Encode()
}

// fetchResourcePackages reads the banner feed. Unauthenticated on the
// desktop client (it loads before login), so the JWT is attached when
// present but its absence is not an error.
func fetchResourcePackages(ctx context.Context, sa *storedAuth) ([]resourcePackageActivity, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	id := zcodeIdentity()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resourcePackagesEndpoint(id), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range buildContextIdentityHeaders(id, sa.Auth.DeviceMid) {
		req.Header.Set(k, v)
	}
	if strings.TrimSpace(sa.Auth.JWT) != "" {
		req.Header.Set("Authorization", "Bearer "+sa.Auth.JWT)
	}
	resp, err := hostHTTPDo(req)
	if err != nil {
		return nil, 0, err
	}
	body := strings.TrimSpace(string(resp.Body))
	var envelope struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(resp.Body, &envelope) != nil || envelope.Data == nil {
		if resp.StatusCode == http.StatusNotFound {
			return nil, resp.StatusCode, errRouteAbsent
		}
		return nil, resp.StatusCode, fmt.Errorf("http %d non-json body: %s", resp.StatusCode, truncateRedacted(body, 120))
	}
	if resp.StatusCode >= 400 || (envelope.Code != 0 && envelope.Code != 200) {
		return nil, resp.StatusCode, fmt.Errorf("http %d code %d body: %s", resp.StatusCode, envelope.Code, truncateRedacted(body, 160))
	}
	return parseResourcePackages(envelope.Data), resp.StatusCode, nil
}

// errRouteAbsent marks a 404 page — the endpoint does not exist here.
var errRouteAbsent = fmt.Errorf("route absent (404)")

// parseResourcePackages accepts the shapes seen across zcode desktop
// versions: data as a list, data.items, data.packages, data.list, data.activities.
func parseResourcePackages(raw json.RawMessage) []resourcePackageActivity {
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil {
		var obj map[string]any
		if err2 := json.Unmarshal(raw, &obj); err2 != nil {
			return nil
		}
		for _, key := range []string{"items", "packages", "list", "activities", "resource_packages", "resourcePackages"} {
			if arr, ok := obj[key].([]any); ok {
				for _, it := range arr {
					if m, ok := it.(map[string]any); ok {
						list = append(list, m)
					}
				}
				break
			}
		}
	}
	out := make([]resourcePackageActivity, 0, len(list))
	for _, m := range list {
		a := resourcePackageActivity{
			Title:   firstNonEmpty(strField(m, "title", "name", "show_name", "showName"), "活动"),
			Summary: strField(m, "summary", "description", "desc", "subtitle"),
			Image:   strField(m, "image", "image_url", "imageUrl", "banner", "banner_url"),
			Link:    strField(m, "link", "url", "jump_url", "jumpUrl", "redirect_url"),
		}
		a.ID = strField(m, "id", "package_id", "packageId", "resource_package_id")
		a.StartsAt = int64Field(m, "starts_at", "start_time", "startTime", "begin_time", "beginTime")
		a.EndsAt = int64Field(m, "ends_at", "end_time", "endTime", "expire_time", "expireTime")
		raw, _ := json.Marshal(m)
		a.Raw = truncateRedacted(string(raw), 400)
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].EndsAt > out[j].EndsAt })
	return out
}

func strField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

func int64Field(m map[string]any, keys ...string) int64 {
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			if v == v && v != 0 {
				return int64(v)
			}
		case json.Number:
			if n, err := v.Int64(); err == nil && n != 0 {
				return n
			}
		case string:
			if n, err := time.Parse(time.RFC3339, v); err == nil {
				return n.Unix()
			}
		}
	}
	return 0
}

// probeActivity feeds runs every campaign-related probe for one account.
// Sequential on purpose: this rides the panel refresh, not the request path.
func probeActivityFeeds(authIndex string, sa *storedAuth) ([]activityProbe, []previewPlan) {
	if sa == nil {
		sa = &storedAuth{}
	}
	probes := []activityProbe{}

	// 1. banner feed (the one the desktop client renders).
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), resourcePackagesTimeout)
	acts, httpStatus, err := fetchResourcePackages(ctx, sa)
	cancel()
	entry := activityProbe{
		Name:       "活动横幅 (resource-packages)",
		URL:        resourcePackagesPath,
		HTTPStatus: httpStatus,
		CheckedAt:  start.UTC().Format(time.RFC3339),
		DurationMS: time.Since(start).Milliseconds(),
	}
	key := authIndex
	switch {
	case err == errRouteAbsent:
		entry.Status, entry.Note = probeStatusMissing, "该部署没有这个接口（返回 404 页面）"
	case err != nil:
		entry.Status, entry.Error = probeStatusError, err.Error()
	case len(acts) == 0:
		entry.Status, entry.Note = probeStatusEmpty, "上游答了，但没有挂活动"
	default:
		entry.Status, entry.Items, entry.Activities = probeStatusOK, len(acts), acts
		probeCachePut(key, acts)
	}
	if entry.Status == probeStatusError || entry.Status == probeStatusEmpty || entry.Status == probeStatusMissing {
		if cached, at, ok := probeCacheGet(key); ok && time.Since(at) < 24*time.Hour {
			entry.Note = firstNonEmpty(entry.Note+"；", "") + "沿用 " + at.Format("01-02 15:04") + " 拉到的那次结果（" + fmt.Sprint(len(cached)) + " 条）"
			entry.Activities = cached
			entry.Items = len(cached)
		}
	}
	probes = append(probes, entry)

	// 2. claimable preview (existing plane) — reported, not re-fetched.
	start = time.Now()
	var plans []previewPlan
	var perr error
	if strings.TrimSpace(sa.Auth.JWT) != "" {
		pc, pcancel := context.WithTimeout(context.Background(), previewTimeout)
		plans, perr = fetchClaimablePreviewCtx(pc, sa)
		pcancel()
	}
	entry = activityProbe{
		Name:       "可领取套餐 (billing/preview)",
		URL:        zcodeAPIBase + "/zcode-plan/billing/preview",
		CheckedAt:  start.UTC().Format(time.RFC3339),
		DurationMS: time.Since(start).Milliseconds(),
	}
	switch {
	case strings.TrimSpace(sa.Auth.JWT) == "":
		entry.Status, entry.Note = probeStatusNoAuth, "账号没有 plan JWT，无法查询（重新登录补齐）"
	case perr != nil:
		entry.Status, entry.Error = probeStatusError, perr.Error()
	case len(plans) == 0:
		entry.Status, entry.Note = probeStatusEmpty, "没有可领取的套餐"
	default:
		entry.Status, entry.Items = probeStatusOK, len(plans)
	}
	probes = append(probes, entry)

	// 3. granted buckets (billing/balance) — already cached by the dashboard;
	//    reuse that cache so a refresh does not double-fetch.
	start = time.Now()
	entry = activityProbe{
		Name:      "已发放额度池 (billing/balance)",
		URL:       zcodeAPIBase + "/zcode-plan/billing/balance",
		CheckedAt: start.UTC().Format(time.RFC3339),
	}
	cr := cachedCreditsFor(authIndex)
	if cr == nil && strings.TrimSpace(sa.Auth.JWT) != "" {
		// The dashboard cache may be cold (first panel load, or the panel was
		// never opened); fetch once so this row is a measurement, not a gap.
		qc, qerr := fetchQuotaSnapshot(sa)
		if qerr != nil {
			entry.Status, entry.Error = probeStatusError, qerr.Error()
		} else {
			cr = qc
		}
	}
	if cr != nil {
		entry.Items = len(cr.Packages)
		if len(cr.Packages) == 0 {
			entry.Status, entry.Note = probeStatusEmpty, "上游答了，但没有任何额度池（活动包通常落在这里）"
		} else {
			entry.Status = probeStatusOK
		}
	} else if entry.Status == "" {
		entry.Status, entry.Note = probeStatusError, "额度没拉到"
	}
	probes = append(probes, entry)

	// 4. off-peak lane admission.
	start = time.Now()
	entry = activityProbe{
		Name:      "闲时通道 (off-peak availability)",
		URL:       offPeakBase + offPeakAvailabilityPath,
		CheckedAt: start.UTC().Format(time.RFC3339),
	}
	oc, ocancel := context.WithTimeout(context.Background(), offPeakProbeTimeout)
	av, oerr := offPeakQueryAvailabilityCtx(oc, sa)
	ocancel()
	switch {
	case oerr == nil && av != nil && av.CanTakeNumber:
		entry.Status, entry.Note = probeStatusOK, "现在可以取号"
	case oerr == nil && av != nil:
		entry.Status, entry.Note = probeStatusOK, "暂不可取号（有 next_take_at）"
	case oerr != nil && strings.Contains(oerr.Error(), "3101"):
		entry.Status, entry.Note = probeStatusEmpty, "start-plan 不参与闲时通道（coding plan is required）"
	case oerr != nil:
		entry.Status, entry.Error = probeStatusError, oerr.Error()
	}
	entry.DurationMS = time.Since(start).Milliseconds()
	probes = append(probes, entry)

	return probes, plans
}

// cachedCreditsFor returns the dashboard's cached credits for an account,
// if the cache has been filled.
func cachedCreditsFor(authIndex string) *creditsSummary {
	if authIndex == "" {
		return nil
	}
	if v, ok := accountCache.Load(authIndex); ok {
		if e, ok2 := v.(*accountCacheEntry); ok2 {
			return e.credits
		}
	}
	return nil
}

// zcodeOrigin derives the site origin from zcodeAPIBase, so tests that
// point the API base at an httptest server also redirect the sweep routes.
func zcodeOrigin() string {
	base := strings.TrimRight(zcodeAPIBase, "/")
	for _, suffix := range []string{sweepAPIBase} {
		if strings.HasSuffix(base, suffix) {
			return strings.TrimSuffix(base, suffix)
		}
	}
	return base
}
