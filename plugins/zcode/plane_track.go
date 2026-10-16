// plane_track.go owns the per-plane request accounting behind the panel's
// "which channel actually served this request" view.
//
// zcode sends a chat completion down one of three upstream planes (plus the
// off-peak lane), and the choice is implicit: the coding-plane *host* comes
// from auth.Provider, the anthropic plane from auth.Plan plus the entitlement
// override in plane.go, and the off-peak lane from config. Nothing surfaced
// which one a request actually rode, so diagnosing "why is this model 429ing"
// meant reading logs. This file records one hit per dispatched send plus a
// separate counter for reactive JWT-plane fallbacks, so the dashboard can show
// both volume per plane and how often the primary route turned out to be wrong.
//
// State is process-local by design, matching cooldown.go: it survives config
// reloads but not a CPA restart, and the management response says so.
package main

import (
	"sort"
	"sync"
	"time"
)

// Plane identities. These are the stable keys the panel renders and the
// counters are stored under; add new ones here rather than inline so
// planeSnapshot and the panel label table stay in sync.
const (
	planeZaiCoding      = "zai-coding"
	planeBigmodelCoding = "bigmodel-coding"
	planeJWTAnthropic   = "jwt-anthropic"
	planeOffPeak        = "off-peak"
	planeUnknown        = "unknown"
)

// planeMeta is the display table: id, human label, and the one-line "what this
// actually is" the panel shows under the label. The panel renders whatever
// this says instead of hardcoding the three names, so adding a plane here is
// enough to make it appear.
type planeMeta struct {
	ID    string
	Label string
	Note  string
}

var planeCatalog = []planeMeta{
	{planeZaiCoding, "Z.AI Coding", "api.z.ai · OpenAI 方言 · 解析出的 plan key"},
	{planeBigmodelCoding, "BigModel Coding", "open.bigmodel.cn · OpenAI 方言 · 解析出的 plan key"},
	{planeJWTAnthropic, "ZCode JWT", "zcode.z.ai · Anthropic 方言 · plan JWT（start-plan / 活动套餐）"},
	{planeOffPeak, "Off-Peak", "zcode.z.ai 闲时凭票通道 · 需先取号"},
}

// planeStat is one plane's counters. LastAuth carries the sanitized UID of the
// most recent account to ride the plane, which is what makes "this model only
// ever goes down one account's plane" legible.
type planeStat struct {
	Hits     int64
	LastAt   time.Time
	LastAuth string
}

var (
	planeStatsMu sync.Mutex
	planeStats   = map[string]planeStat{}
	planeNowFn   = time.Now
)

// recordPlaneHit counts one dispatched send on a plane. Called immediately
// before the request goes out, not when the route is built, because a route can
// be constructed and then abandoned (a denied fallback, a dry captcha pool).
func recordPlaneHit(plane string, sa *storedAuth) {
	if plane == "" {
		plane = planeUnknown
	}
	authID := ""
	if sa != nil {
		authID = sanitizeUIDForFileName(sa.Account.UID)
	}
	now := planeNowFn()
	planeStatsMu.Lock()
	st := planeStats[plane]
	st.Hits++
	st.LastAt = now
	if authID != "" {
		st.LastAuth = authID
	}
	planeStats[plane] = st
	planeStatsMu.Unlock()
}

// fallbackStat counts reactive JWT-plane fallbacks: a coding-plane send that
// failed with no-resource-package semantics and was retried on the anthropic
// plane (see plane.go). A non-zero count means the pre-routing harvest did not
// know about an entitlement the account actually had.
type fallbackStat struct {
	Activations int64
	LastAt      time.Time
	LastAuth    string
}

var (
	fallbackMu    sync.Mutex
	fallbacks     fallbackStat
	fallbackNowFn = time.Now
)

// recordPlaneFallback counts one reactive fallback activation.
func recordPlaneFallback(sa *storedAuth) {
	authID := ""
	if sa != nil {
		authID = sanitizeUIDForFileName(sa.Account.UID)
	}
	now := fallbackNowFn()
	fallbackMu.Lock()
	fallbacks.Activations++
	fallbacks.LastAt = now
	if authID != "" {
		fallbacks.LastAuth = authID
	}
	fallbackMu.Unlock()
}

// planeSnapshot renders the counters for the panel: one row per catalog plane
// (including zero-hit ones, so an unused plane is visibly unused rather than
// absent), plus any plane that recorded a hit without a catalog entry.
func planeSnapshot() map[string]any {
	planeStatsMu.Lock()
	stats := make(map[string]planeStat, len(planeStats))
	for k, v := range planeStats {
		stats[k] = v
	}
	planeStatsMu.Unlock()

	seen := make(map[string]bool, len(planeCatalog))
	rows := make([]map[string]any, 0, len(planeCatalog)+1)
	for _, meta := range planeCatalog {
		seen[meta.ID] = true
		rows = append(rows, planeRow(meta, stats[meta.ID]))
	}
	// A plane that recorded traffic but lost its catalog entry (renamed id,
	// stale counter) still shows up rather than silently vanishing from the
	// totals the operator is reading.
	extra := make([]string, 0)
	for id := range stats {
		if !seen[id] {
			extra = append(extra, id)
		}
	}
	sort.Strings(extra)
	for _, id := range extra {
		rows = append(rows, planeRow(planeMeta{ID: id, Label: id, Note: "未登记的通道"}, stats[id]))
	}

	var total int64
	for _, s := range stats {
		total += s.Hits
	}

	fallbackMu.Lock()
	fb := fallbacks
	fallbackMu.Unlock()

	return map[string]any{
		"planes":   rows,
		"total":    total,
		"fallback": fallbackRow(fb),
		// Mirrors cooldown.go's contract: in-memory, gone on restart.
		"persistent": false,
	}
}

func planeRow(meta planeMeta, st planeStat) map[string]any {
	row := map[string]any{
		"id":    meta.ID,
		"label": meta.Label,
		"note":  meta.Note,
		"hits":  st.Hits,
	}
	if !st.LastAt.IsZero() {
		row["last_at"] = st.LastAt.Format("2006-01-02 15:04:05")
	}
	if st.LastAuth != "" {
		row["last_auth"] = st.LastAuth
	}
	return row
}

func fallbackRow(fb fallbackStat) map[string]any {
	row := map[string]any{"activations": fb.Activations}
	if !fb.LastAt.IsZero() {
		row["last_at"] = fb.LastAt.Format("2006-01-02 15:04:05")
	}
	if fb.LastAuth != "" {
		row["last_auth"] = fb.LastAuth
	}
	return row
}

// resetPlaneStats clears the counters. Test seam only.
func resetPlaneStats() {
	planeStatsMu.Lock()
	planeStats = map[string]planeStat{}
	planeStatsMu.Unlock()
	fallbackMu.Lock()
	fallbacks = fallbackStat{}
	fallbackMu.Unlock()
}
