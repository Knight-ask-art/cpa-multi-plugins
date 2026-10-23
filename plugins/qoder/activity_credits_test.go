package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// TestSummarizeQuotaResponse_ActivityGrantsAreClassified pins v0.8.76: activity
// grants (check-in / campaign / SOTA packs) are their own subtotal, they still
// join Total*, and the org pool is NOT mistaken for an activity grant.
func TestSummarizeQuotaResponse_ActivityGrantsAreClassified(t *testing.T) {
	q := quotaUsageResponse{}
	q.UserQuota.Total, q.UserQuota.Used, q.UserQuota.Remaining = 1000, 200, 800
	q.AddOnQuota.Total, q.AddOnQuota.Used, q.AddOnQuota.Remaining = 100, 40, 60
	q.DedicatedResourcePackages = []quotaPool{
		{Name: "每日签到 100", Total: 100, Used: 0, Remaining: 100},
		{Name: "Pro 升级包", Total: 1800, Used: 300, Remaining: 1500},
	}
	q.OrgResourcePackage = &quotaPool{Name: "团队池", Total: 500, Used: 100, Remaining: 400}

	sum := summarizeQuotaResponse(q)

	// Totals still cover every package — no consumer loses money it can spend.
	if sum.TotalRemain != 800+60+100+1500+400 || sum.TotalSize != 1000+100+100+1800+500 {
		t.Fatalf("totals drifted: %+v", sum)
	}
	if sum.ActivityRemain != 1600 || sum.ActivitySize != 1900 || sum.ActivityUsed != 300 {
		t.Fatalf("activity subtotal: remain=%d size=%d used=%d, want 1600/1900/300",
			sum.ActivityRemain, sum.ActivitySize, sum.ActivityUsed)
	}
	if sum.ActivityPacks != 2 {
		t.Fatalf("ActivityPacks = %d, want 2", sum.ActivityPacks)
	}
	// The org pool keeps its own kind and stays out of the activity subtotal.
	for _, p := range sum.Packages {
		if p.Name == "团队池" && (p.Kind != packageKindOrg || p.Activity) {
			t.Fatalf("org row classified as %q activity=%v", p.Kind, p.Activity)
		}
		if p.Name == "每日签到 100" && (!p.Activity || p.Kind != packageKindActivity) {
			t.Fatalf("activity row not classified: %+v", p)
		}
	}
}

// TestSummarizeQuotaResponse_ActivityExpiry: the soonest future expiry becomes
// the headline; an expired pack never does.
func TestSummarizeQuotaResponse_ActivityExpiry(t *testing.T) {
	future := time.Now().Add(72 * time.Hour).UnixMilli()
	soon := time.Now().Add(5 * time.Hour).UnixMilli()
	past := time.Now().Add(-48 * time.Hour).UnixMilli()
	q := quotaUsageResponse{}
	q.DedicatedResourcePackages = []quotaPool{
		{Name: "old", Total: 100, Remaining: 0, ExpiresAt: float64(past)},
		{Name: "later", Total: 100, Remaining: 100, ExpiresAt: float64(future)},
		{Name: "sooner", Total: 100, Remaining: 100, ExpiresAt: float64(soon)},
	}
	sum := summarizeQuotaResponse(q)
	want := time.UnixMilli(soon).Format("2006-01-02T15:04:05+08:00")
	if sum.ActivityExpiring != want {
		t.Fatalf("ActivityExpiring = %q, want %q", sum.ActivityExpiring, want)
	}
	var expired int
	for _, p := range sum.Packages {
		if p.Expired {
			expired++
		}
	}
	if expired != 1 {
		t.Fatalf("expired rows = %d, want 1", expired)
	}
}

// TestPoolExpiryEncodings: upstream reports expiry as ms, s, ISO and the 9999
// sentinel. Every spelling resolves; a missing field stays missing.
func TestPoolExpiryEncodings(t *testing.T) {
	now := time.Now()
	sec := now.Add(24 * time.Hour).Unix()
	ms := now.Add(24 * time.Hour).UnixMilli()
	cases := []struct {
		name  string
		pool  quotaPool
		never bool
		empty bool
	}{
		{"ms", quotaPool{ExpiresAt: float64(ms)}, false, false},
		{"seconds", quotaPool{ExpireAt: float64(sec)}, false, false},
		{"iso string", quotaPool{EndTime: now.Add(24 * time.Hour).Format(time.RFC3339)}, false, false},
		{"json number string", quotaPool{ExpireTime: json.Number("9999")}, true, true},
		{"sentinel 9999", quotaPool{ExpiresAt: float64(9999)}, true, true},
		{"sentinel 9999999999", quotaPool{ExpirationTime: float64(9999999999)}, true, true},
		{"neverExpires flag", quotaPool{NeverExpires: true}, true, true},
		{"absent", quotaPool{}, false, true},
		{"zero", quotaPool{ExpiresAt: float64(0)}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			iso, never, expired := poolExpiry(tc.pool, now)
			if never != tc.never {
				t.Fatalf("never = %v, want %v", never, tc.never)
			}
			if tc.empty && iso != "" {
				t.Fatalf("iso = %q, want empty", iso)
			}
			if !tc.empty && iso == "" && !never {
				t.Fatalf("iso empty for a present expiry")
			}
			if expired {
				t.Fatalf("future expiry reported as expired")
			}
		})
	}
}

// TestParsePoolExpiry_CustomTimeZone: the rendered form is +08:00 so the panel
// can slice the date without re-localising.
func TestParsePoolExpiry_CustomTimeZone(t *testing.T) {
	ms := time.Date(2026, 10, 31, 23, 59, 0, 0, time.FixedZone("CST", 8*3600)).UnixMilli()
	iso, never, expired := poolExpiry(quotaPool{ExpiresAt: float64(ms)}, time.Now())
	if never || expired {
		t.Fatalf("never=%v expired=%v", never, expired)
	}
	if iso != "2026-10-31T23:59:00+08:00" {
		t.Fatalf("iso = %q", iso)
	}
}

// TestPricePromotions_DFModelFallsBackAfterCampaign: the CN DeepSeek-Flash 0x
// campaign must stop advertising "free" once its end passes (dsh-our-free-model
// #518: a compiled table that only knows priceFactor=0 lies forever).
func TestPricePromotions_DFModelFallsBackAfterCampaign(t *testing.T) {
	during := time.Date(2026, 10, 20, 12, 0, 0, 0, time.FixedZone("CST", 8*3600))
	after := time.Date(2026, 10, 26, 0, 0, 0, 0, time.FixedZone("CST", 8*3600))

	d := pricePromotions(during)["dfmodel"]
	if !d.PromoActive || !d.LimitedFree || d.PriceFactor != 0 || d.OriginalPriceFactor != 0.1 {
		t.Fatalf("during campaign: %+v", d)
	}
	a := pricePromotions(after)["dfmodel"]
	if a.PromoActive || a.LimitedFree {
		t.Fatalf("after campaign still marked free: %+v", a)
	}
	if a.PriceFactor != 0.1 {
		t.Fatalf("after campaign price_factor = %v, want the regular 0.1", a.PriceFactor)
	}
}

// TestModelGroupEntries_CarryPriceCampaign: a catalog row whose raw key is in
// a price campaign surfaces it, so the picker can badge it.
func TestModelGroupEntries_CarryPriceCampaign(t *testing.T) {
	rows := modelGroupEntries("cn", []pluginapi.ModelInfo{{ID: "dfmodel", DisplayName: "DeepSeek-Flash"}})
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].Price == nil {
		t.Fatalf("dfmodel row lost its price campaign: %+v", rows[0])
	}
	if rows[0].Price.OriginalPriceFactor != 0.1 {
		t.Fatalf("original multiplier = %v", rows[0].Price.OriginalPriceFactor)
	}
	if again := strings.TrimSpace(rows[0].Price.FreeUntil); again == "" {
		t.Fatalf("promo end missing")
	}
	// The campaign was observed in CN only; an Intl row must not inherit it.
	intl := modelGroupEntries("intl", []pluginapi.ModelInfo{{ID: "dfmodel", DisplayName: "DeepSeek-Flash"}})
	if len(intl) != 1 || intl[0].Price != nil {
		t.Fatalf("intl inherited the CN campaign: %+v", intl)
	}
}
