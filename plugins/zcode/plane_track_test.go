// plane_track_test.go covers the per-plane request accounting behind the
// panel's "which channel actually served this" view, and the entitlement-cache
// invalidation a credential mutation has to perform.
package main

import (
	"testing"
	"time"
)

func resetPlaneStatsForTest(t *testing.T) {
	t.Helper()
	resetPlaneStats()
	t.Cleanup(resetPlaneStats)
}

func testAuthWithUID(uid string) *storedAuth {
	return &storedAuth{
		// JWT is required for the entitlement override to have any effect
		// (modelRidesStartPlane bails on an empty one).
		Auth:    zcodeTokens{AccessToken: "a.b", JWT: "j", Provider: providerZai, Plan: planCoding},
		Account: zcodeAccount{UID: uid},
	}
}

func TestRecordPlaneHitCountsAndAttributes(t *testing.T) {
	resetPlaneStatsForTest(t)
	fixed := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	planeNowFn = func() time.Time { return fixed }
	t.Cleanup(func() { planeNowFn = time.Now })

	recordPlaneHit(planeZaiCoding, testAuthWithUID("uid-zai-1"))
	recordPlaneHit(planeZaiCoding, testAuthWithUID("uid-zai-2"))
	recordPlaneHit(planeJWTAnthropic, testAuthWithUID("uid-jwt"))

	snap := planeSnapshot()
	rows, ok := snap["planes"].([]map[string]any)
	if !ok {
		t.Fatalf("planes row type = %T", snap["planes"])
	}
	byID := map[string]map[string]any{}
	for _, r := range rows {
		byID[r["id"].(string)] = r
	}

	if got := byID[planeZaiCoding]["hits"]; got != int64(2) {
		t.Fatalf("zai hits = %v, want 2", got)
	}
	if got := byID[planeJWTAnthropic]["hits"]; got != int64(1) {
		t.Fatalf("jwt hits = %v, want 1", got)
	}
	if got := snap["total"]; got != int64(3) {
		t.Fatalf("total = %v, want 3", got)
	}
	// Last-writer attribution, with the timestamp from the injected clock.
	if got := byID[planeZaiCoding]["last_auth"]; got != "uid-zai-2" {
		t.Fatalf("zai last_auth = %v, want uid-zai-2", got)
	}
	if got := byID[planeZaiCoding]["last_at"]; got != "2026-10-16 12:00:00" {
		t.Fatalf("zai last_at = %v", got)
	}
}

// A plane with no traffic must still be listed, so "unused" is visible rather
// than indistinguishable from "missing".
func TestPlaneSnapshotListsIdlePlanes(t *testing.T) {
	resetPlaneStatsForTest(t)
	snap := planeSnapshot()
	rows := snap["planes"].([]map[string]any)
	if len(rows) != len(planeCatalog) {
		t.Fatalf("rows = %d, want %d (one per catalog plane)", len(rows), len(planeCatalog))
	}
	for _, r := range rows {
		if got := r["hits"]; got != int64(0) {
			t.Fatalf("idle plane %v hits = %v, want 0", r["id"], got)
		}
	}
	if snap["persistent"] != false {
		t.Fatalf("persistent = %v, want false", snap["persistent"])
	}
}

// An unknown plane name must not vanish from the totals the operator reads.
func TestPlaneSnapshotKeepsUnregisteredPlane(t *testing.T) {
	resetPlaneStatsForTest(t)
	recordPlaneHit("some-future-plane", nil)
	snap := planeSnapshot()
	if got := snap["total"]; got != int64(1) {
		t.Fatalf("total = %v, want 1", got)
	}
}

func TestRecordPlaneHitWithoutAuth(t *testing.T) {
	resetPlaneStatsForTest(t)
	// An empty plane name must land under the unknown bucket rather than
	// creating a nameless entry.
	recordPlaneHit("", nil)
	snap := planeSnapshot()
	rows := snap["planes"].([]map[string]any)
	var found bool
	for _, r := range rows {
		if r["id"] == planeUnknown {
			found = true
			if r["hits"] != int64(1) {
				t.Fatalf("unknown hits = %v", r["hits"])
			}
			if _, has := r["last_auth"]; has {
				t.Fatalf("unknown row should carry no last_auth")
			}
		}
	}
	if !found {
		t.Fatalf("unknown plane missing from snapshot")
	}
}

func TestRecordPlaneFallbackCounts(t *testing.T) {
	resetPlaneStatsForTest(t)
	fixed := time.Date(2026, 10, 16, 9, 30, 0, 0, time.UTC)
	fallbackNowFn = func() time.Time { return fixed }
	t.Cleanup(func() { fallbackNowFn = time.Now })

	recordPlaneFallback(testAuthWithUID("uid-fb"))
	snap := planeSnapshot()
	fb := snap["fallback"].(map[string]any)
	if fb["activations"] != int64(1) {
		t.Fatalf("activations = %v, want 1", fb["activations"])
	}
	if fb["last_auth"] != "uid-fb" {
		t.Fatalf("last_auth = %v", fb["last_auth"])
	}
	if fb["last_at"] != "2026-10-16 09:30:00" {
		t.Fatalf("last_at = %v", fb["last_at"])
	}
}

// The 6h entitlement snapshot had no expiry path before this; a credential
// mutation must be able to drop one account without disturbing the others.
func TestClearStartPlane(t *testing.T) {
	resetStartPlane(t)
	harvestStartPlaneCapabilities("uid-a", []zcodeBalance{{Capabilities: []string{"model:glm-5.3-flash"}}})
	harvestStartPlaneCapabilities("uid-b", []zcodeBalance{{Capabilities: []string{"model:glm-5.2"}}})

	sa := testAuthWithUID("uid-a")
	if !modelRidesStartPlane(sa, "glm-5.3-flash") {
		t.Fatalf("precondition: uid-a should ride the JWT plane for glm-5.3-flash")
	}
	if got := clearStartPlane("uid-a"); got != 1 {
		t.Fatalf("clearStartPlane(uid-a) = %d, want 1", got)
	}
	if modelRidesStartPlane(sa, "glm-5.3-flash") {
		t.Fatalf("uid-a still rides the JWT plane after clear")
	}
	// Scoped: the other account keeps its snapshot.
	if !modelRidesStartPlane(testAuthWithUID("uid-b"), "glm-5.2") {
		t.Fatalf("clearStartPlane(uid-a) must not disturb uid-b")
	}
	// Clearing an absent account is a no-op; the empty UID clears everything.
	if got := clearStartPlane("uid-absent"); got != 0 {
		t.Fatalf("clearStartPlane(absent) = %d, want 0", got)
	}
	if got := clearStartPlane(""); got != 1 {
		t.Fatalf("clearStartPlane(all) = %d, want 1 remaining", got)
	}
	if modelRidesStartPlane(testAuthWithUID("uid-b"), "glm-5.2") {
		t.Fatalf("uid-b survived a clear-all")
	}
}

// routeFor is the single decision point for the planes; the label it stamps is
// what the dispatch sites count.
func TestRouteForStampsPlane(t *testing.T) {
	resetStartPlane(t)

	zai := &storedAuth{
		Auth:    zcodeTokens{AccessToken: "a.b", JWT: "j", Provider: providerZai, Plan: planCoding},
		Account: zcodeAccount{UID: "uid-zai"},
	}
	bm := &storedAuth{
		Auth:    zcodeTokens{AccessToken: "a.b", JWT: "j", Provider: providerBigmodel, Plan: planCoding},
		Account: zcodeAccount{UID: "uid-bm"},
	}
	start := &storedAuth{
		Auth:    zcodeTokens{AccessToken: "a.b", JWT: "j", Provider: providerZai, Plan: planStart},
		Account: zcodeAccount{UID: "uid-start"},
	}

	if got := routeFor(zai, "glm-5.3").plane; got != planeZaiCoding {
		t.Fatalf("zai coding-plane route = %q, want %q", got, planeZaiCoding)
	}
	if got := routeFor(bm, "glm-5.3").plane; got != planeBigmodelCoding {
		t.Fatalf("bigmodel route = %q, want %q", got, planeBigmodelCoding)
	}
	if got := routeFor(start, "glm-5.3").plane; got != planeJWTAnthropic {
		t.Fatalf("start-plan route = %q, want %q", got, planeJWTAnthropic)
	}
	// The reactive fallback reuses the anthropic endpoint, so it must carry the
	// same plane identity as the proactive route.
	if got := startPlaneFallbackRoute().plane; got != planeJWTAnthropic {
		t.Fatalf("fallback route plane = %q, want %q", got, planeJWTAnthropic)
	}
	if got := offPeakRouteFor(zai, "ticket-1").plane; got != planeOffPeak {
		t.Fatalf("off-peak route plane = %q, want %q", got, planeOffPeak)
	}
}

// A coding-plane credential whose model entitlement only lives on the JWT
// plane must route there proactively, and the label must follow.
func TestRouteForStampsPlaneOnEntitlementOverride(t *testing.T) {
	resetStartPlane(t)
	sa := &storedAuth{
		Auth:    zcodeTokens{AccessToken: "a.b", JWT: "j", Provider: providerZai, Plan: planCoding},
		Account: zcodeAccount{UID: "uid-ovr"},
	}
	harvestStartPlaneCapabilities("uid-ovr", []zcodeBalance{{Capabilities: []string{"model:glm-5.3-flash"}}})

	if got := routeFor(sa, "glm-5.3-flash").plane; got != planeJWTAnthropic {
		t.Fatalf("entitlement-override route = %q, want %q", got, planeJWTAnthropic)
	}
	// A model with no harvested entitlement stays on the coding plane.
	if got := routeFor(sa, "glm-5.3").plane; got != planeZaiCoding {
		t.Fatalf("non-override route = %q, want %q", got, planeZaiCoding)
	}
}
