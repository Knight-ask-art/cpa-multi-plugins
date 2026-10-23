// activity_probe_test.go pins v0.2.1: an empty "可领取活动" list must be
// explainable. The banner feed parse tolerates the shapes seen across
// desktop versions; a bare 404 page is "route absent" (not an error); a
// non-2xx JSON answer is an error carrying status and body; and the probe
// rows always report when they ran.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func probeTestAuth() *storedAuth {
	return &storedAuth{
		Auth: zcodeTokens{
			JWT:       "probe-jwt",
			DeviceMid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Provider:  providerZai,
		},
		Account: zcodeAccount{UID: "probe-user"},
	}
}

func TestParseResourcePackagesShapes(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int
	}{
		{"bare list", `[{"title":"国庆活动","summary":"s","ends_at":1760000000}]`, 1},
		{"data.items", `{"items":[{"name":"A"},{"name":"B"}]}`, 2},
		{"data.packages camel", `{"resourcePackages":[{"show_name":"C"}]}`, 1},
		{"data.activities", `{"activities":[{"title":"D"},{"title":"E"},{"title":"F"}]}`, 3},
		{"empty object", `{}`, 0},
		{"empty list", `[]`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseResourcePackages(json.RawMessage(tc.raw))
			if len(got) != tc.want {
				t.Fatalf("got %d items, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
	// Field aliases and the sort (latest end first).
	got := parseResourcePackages(json.RawMessage(`{"items":[
		{"package_id":"p1","showName":"早","description":"d1","endTime":1700000000},
		{"package_id":"p2","title":"晚","end_time":1800000000,"jump_url":"https://z.ai/a"}]}`))
	if len(got) != 2 {
		t.Fatalf("items = %d", len(got))
	}
	if got[0].ID != "p2" || got[0].Title != "晚" || got[0].EndsAt != 1800000000 || got[0].Link == "" {
		t.Fatalf("first row = %+v", got[0])
	}
	if got[1].Title != "早" || got[1].Summary != "d1" {
		t.Fatalf("second row = %+v", got[1])
	}
}

func TestFetchResourcePackagesStatuses(t *testing.T) {
	old := zcodeAPIBase
	t.Cleanup(func() { zcodeAPIBase = old })

	t.Run("bare 404 page is route absent", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("404 page not found"))
		}))
		defer srv.Close()
		zcodeAPIBase = srv.URL + "/api/v1"
		if _, status, err := fetchResourcePackages(context.Background(), probeTestAuth()); err != errRouteAbsent || status != 404 {
			t.Fatalf("got status=%d err=%v", status, err)
		}
	})

	t.Run("json error envelope is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"code":3010,"msg":"forbidden"}`))
		}))
		defer srv.Close()
		zcodeAPIBase = srv.URL + "/api/v1"
		_, status, err := fetchResourcePackages(context.Background(), probeTestAuth())
		if err == nil || err == errRouteAbsent || status != 403 {
			t.Fatalf("got status=%d err=%v", status, err)
		}
		if !strings.Contains(err.Error(), "3010") {
			t.Fatalf("error lost the biz code: %v", err)
		}
	})

	t.Run("ok with both casings and envelope code 200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != resourcePackagesPath {
				t.Errorf("path = %q", r.URL.Path)
			}
			if r.URL.Query().Get("host") != "zcode.z.ai" {
				t.Errorf("host param = %q", r.URL.Query().Get("host"))
			}
			if got := r.Header.Get("X-Device-Mid"); got != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
				t.Errorf("device mid = %q", got)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer probe-jwt" {
				t.Errorf("authorization = %q", got)
			}
			w.Write([]byte(`{"code":200,"data":{"items":[{"title":"双十一"}]}}`))
		}))
		defer srv.Close()
		zcodeAPIBase = srv.URL + "/api/v1"
		acts, _, err := fetchResourcePackages(context.Background(), probeTestAuth())
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		if len(acts) != 1 || acts[0].Title != "双十一" {
			t.Fatalf("acts = %+v", acts)
		}
	})
}

func TestProbeRowsAlwaysCarryTime(t *testing.T) {
	oldAPI, oldPeak := zcodeAPIBase, offPeakBase
	t.Cleanup(func() { zcodeAPIBase, offPeakBase = oldAPI, oldPeak })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/billing/preview"):
			w.Write([]byte(`{"code":0,"data":{"plans":[]}}`))
		case strings.HasSuffix(r.URL.Path, "/off-peak/ticket/availability"):
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"code":3101,"msg":"coding plan is required"}`))
		default:
			w.Write([]byte(`{"code":0,"data":{"items":[]}}`))
		}
	}))
	defer srv.Close()
	zcodeAPIBase = srv.URL + "/api/v1"
	offPeakBase = srv.URL

	probes, plans := probeActivityFeeds("probe-user", probeTestAuth())
	if len(plans) != 0 {
		t.Fatalf("plans = %+v", plans)
	}
	if len(probes) < 4 {
		t.Fatalf("probes = %d, want >= 4", len(probes))
	}
	statuses := map[string]string{}
	for _, p := range probes {
		if p.CheckedAt == "" {
			t.Fatalf("probe %q has no checked_at", p.Name)
		}
		statuses[p.Name] = p.Status
	}
	if statuses["活动横幅 (resource-packages)"] != probeStatusEmpty {
		t.Fatalf("banner status = %q", statuses["活动横幅 (resource-packages)"])
	}
	if statuses["可领取套餐 (billing/preview)"] != probeStatusEmpty {
		t.Fatalf("preview status = %q", statuses["可领取套餐 (billing/preview)"])
	}
	if statuses["闲时通道 (off-peak availability)"] != probeStatusEmpty {
		t.Fatalf("offpeak status = %q", statuses["闲时通道 (off-peak availability)"])
	}
}
