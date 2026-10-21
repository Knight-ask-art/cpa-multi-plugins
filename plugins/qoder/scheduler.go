// scheduler.go implements the CPA scheduler.pick capability for qoderwork.
//
// Routing uses the panel-selected active account (region from that card's
// domain). When the selection is exhausted/disabled/missing, randomly switch
// to another non-exhausted qoderwork candidate. Non-qoderwork candidates are
// always deferred so the built-in scheduler handles them.
package main

import (
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// scheduler_mode values.
//
// v0.8.65: "credits" actually ranks by remaining credits now. Since v0.6.31
// the mode only switched the plugin picker ON and then deferred to the
// sticky panel selection — with two accounts that meant whichever card was
// picked first kept ALL traffic until it hit zero (field report: the low pool
// drained while the fuller one idled). The ranking is in pickCreditsAuth.
const (
	schedulerModeOff     = "off"
	schedulerModeCredits = "credits"
)

var (
	schedulerMode   = schedulerModeOff
	schedulerModeMu sync.RWMutex
)

// setSchedulerMode is a test helper that returns a restore func.
func setSchedulerMode(mode string) func() {
	schedulerModeMu.Lock()
	old := schedulerMode
	schedulerMode = mode
	schedulerModeMu.Unlock()
	return func() {
		schedulerModeMu.Lock()
		schedulerMode = old
		schedulerModeMu.Unlock()
	}
}

func loadedSchedulerMode() string {
	schedulerModeMu.RLock()
	defer schedulerModeMu.RUnlock()
	return schedulerMode
}

// handleSchedulerPick selects a qoderwork auth candidate based on the
// panel-selected active account. Non-qoderwork candidates are always deferred
// (Handled: false) so the built-in scheduler handles them.
//
// scheduler_mode:
//   - "off"     → plugin does NOT handle routing; defer everything to built-in.
//   - "credits" → plugin picks via panel-selected active account (sticky, with
//     fallback when that account becomes exhausted/disabled).
//
// Default is off (see schedulerMode init). Users opting into the plugin's
// routing should set scheduler_mode: credits in plugin config.
func handleSchedulerPick(raw []byte) ([]byte, error) {
	var req pluginapi.SchedulerPickRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}

	// v0.6.31: actually honor the scheduler_mode toggle. Previously the config
	// was parsed but never read here, so "off" silently behaved like "credits".
	if loadedSchedulerMode() != schedulerModeCredits {
		return okEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
	}

	// Collect qoderwork candidates only. v0.8.18: a candidate whose
	// (account, request-model) pair is cooling is skipped so the opt-in
	// plugin-side picker agrees with the catalog filter used by host routing.
	reqModel := requestModelForCooldown(req.Model, req.Options.Metadata)
	var wbCandidates []pluginapi.SchedulerAuthCandidate
	for _, c := range req.Candidates {
		if c.Provider != providerName {
			continue
		}
		if candidateDisabled(c) {
			continue
		}
		if reqModel != "" && modelIsCooling(c.ID, reqModel) {
			continue
		}
		wbCandidates = append(wbCandidates, c)
	}
	if len(wbCandidates) == 0 {
		return okEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
	}

	// Build the ranking view: remaining credits per candidate.
	cands := make([]activeAuthCandidate, 0, len(wbCandidates))
	for _, c := range wbCandidates {
		remain, exhausted := cachedCreditsScore(c.ID)
		if !exhausted {
			exhausted = candidateExhausted(c)
		}
		cands = append(cands, activeAuthCandidate{
			ID:        c.ID,
			Disabled:  false, // already filtered
			Exhausted: exhausted,
			Remain:    remain,
		})
	}
	// v0.8.65: rank by remaining credits. Accounts with a known positive pool
	// compete on size (the panel selection stays while it is positive);
	// accounts whose balance was never fetched follow the panel's own opinion
	// (candidateExhausted) — an account the panel marks exhausted must never
	// win on "unknown". A single live candidate keeps the panel selection, so
	// the dashboard and the router never disagree.
	picked := pickCreditsAuth(cands)
	if picked == "" {
		return okEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
	}
	if picked != getActiveAuthID() {
		setActiveAuthID(picked)
		log.Printf("qoder: scheduler_mode=credits picked %s (remain=%s; candidates=%s)",
			picked, creditsRankLabel(picked), creditsCandidateTrail(cands))
	}
	return okEnvelope(pluginapi.SchedulerPickResponse{
		AuthID:  picked,
		Handled: true,
	})
}

// candidateExhausted reports host-side exhaustion (Status or metadata) for a
// candidate whose credits were never fetched in this process. The panel's
// snapshot goes through the same fields, so the router and the dashboard agree.
func candidateExhausted(c pluginapi.SchedulerAuthCandidate) bool {
	if strings.EqualFold(strings.TrimSpace(c.Status), "exhausted") {
		return true
	}
	if c.Metadata == nil {
		return false
	}
	switch t := c.Metadata["exhausted"].(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	}
	return false
}

// candidateDisabled reports host-disabled auth from Status/metadata.
func candidateDisabled(c pluginapi.SchedulerAuthCandidate) bool {
	st := strings.ToLower(strings.TrimSpace(c.Status))
	if st == "disabled" {
		return true
	}
	if c.Metadata != nil {
		if v, ok := c.Metadata["disabled"]; ok {
			switch t := v.(type) {
			case bool:
				return t
			case string:
				return strings.EqualFold(strings.TrimSpace(t), "true")
			}
		}
	}
	return false
}

// cachedCreditsScore returns (remain, exhausted) from accountCache.
// remain is -1 when unknown; exhausted uses isCreditsExhausted.
// Key is auth.ID (same as SchedulerAuthCandidate.ID and activeAuthID).
func cachedCreditsScore(authID string) (int64, bool) {
	v, ok := accountCache.Load(authID)
	if !ok {
		return -1, false
	}
	entry, ok := v.(*accountCacheEntry)
	if !ok || entry.credits == nil {
		return -1, false
	}
	return entry.credits.TotalRemain, isCreditsExhausted(entry.credits)
}

// creditsRankLabel renders a candidate's cached remaining credits for logs.
func creditsRankLabel(id string) string {
	remain, _ := cachedCreditsScore(id)
	if remain < 0 {
		return "unknown"
	}
	return strconv.FormatInt(remain, 10)
}

// creditsCandidateTrail renders "id=remain" pairs for the decision log line.
func creditsCandidateTrail(cands []activeAuthCandidate) string {
	parts := make([]string, 0, len(cands))
	for _, c := range cands {
		r := "unknown"
		if c.Remain >= 0 {
			r = strconv.FormatInt(c.Remain, 10)
		}
		parts = append(parts, c.ID+"="+r)
	}
	return strings.Join(parts, ",")
}
