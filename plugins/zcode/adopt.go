// adopt.go migrates legacy zcode auth shapes to the canonical file layout.
//
// zcode ships without legacy predecessors, so adoption today only normalizes
// the single-file zcode.json shape (no UID suffix) when it carries a UID: the
// JSON is re-saved under the canonical zcode-<provider>-<uid>.json name.
// Idempotent (files already carrying the canonical name are skipped), guarded
// by a min re-run interval, and never blocks plugin registration (background).
//
// Two corrections against the original implementation:
//
//  1. It listed credentials with hostAuthList(), which filters to names
//     carrying the "zcode-" prefix. The legacy file is zcode.json — a dot at
//     index 5, not a dash — so it was NEVER returned and this migration had
//     never run once. It now uses hostAuthListFiles(), the unfiltered list
//     that existed for exactly this purpose but had no caller.
//  2. The old header claimed the legacy file was removed. The host ABI has no
//     auth-delete method (only list/get/get_runtime/save), so the copy cannot
//     be cleaned up from here. Re-saving under the canonical name is the whole
//     of what this file can do; the stale zcode.json is left for the operator
//     to delete, and the log line says so.
package main

import (
	"log"
	"strings"
	"sync"
	"time"
)

var (
	adoptMu      sync.Mutex
	lastAdoptRun time.Time
)

// startAdoption kicks the background migration. Safe to call on every
// register/reconfigure — the guard collapses repeated calls.
func startAdoption() {
	go func() {
		adoptMu.Lock()
		if !lastAdoptRun.IsZero() && time.Since(lastAdoptRun) < time.Minute {
			adoptMu.Unlock()
			return
		}
		lastAdoptRun = time.Now()
		adoptMu.Unlock()
		adoptLegacyAuths()
	}()
}

// adoptLegacyAuths rewrites single-file zcode.json auths that carry a UID to
// the canonical zcode-<provider>-<uid>.json name.
//
// The unfiltered list is required: hostAuthList() drops everything that does
// not start with "zcode-", which excludes the one shape this function exists
// to migrate. See the file header.
func adoptLegacyAuths() {
	files, err := hostAuthListFiles()
	if err != nil {
		log.Printf("adopt: host auth list failed: %v", err)
		return
	}
	adopted := 0
	for _, f := range files {
		name := strings.ToLower(strings.TrimSpace(f.Name))
		if name != authFileName { // zcode.json — the only legacy shape today
			continue
		}
		phys, err := hostAuthGetPhysical(f.AuthIndex)
		if err != nil {
			log.Printf("adopt %s: get failed: %v", f.Name, err)
			continue
		}
		sa, err := parseStored(phys.JSON)
		if err != nil || sa == nil {
			continue
		}
		if sanitizeUIDForFileName(sa.Account.UID) == "" {
			continue // anonymous single-account file stays as-is
		}
		disabled := parseDisabledFromAuthJSON(phys.JSON)
		note := displayNoteWithPrev(sa, nil, disabled, noteCreditsFromJSON(phys.JSON))
		raw, err := buildAuthFileJSON(sa, disabled, note, nil)
		if err != nil {
			continue
		}
		canonical := authFileNameFor(sa)
		if canonical == f.Name {
			continue
		}
		if err := hostAuthPersistFn(canonical, raw); err != nil {
			log.Printf("adopt %s: save failed: %v", f.Name, err)
			continue
		}
		log.Printf("adopt: %s -> %s (the old file has no delete RPC; remove it once the new one is confirmed loaded)", f.Name, canonical)
		adopted++
	}
	if adopted > 0 {
		log.Printf("adopt: done — migrated %d legacy zcode auth file(s)", adopted)
	}
}
