package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// model_ids — v0.8.72: custom client-facing model ids edited from the panel.
//
// The panel's model list lets the admin rename any model's public id
// (qfmodel → my-flash). The edit is applied to the live process immediately
// and persisted into the plugin state dir, so it survives restarts and
// reconfigures.
//
// v0.8.73: the host only registers a plugin catalog at startup, so a changed
// id becomes routable only after CPA restarts. The save can therefore schedule
// that restart itself (see restart.go) — the panel asks for it by default and
// waits for the new pid before reloading.

// handleModelIDs answers POST <base>/model-ids with
// {"model_ids":{raw:custom}} and, when the table actually changed and restart
// is allowed, a restart_scheduled block describing the pending restart.
func handleModelIDs(req pluginapi.ManagementRequest) map[string]any {
	var body struct {
		ModelIDs map[string]string `json:"model_ids"`
		Restart  *bool             `json:"restart"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return map[string]any{"error": "invalid body: " + err.Error()}
	}
	next := map[string]string{}
	for k, v := range body.ModelIDs {
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k != "" && v != "" && !strings.EqualFold(k, v) {
			next[k] = v
		}
	}
	prev := modelIDOverridesSnapshot()
	changed := !sameStringTable(prev, next)
	setModelIDOverrides(next)
	persisted := saveModelIDsToDisk(next)
	resp := map[string]any{
		"model_ids": next,
		"persisted": persisted,
		"applied":   true,
		"changed":   changed,
	}

	// Best-effort live re-query: re-saving the auth files makes the host ask
	// for the catalog again. It does not re-register ids on the versions we
	// target (hence the restart), but it keeps the panel snapshot fresh.
	if changed {
		resp["refreshed"] = refreshHostModelRegistration()
	}

	wantRestart := restartOnSaveEnabled()
	if body.Restart != nil {
		wantRestart = *body.Restart
	}
	switch {
	case !changed:
		resp["restart_scheduled"] = false
		resp["restart_reason"] = "unchanged"
	case !persisted:
		resp["restart_scheduled"] = false
		resp["restart_reason"] = "not persisted"
	case !wantRestart:
		resp["restart_scheduled"] = false
		resp["restart_reason"] = "disabled"
	default:
		info, _ := scheduleCPARestart("model-ids")
		for k, v := range info {
			resp[k] = v
		}
	}
	return resp
}

// modelIDsFile is the plugin-owned override table. Storing it next to the
// plugin state (not config.yaml) keeps the panel write path independent of the
// host's management API; the value is re-read on every configure().
func modelIDsFile() string {
	return filepath.Join(modelIDsDir(), "model_ids.json")
}

func loadModelIDsFromDisk() map[string]string {
	b, err := os.ReadFile(modelIDsFile())
	if err != nil {
		return map[string]string{}
	}
	var m map[string]string
	if json.Unmarshal(b, &m) != nil {
		return map[string]string{}
	}
	return m
}

func saveModelIDsToDisk(next map[string]string) bool {
	p := modelIDsFile()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return false
	}
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return false
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return false
	}
	return os.Rename(tmp, p) == nil
}

// refreshHostModelRegistration re-saves each qoder auth unchanged so the
// host's auth-file watcher re-queries model.for_auth. That is the only
// plugin-side way to make the host pick up a changed published catalog
// without a restart (the host caches the static list from registration).
func refreshHostModelRegistration() int {
	files, err := hostAuthListFn()
	if err != nil {
		return 0
	}
	n := 0
	for _, f := range files {
		if !strings.HasPrefix(strings.ToLower(f.Name), providerName+"-") {
			continue
		}
		raw, gerr := hostAuthGetByIndex(f.AuthIndex)
		if gerr != nil || len(raw) == 0 {
			continue
		}
		name, doc, ok := locateCredentialFile(raw)
		if !ok {
			continue
		}
		if serr := hostAuthSaveJSONFn(name, doc); serr == nil {
			n++
		}
	}
	return n
}
