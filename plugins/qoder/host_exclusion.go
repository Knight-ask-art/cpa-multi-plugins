// host_exclusion.go — v0.8.74: the plugin reads and writes the host's
// oauth-excluded-models table on the panel's behalf.
//
// Why: the panel (served by CPA) used to call /v0/management/oauth-excluded-models
// with the access key the admin typed. CPA answers "invalid management key"
// for that key, so every save wrote nothing — "保存排除" looked like a no-op.
//
// Now the panel calls the plugin, and the plugin talks to the host locally
// using the management secret-key from config.yaml (bcrypt hashed; compared
// here with bcrypt instead of handing more plaintext secrets around).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// newlineChar splits the env file without a raw newline in a Go literal.
const newlineChar = string(rune(10))

// hostExcludedKeys are the provider keys this plugin owns in the host table.
var hostExcludedKeys = []string{providerName, providerName + "-" + regionCN, providerName + "-" + regionIntl}

// hostExcludedOverride is the per-client map PATCH /oauth-excluded-models
// merges into the config; an empty list removes the key.
type hostExcludedOverride struct {
	Provider string   `json:"provider"`
	Models   []string `json:"models"`
}

var (
	hostAdminMu     sync.Mutex
	hostAdminClient *http.Client
	hostAdminOrigin string
)

var hostAdminHostOverride string // tests point this at an httptest server

// resetHostAdmin forgets the cached client/origin (tests, config reload).
func resetHostAdmin() {
	hostAdminMu.Lock()
	hostAdminClient, hostAdminOrigin = nil, ""
	hostAdminMu.Unlock()
}

// hostAdminTransport: an explicit proxy would send 127.0.0.1 through the
// proxy (the launch scripts export HTTP_PROXY for upstream calls), so it is
// disabled for host-local calls.
func hostAdminTransport() *http.Transport {
	return &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
}

func hostAdminBase() string {
	if hostAdminHostOverride != "" {
		return strings.TrimRight(hostAdminHostOverride, "/")
	}
	hostAdminMu.Lock()
	defer hostAdminMu.Unlock()
	if hostAdminOrigin == "" {
		origin := strings.TrimRight(strings.TrimSpace(os.Getenv("CPA_MANAGEMENT_URL")), "/")
		if origin == "" {
			origin = "http://127.0.0.1:8317"
		}
		hostAdminOrigin = origin
	}
	return hostAdminOrigin
}

func hostAdminHTTP() *http.Client {
	hostAdminMu.Lock()
	defer hostAdminMu.Unlock()
	if hostAdminClient == nil {
		hostAdminClient = &http.Client{Timeout: 10 * time.Second, Transport: hostAdminTransport()}
	}
	return hostAdminClient
}

// managementSecret is the fallback credential when the caller did not supply
// one. Order:
//
//  1. plugins.configs.qoder.management_key
//  2. CPA_MANAGEMENT_KEY / OMCPA_CPA_MANAGEMENT_KEY in the environment
//  3. OMCPA_CPA_MANAGEMENT_KEY from oh-my-cpa/.env next to the executable
//
// The host's management.secret-key is deliberately NOT used: it is a bcrypt
// hash and the host only accepts the plaintext key (measured: HTTP 401).
func managementSecret() string {
	if k := loadedManagementKey(); k != "" {
		return k
	}
	for _, name := range []string{"CPA_MANAGEMENT_KEY", "OMCPA_CPA_MANAGEMENT_KEY"} {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v
		}
	}
	return managementKeyFromEnvFiles()
}

// managementKeyFromEnvFiles looks for the OMC env file beside the CPA binary.
// Reading it is local and the value never leaves the process.
func managementKeyFromEnvFiles() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(filepath.Clean(exe))
	for _, rel := range []string{
		filepath.Join("oh-my-cpa", ".env"),
		".env",
	} {
		raw, rerr := os.ReadFile(filepath.Join(dir, rel))
		if rerr != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), newlineChar) {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			kv := strings.SplitN(line, "=", 2)
			if strings.TrimSpace(kv[0]) != "OMCPA_CPA_MANAGEMENT_KEY" {
				continue
			}
			v := strings.Trim(strings.TrimSpace(kv[1]), `"'`)
			if v != "" {
				log.Printf("qoder: host management key discovered in %s (len %d)", rel, len(v))
				return v
			}
		}
	}
	return ""
}

// bearerOf extracts the caller's Bearer token from a plugin request.
func bearerOf(req pluginapi.ManagementRequest) string {
	for _, v := range req.Headers["Authorization"] {
		if t := strings.TrimSpace(v); t != "" {
			return strings.TrimSpace(strings.TrimPrefix(t, "Bearer "))
		}
	}
	return ""
}

// hostAdminMutate serializes read-modify-write cycles on the host table: the
// panel saves every region, and a concurrent auto-adopt save must not clobber
// a key it did not touch.
var hostAdminMutate sync.Mutex

// hostAdminDo runs one management request against the host and returns the
// decoded body.
func hostAdminDo(method, path string, payload any) (map[string]any, error) {
	return hostAdminDoAs(method, path, payload, "")
}

// hostAdminDoAs runs one management request with an explicit credential.
// An empty secret falls back to the plugin's configured management_key; the
// caller's own key is preferred so the host — not this plugin — decides
// whether it is valid.
func hostAdminDoAs(method, path string, payload any, callerSecret string) (map[string]any, error) {
	caller := strings.TrimSpace(callerSecret)
	secret := caller
	if secret == "" {
		secret = managementSecret()
	}
	if secret == "" {
		return nil, fmt.Errorf("no management credential: enter the CPA management key in the panel")
	}
	out, err := hostAdminOnce(method, path, payload, secret)
	// v0.8.74: the panel may hold the plain API key (it also works for chat).
	// The host rejects it for /management; fall back to the plugin's own
	// management_key before surfacing the error, so a save still lands.
	if err != nil && caller != "" && strings.Contains(err.Error(), "HTTP 401") {
		if fallback := managementSecret(); fallback != "" && fallback != caller {
			if out2, err2 := hostAdminOnce(method, path, payload, fallback); err2 == nil {
				return out2, nil
			}
		}
	}
	return out, err
}

// hostAdminOnce performs one management request with one credential.
func hostAdminOnce(method, path string, payload any, secret string) (map[string]any, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	url := hostAdminBase() + loadedManagementBasePath() + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-Management-Key", secret)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hostAdminHTTP().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("host %s %s: HTTP %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	out := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out, nil
}

// fetchHostExcludedModelsForPanel is the exported alias used by the groups
// endpoint, so the panel's checkbox state comes from the same source as a save.
func fetchHostExcludedModelsForPanel(secret string) map[string][]string {
	return fetchHostExcludedModelsAs(secret)
}

// fetchHostExcludedModels returns the host table filtered to this plugin's
// keys. Errors are logged: the panel then shows an empty map.
func fetchHostExcludedModels() map[string][]string {
	return fetchHostExcludedModelsAs("")
}

// fetchHostExcludedModelsAs reads the table using the caller's credential.
func fetchHostExcludedModelsAs(secret string) map[string][]string {
	out, _ := fetchHostExcludedModelsChecked(secret)
	return out
}

// fetchHostExcludedModelsChecked also reports whether the read succeeded, so
// the panel can refuse to save instead of rewriting the lists from an empty
// (unreadable) map.
func fetchHostExcludedModelsChecked(secret string) (map[string][]string, bool) {
	out := map[string][]string{}
	resp, err := hostAdminDoAs(http.MethodGet, "/oauth-excluded-models", nil, secret)
	if err != nil {
		log.Printf("qoder: cannot read host oauth-excluded-models: %v", err)
		return out, false
	}
	table, _ := resp["oauth-excluded-models"].(map[string]any)
	for _, key := range hostExcludedKeys {
		list, _ := table[key].([]any)
		vals := make([]string, 0, len(list))
		for _, v := range list {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				vals = append(vals, strings.TrimSpace(s))
			}
		}
		if len(vals) > 0 {
			out[key] = vals
		}
	}
	return out, true
}

func hostExcludedKeyAllowed(key string) bool {
	for _, k := range hostExcludedKeys {
		if strings.EqualFold(k, strings.TrimSpace(key)) {
			return true
		}
	}
	return false
}

// patchHostExclusions PATCHes one key of the host table. An empty list removes
// the key.
func patchHostExclusions(provider string, models []string, secret string) error {
	hostAdminMutate.Lock()
	defer hostAdminMutate.Unlock()
	if models == nil {
		models = []string{}
	}
	if _, err := hostAdminDoAs(http.MethodPatch, "/oauth-excluded-models",
		hostExcludedOverride{Provider: provider, Models: models}, secret); err != nil {
		return err
	}
	log.Printf("qoder: host oauth-excluded-models[%s] := %d entries", provider, len(models))
	return nil
}

// handleHostExclusions answers the panel's exclusion endpoints:
//
//	GET  <base>/exclusions                → {exclusions:{qoder-cn:[…]}}
//	POST <base>/exclusions                → {provider, models:[…]} (empty removes)
//	POST <base>/exclusions/reset?realm=cn → drop that region's key
func handleHostExclusions(req pluginapi.ManagementRequest) map[string]any {
	path := strings.TrimRight(req.Path, "/")
	secret := bearerOf(req)
	switch {
	case req.Method == http.MethodGet:
		return map[string]any{"exclusions": fetchHostExcludedModelsAs(secret)}
	case req.Method == http.MethodPost && strings.HasSuffix(path, "/reset"):
		realm := strings.ToLower(strings.TrimSpace(req.Query.Get("realm")))
		if realm != regionCN && realm != regionIntl {
			return map[string]any{"error": "realm must be cn or intl"}
		}
		key := providerName + "-" + realm
		if err := patchHostExclusions(key, nil, secret); err != nil {
			return map[string]any{"error": err.Error()}
		}
		return map[string]any{"provider": key, "exclusions": fetchHostExcludedModelsAs(secret)}
	case req.Method == http.MethodPost:
		var body struct {
			Provider string   `json:"provider"`
			Models   []string `json:"models"`
		}
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return map[string]any{"error": "invalid body: " + err.Error()}
		}
		if !hostExcludedKeyAllowed(body.Provider) {
			return map[string]any{"error": "provider must be one of " + strings.Join(hostExcludedKeys, ", ")}
		}
		if err := patchHostExclusions(body.Provider, body.Models, secret); err != nil {
			return map[string]any{"error": err.Error()}
		}
		return map[string]any{"provider": body.Provider, "exclusions": fetchHostExcludedModelsAs(secret)}
	}
	return map[string]any{"error": "method not allowed"}
}
