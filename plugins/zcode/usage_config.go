// usage_config.go decodes plugin config from config_yaml on every
// register/reconfigure call and resolves the CPAMP usage report URL/key.
// All plugin-level config lives here so the rest of the plugin reads
// consistent, lock-protected snapshots.
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// plugin-level config decoded from plugin.register/reconfigure config_yaml.
var (
	// loginProvider: upstream for NEW logins (zai default). Existing accounts
	// keep their own provider field.
	loginProvider   = providerZai
	loginProviderMu sync.RWMutex

	// identity header values (see identity.go). The first five shape the
	// User-Agent / title / locale family; the rest exist because the DERIVED
	// value is an inference from the mirrored reference source, and a
	// fingerprint header is worth being able to correct without a rebuild.
	identityMu             sync.RWMutex
	identityAppVersion     = ""
	identitySourceTitle    = ""
	identityReferer        = ""
	identityLanguage       = ""
	identityTimezone       = ""
	identityPlatform       = "" // X-Platform as a whole "platform-arch" string
	identityOSCategory     = "" // X-Os-Category
	identityOSVersion      = "" // X-Os-Version (Windows/macOS have no default)
	identityReleaseChannel = "" // X-Release-Channel
	identityDeviceMid      = "" // device id for NEW logins (empty = fresh UUID)
	identitySessionID      = "" // pins x-session-id (empty = fresh UUID)
	identityTraceID        = "" // pins x-zcode-trace-id (empty = fresh UUID)

	// usageReportURL / usageReportKey: POST NDJSON to CPA-Manager-Plus
	// /v0/management/usage/import (only path that reaches request monitoring;
	// c-shared plugins cannot use host usage.DefaultManager/redisqueue).
	usageReportURL = ""
	usageReportKey = ""
	usageReportMu  sync.RWMutex

	// managementAPIKey: plugin-layer auth for /v0/management/plugins/zcode/*
	// write endpoints. When empty, plugin relies on host-side auth.
	managementAPIKey   = ""
	managementAPIKeyMu sync.RWMutex

	// importClientCredential / clientDataDir back the local-client importer
	// (client_import.go). OFF by default: reading another application's private
	// state is something the operator opts into, not something a plugin does on
	// its own initiative.
	clientImportAllowed = false
	clientDataDir       = ""
	clientImportMu      sync.RWMutex
)

const defaultUsageReportURL = "http://127.0.0.1:18317/v0/management/usage/import"
const fallbackUsageReportURL = "http://cpa-manager-plus:18317/v0/management/usage/import"

func loadedLoginProvider() string {
	loginProviderMu.RLock()
	defer loginProviderMu.RUnlock()
	return loginProvider
}

// clientImportEnabled reports whether the local-client importer may WRITE. The
// read-only scan is deliberately not gated on it: the scan is how an operator
// finds out whether importing is even possible on this machine.
func clientImportEnabled() bool {
	clientImportMu.RLock()
	defer clientImportMu.RUnlock()
	return clientImportAllowed
}

// loadedClientDataDir is the configured client path, empty when unset (the
// per-user default then applies, see clientCredPath).
func loadedClientDataDir() string {
	clientImportMu.RLock()
	defer clientImportMu.RUnlock()
	return clientDataDir
}

// configure decodes plugin config from the lifecycle request.
// identityConfigKeys is the full set of fingerprint override keys. Order is
// irrelevant to correctness but the list is the single place a new key is
// declared, so the decoder and the assignment in configure cannot drift.
var identityConfigKeys = []string{
	"identity_version",
	"identity_source_title",
	"identity_referer",
	"identity_language",
	"identity_timezone",
	"identity_platform",
	"identity_os_category",
	"identity_os_version",
	"identity_release_channel",
	"identity_device_mid",
	"identity_session_id",
	"identity_trace_id",
}

// decodeIdentityConfig reads the identity_* keys from a plugin config, by key.
// An absent key is simply missing from the result.
//
// TWO passes, deliberately. The YAML map understands flow style ({k: v}) and
// JSON that a raw-line scan can never match; the line scan is what still works
// when the payload is not YAML at all. The first five keys used to be read ONLY
// by the line scan, so a flow-style or JSON config silently lost them — the map
// pass is that bug's fix, and the line scan stays as the fallback for the
// shapes the map cannot parse.
func decodeIdentityConfig(configYAML []byte) map[string]string {
	out := map[string]string{}
	if m, ok := decodePluginConfigYAML(configYAML); ok {
		for _, k := range identityConfigKeys {
			if v, present := m[k]; present {
				out[k] = configScalarString(v)
			}
		}
	}
	for _, rawLine := range strings.Split(string(configYAML), "\n") {
		line := strings.TrimSpace(rawLine)
		for _, k := range identityConfigKeys {
			// The colon is part of the prefix, so identity_os_version is never
			// matched by a longer key that merely starts with it.
			if prefix := k + ":"; strings.HasPrefix(line, prefix) {
				out[k] = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, prefix)), "\"'")
			}
		}
	}
	return out
}

func configure(raw []byte) {
	nextLoginProvider := "" // sticky: empty = keep current (issue #24)
	nextLifecycleAuto := true
	nextMgmtKey := ""
	cfgURL, cfgKey := "", ""
	// identity_* is decoded separately so the decode is reachable without
	// running configure — which starts the claim scheduler.
	var idv map[string]string
	var cfgYAML []byte
	nextOffPeak := false
	nextOffPeakMaxWait := time.Duration(0)
	nextClaimAuto := true
	nextClaimPlanID := ""
	nextClaimPoll, nextClaimCooldown := 0, 0
	nextImportClient, nextClientDir := false, ""

	if len(raw) > 0 {
		var req struct {
			ConfigYAML []byte `json:"config_yaml"`
		}
		if err := json.Unmarshal(raw, &req); err == nil {
			// v0.1.9 (issue #24): decode the payload as real YAML first --
			// yaml.v3 rides in via the SDK, and this sees flow-style
			// one-liners ({k: v}) and JSON that the line-scan below can
			// never match. Block style parses identically in both paths.
			if m, ok := decodePluginConfigYAML(req.ConfigYAML); ok {
				if v, present := m["login_provider"]; present {
					nextLoginProvider = normalizeProvider(configScalarString(v))
				}
				if v, present := m["lifecycle_auto"]; present {
					nextLifecycleAuto = configScalarBool(v)
				}
				if v, present := m["offpeak"]; present {
					nextOffPeak = configScalarBool(v)
				}
				if v, present := m["usage_report_url"]; present {
					cfgURL = configScalarString(v)
				}
				if v, present := m["usage_report_key"]; present {
					cfgKey = configScalarString(v)
				}
				if v, present := m["management_key"]; present {
					nextMgmtKey = configScalarString(v)
				}
				if v, present := m["claim_auto"]; present {
					nextClaimAuto = configScalarBool(v)
				}
				if v, present := m["claim_plan_id"]; present {
					nextClaimPlanID = configScalarString(v)
				}
				if v, present := m["claim_poll_seconds"]; present {
					if secs, perr := strconv.ParseInt(configScalarString(v), 10, 64); perr == nil && secs > 0 {
						nextClaimPoll = int(secs)
					}
				}
				if v, present := m["claim_cooldown_seconds"]; present {
					if secs, perr := strconv.ParseInt(configScalarString(v), 10, 64); perr == nil && secs > 0 {
						nextClaimCooldown = int(secs)
					}
				}
				if v, present := m["import_client_credential"]; present {
					nextImportClient = configScalarBool(v)
				}
				if v, present := m["client_data_dir"]; present {
					nextClientDir = configScalarString(v)
				}
				if v, present := m["offpeak_max_wait"]; present {
					if secs, perr := strconv.ParseInt(configScalarString(v), 10, 64); perr == nil && secs > 0 {
						nextOffPeakMaxWait = time.Duration(secs) * time.Second
					}
				}
			}
			for _, line := range strings.Split(string(req.ConfigYAML), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "login_provider:") {
					v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "login_provider:")), "\"'")
					nextLoginProvider = normalizeProvider(v)
				}
				if strings.HasPrefix(line, "lifecycle_auto:") {
					v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "lifecycle_auto:")), "\"'")
					nextLifecycleAuto = v == "true" || v == "1" || v == "yes" || v == "on"
				}
				if strings.HasPrefix(line, "offpeak:") {
					v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "offpeak:")), "\"'")
					nextOffPeak = v == "true" || v == "1" || v == "yes" || v == "on"
				}
				if strings.HasPrefix(line, "import_client_credential:") {
					v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "import_client_credential:")), "\"'")
					nextImportClient = v == "true" || v == "1" || v == "yes" || v == "on"
				}
				if strings.HasPrefix(line, "client_data_dir:") {
					nextClientDir = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "client_data_dir:")), "\"'")
				}
				if strings.HasPrefix(line, "offpeak_max_wait:") {
					v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "offpeak_max_wait:")), "\"'")
					if secs, perr := strconv.ParseInt(v, 10, 64); perr == nil && secs > 0 {
						nextOffPeakMaxWait = time.Duration(secs) * time.Second
					}
				}
				if strings.HasPrefix(line, "usage_report_url:") {
					cfgURL = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "usage_report_url:")), "\"'")
				}
				if strings.HasPrefix(line, "usage_report_key:") {
					cfgKey = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "usage_report_key:")), "\"'")
				}
				if strings.HasPrefix(line, "management_key:") {
					nextMgmtKey = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "management_key:")), "\"'")
				}
				if strings.HasPrefix(line, "claim_auto:") {
					v := strings.TrimSpace(strings.TrimPrefix(line, "claim_auto:"))
					nextClaimAuto = v == "true" || v == "1" || v == "yes" || v == "on"
				}
				if strings.HasPrefix(line, "claim_plan_id:") {
					nextClaimPlanID = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "claim_plan_id:")), "\"'")
				}
				if strings.HasPrefix(line, "claim_poll_seconds:") {
					v := strings.TrimSpace(strings.TrimPrefix(line, "claim_poll_seconds:"))
					if secs, perr := strconv.ParseInt(v, 10, 64); perr == nil && secs > 0 {
						nextClaimPoll = int(secs)
					}
				}
				if strings.HasPrefix(line, "claim_cooldown_seconds:") {
					v := strings.TrimSpace(strings.TrimPrefix(line, "claim_cooldown_seconds:"))
					if secs, perr := strconv.ParseInt(v, 10, 64); perr == nil && secs > 0 {
						nextClaimCooldown = int(secs)
					}
				}
			}
		}
		idv = decodeIdentityConfig(req.ConfigYAML)
		cfgYAML = req.ConfigYAML
	}

	// The model namespace is decoded by its own function for the same reason
	// identity_* is: it keeps the decode testable without running configure,
	// which starts the claim scheduler. A reconfigure carrying no config_yaml
	// decodes to the empty policy, matching how the identity overrides in the
	// same situation fall back to their derived defaults.
	configureModelPolicy(decodeModelPolicy(cfgYAML))

	// Sticky (issue #24): only an explicit login_provider key moves the
	// pointer; bare/foreign reconfigures keep whatever was configured.
	if nextLoginProvider != "" {
		loginProviderMu.Lock()
		loginProvider = nextLoginProvider
		loginProviderMu.Unlock()
	}

	lifecycleAutoMu.Lock()
	lifecycleAuto = nextLifecycleAuto
	lifecycleAutoMu.Unlock()

	clientImportMu.Lock()
	clientImportAllowed = nextImportClient
	clientDataDir = nextClientDir
	clientImportMu.Unlock()

	identityMu.Lock()
	// A key absent from the config decodes to "" and therefore keeps the
	// derived default (identity.go) rather than clearing a previous value's
	// intent — an empty override and a missing override mean the same thing.
	identityAppVersion = idv["identity_version"]
	identitySourceTitle = idv["identity_source_title"]
	identityReferer = idv["identity_referer"]
	identityLanguage = idv["identity_language"]
	identityTimezone = idv["identity_timezone"]
	identityPlatform = idv["identity_platform"]
	identityOSCategory = idv["identity_os_category"]
	identityOSVersion = idv["identity_os_version"]
	identityReleaseChannel = idv["identity_release_channel"]
	identityDeviceMid = idv["identity_device_mid"]
	identitySessionID = idv["identity_session_id"]
	identityTraceID = idv["identity_trace_id"]
	identityMu.Unlock()

	configureOffPeak(nextOffPeak, nextOffPeakMaxWait)

	// management key: config_yaml > env > keep existing.
	if nextMgmtKey == "" {
		nextMgmtKey = strings.TrimSpace(os.Getenv("ZCODE_MANAGEMENT_KEY"))
	}
	managementAPIKeyMu.Lock()
	managementAPIKey = nextMgmtKey
	managementAPIKeyMu.Unlock()

	claimConfigMu.Lock()
	claimAuto = nextClaimAuto
	claimPlanID = strings.TrimSpace(nextClaimPlanID)
	if nextClaimPoll > 0 {
		claimPollSeconds = nextClaimPoll
	}
	if nextClaimCooldown > 0 {
		claimCooldownSecs = nextClaimCooldown
	}
	claimConfigMu.Unlock()
	startClaimSchedulerOnce()

	resolveUsageReport(cfgURL, cfgKey)
}

// resolveUsageReport fills usageReportURL/key from config → env → secret files.
func resolveUsageReport(cfgURL, cfgKey string) {
	url := firstNonEmpty(
		strings.TrimSpace(cfgURL),
		strings.TrimSpace(os.Getenv("USAGE_REPORT_URL")),
		strings.TrimSpace(os.Getenv("CPAMP_USAGE_IMPORT_URL")),
	)
	key := firstNonEmpty(
		strings.TrimSpace(cfgKey),
		strings.TrimSpace(os.Getenv("USAGE_REPORT_KEY")),
		strings.TrimSpace(os.Getenv("CPAMP_ADMIN_KEY")),
		strings.TrimSpace(os.Getenv("CPA_MANAGER_ADMIN_KEY")),
		readSecretFile(os.Getenv("USAGE_REPORT_KEY_FILE")),
		readSecretFile(os.Getenv("CPAMP_ADMIN_KEY_FILE")),
		readSecretFile("/run/secrets/cpamp_admin_key"),
		readSecretFile("/run/secrets/cpamp-admin-key"),
	)
	// Without an admin key every report is a guaranteed 401, and even the
	// unauthenticated reachability probe alone trips CPA's management
	// anti-brute-force ban — disable reporting entirely unless a key is set.
	if strings.TrimSpace(key) == "" {
		url = ""
	} else if url == "" {
		url = probeUsageReportURL(key)
	}
	usageReportMu.Lock()
	usageReportURL = url
	usageReportKey = key
	usageReportMu.Unlock()
}

// probeUsageReportURL tries localhost first, then the compose service name.
// 401/403 responses disqualify a candidate.
func probeUsageReportURL(key string) string {
	for _, candidate := range []string{defaultUsageReportURL, fallbackUsageReportURL} {
		if probeURL(candidate, 2*time.Second, key) {
			return candidate
		}
	}
	return ""
}

// probeURL does a quick authenticated GET to check if the endpoint accepts us.
func probeURL(target string, timeout time.Duration, key string) bool {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	if strings.TrimSpace(key) != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return false
	}
	return resp.StatusCode > 0
}

func readSecretFile(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
