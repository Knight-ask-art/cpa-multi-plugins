// identity.go emits the ZCode desktop client's companion headers so the
// plugin is indistinguishable from the official client at the fingerprinting
// layer. TWO distinct builders are mirrored (TriDefender/zcode-api
// src/proxy/identity.ts, ZCode 3.12.3):
//
//  1. `g6n` = buildCliZCodeSourceHeaders — the single source for LLM
//     completion defaultHeaders AND the coding-plan-signature gate fetch.
//     Shape: HTTP-Referer, User-Agent, [X-ZCode-App-Version], X-Title,
//     X-Release-Channel, X-Client-Language (always, "unknown" fallback),
//     X-Client-Timezone (always, "unknown" fallback), X-ZCode-Agent ("glm",
//     inline), [X-Platform], X-Os-Category (always), [X-Os-Version].
//     NO X-Device-Mid.
//
//  2. `TV` = buildZCodeSourceHeadersFromContext — the endpoint-routing /
//     billing / claim plane. X-ZCode-Agent is GONE from this plane and
//     language/timezone are always present with the "unknown" fallback.
//     Optional X-Device-Mid last.
//
// Both gate header values through the client's printable-ASCII rule; an
// invalid appVersion drops X-ZCode-App-Version entirely and falls the
// User-Agent back to `ZCode/unknown`.
//
// Every value below is overridable from the plugin config (identity_*, parsed
// in usage_config.go). The overrides exist because the derived defaults are
// inferences from the reference source, and a header that only needs to look
// like the real client is worth being able to correct in one line without a
// rebuild.
//
// One resolver, three consumers. The platform/arch/os-version triple feeds
// X-Platform, the billing/routing query params (quota.go, preview.go,
// claim.go) and the prompt's Environment lines (system_prompt.go); those must
// never disagree, so they all read the same snapshot rather than re-deriving.
package main

import (
	"os"
	"regexp"
	"runtime"
	"strings"
)

// ASCII gate copied from the ZCode client's printable-header rule.
var asciiPrintable = regexp.MustCompile(`^[\x20-\x7e]+$`)

// normalizePrintableHeaderValue trims and validates a header value against
// the printable-ASCII rule; non-conforming values are dropped (nil).
func normalizePrintableHeaderValue(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" || !asciiPrintable.MatchString(v) {
		return ""
	}
	return v
}

// firstPrintable returns the first candidate that survives the printable-ASCII
// gate, so every value reads as "config override → fixed default".
func firstPrintable(candidates ...string) string {
	for _, c := range candidates {
		if v := normalizePrintableHeaderValue(c); v != "" {
			return v
		}
	}
	return ""
}

// identityConfigSnapshot carries every identity value the two builders emit.
type identityConfigSnapshot struct {
	appVersion  string
	sourceTitle string
	referer     string
	language    string
	timezone    string

	// platformValue is the whole `{platform}-{arch}` string that goes on the
	// wire (X-Platform, and the billing/routing `platform` query param).
	// platform/arch are the halves, kept separate only because the prompt
	// composes its Environment lines from them individually.
	platformValue string
	platform      string
	arch          string
	osCategory    string
	osVersion     string
	// release is X-Release-Channel.
	release string

	// deviceMid/sessionID/traceID are PIN overrides, empty by default. See
	// identity.go's deviceMid note and executor.go's trace note for why none of
	// them has a non-empty default.
	deviceMid string
	sessionID string
	traceID   string
}

// zcodeIdentity resolves every identity value (config override → derived
// default) under one lock, so a reconfigure can never produce a snapshot that
// mixes old and new values across two fields.
func zcodeIdentity() identityConfigSnapshot {
	identityMu.RLock()
	cfgVersion, cfgTitle := identityAppVersion, identitySourceTitle
	cfgReferer, cfgLang, cfgTz := identityReferer, identityLanguage, identityTimezone
	cfgPlatform, cfgOSCat, cfgOSVer := identityPlatform, identityOSCategory, identityOSVersion
	cfgRelease, cfgDeviceMid := identityReleaseChannel, identityDeviceMid
	cfgSessionID, cfgTraceID := identitySessionID, identityTraceID
	identityMu.RUnlock()

	id := identityConfigSnapshot{
		appVersion:  firstPrintable(cfgVersion, zcodeAppVersion),
		sourceTitle: firstPrintable(cfgTitle, "cli"),
		referer:     firstPrintable(cfgReferer, "https://zcode.z.ai"),
		language:    firstPrintable(cfgLang, "unknown"),
		timezone:    firstPrintable(cfgTz, "unknown"),
		deviceMid:   normalizePrintableHeaderValue(cfgDeviceMid),
		sessionID:   normalizePrintableHeaderValue(cfgSessionID),
		traceID:     normalizePrintableHeaderValue(cfgTraceID),
	}
	id.platformValue, id.platform, id.arch = resolvePlatformArch(cfgPlatform)
	// X-Os-Category is unconditional on the LLM plane, and osCategory never
	// returns "", so the fallback chain always lands on a value.
	id.osCategory = firstPrintable(cfgOSCat, osCategory(id.platform))
	id.osVersion = firstPrintable(cfgOSVer, detectOSRelease())
	id.release = firstPrintable(cfgRelease, releaseChannel())
	return id
}

// resolvePlatformArch turns the configured `{platform}-{arch}` (or the runtime
// default) into the wire string plus its two halves.
//
// A configured override wins WHOLE: an operator who pins "win32-x64" must get
// exactly that, not a re-derivation or a half-substituted pair.
//
// The DERIVED default deliberately speaks the client's vocabulary rather than
// Go's. The client is an Electron app, so these values come from Node:
// process.platform is "win32" (there is no "windows") and process.arch is
// "x64" (there is no "amd64"). runtime.GOOS/GOARCH render "windows-amd64" — a
// pair no ZCode client can emit, and therefore a one-line distinguisher in a
// header whose entire purpose is to look like the official client. The
// reference this file mirrors (src/proxy/identity.ts) is TypeScript and reads
// `process.env.SHELL ?? process.env.ComSpec`, so the Node vocabulary is the one
// that reaches the wire.
func resolvePlatformArch(override string) (value, platform, arch string) {
	if v := normalizePrintableHeaderValue(override); v != "" {
		// Split on the LAST dash so a hypothetical "linux-gnu-x64" keeps its
		// platform half intact.
		if i := strings.LastIndex(v, "-"); i > 0 {
			return v, v[:i], v[i+1:]
		}
		return v, v, ""
	}
	platform, arch = clientPlatform(runtime.GOOS), clientArch(runtime.GOARCH)
	if platform != "" && arch != "" {
		value = platform + "-" + arch
	}
	return value, platform, arch
}

// clientPlatform maps runtime.GOOS onto Node's process.platform vocabulary.
// Unknown values pass through unchanged: a Go port for a platform Node does not
// ship on is better reported honestly than mapped onto a wrong constant.
func clientPlatform(goos string) string {
	switch goos {
	case "windows":
		return "win32"
	case "darwin", "linux":
		return goos
	default:
		return goos
	}
}

// clientArch maps runtime.GOARCH onto Node's process.arch vocabulary.
func clientArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "386":
		return "ia32"
	default:
		// arm64/arm/riscv64/s390x/ppc64/... are spelled identically in both.
		return goarch
	}
}

// osCategory maps the platform onto the client's X-Os-Category. Both the
// client's and Go's spellings are accepted because the value it is fed depends
// on whether an identity_platform override is in play.
func osCategory(platform string) string {
	switch platform {
	case "darwin", "macos":
		return "macos"
	case "win32", "windows":
		return "windows"
	default:
		return "linux"
	}
}

// releaseChannel mirrors the client: ZCODE_ENV==="test" ? "test" : "production".
// identity_release_channel overrides it (applied in zcodeIdentity).
func releaseChannel() string {
	if strings.TrimSpace(os.Getenv("ZCODE_ENV")) == "test" {
		return "test"
	}
	return "production"
}

// buildLlmIdentityHeaders mirrors `g6n` — LLM completion requests (and the
// signing gate fetch). X-ZCode-Agent sits inline, X-Os-Category is
// unconditional, X-Device-Mid is NEVER sent.
func buildLlmIdentityHeaders(id identityConfigSnapshot) map[string]string {
	h := map[string]string{
		"HTTP-Referer":      id.referer,
		"User-Agent":        "ZCode/" + orUnknown(id.appVersion),
		"X-Title":           "Z Code@" + id.sourceTitle,
		"X-Release-Channel": id.release,
		"X-Client-Language": id.language,
		"X-Client-Timezone": id.timezone,
		"X-ZCode-Agent":     "glm",
		"X-Os-Category":     id.osCategory,
	}
	if id.appVersion != "" {
		h["X-ZCode-App-Version"] = id.appVersion
	}
	if id.platformValue != "" {
		h["X-Platform"] = id.platformValue
	}
	if id.osVersion != "" {
		h["X-Os-Version"] = id.osVersion
	}
	return h
}

// buildContextIdentityHeaders mirrors `TV` — control-plane fetches
// (endpoint routing, billing). Insertion order follows the client's spread
// semantics (User-Agent, HTTP-Referer, X-Title first), X-ZCode-Agent is
// absent, X-Device-Mid is appended last when a deviceMid is provided.
func buildContextIdentityHeaders(id identityConfigSnapshot, deviceMid string) map[string]string {
	h := map[string]string{
		"User-Agent":        "ZCode/" + orUnknown(id.appVersion),
		"HTTP-Referer":      id.referer,
		"X-Title":           "Z Code@" + id.sourceTitle,
		"X-Client-Language": id.language,
		"X-Client-Timezone": id.timezone,
	}
	if id.appVersion != "" {
		h["X-ZCode-App-Version"] = id.appVersion
	}
	if id.platformValue != "" {
		h["X-Platform"] = id.platformValue
		h["X-Os-Category"] = id.osCategory
	}
	if id.osVersion != "" {
		h["X-Os-Version"] = id.osVersion
	}
	// The credential's own device id always wins: it is the billing identity
	// the account was created with, and pairing an account with a device id it
	// never used is a stronger tell than a missing header. identity_device_mid
	// only fills the gap for credentials that have none (legacy/imported) —
	// see resolveDeviceMid for why a shared pin is not the default.
	if dm := firstPrintable(deviceMid, id.deviceMid); dm != "" {
		h["X-Device-Mid"] = dm
	}
	return h
}

// resolveDeviceMid picks the device id a NEW credential is created with.
//
// Empty (the default) means "generate a fresh UUID", which is what the plugin
// has always done. Setting identity_device_mid pins one id for every account
// created from then on, which is only right when reproducing a specific
// installation — and is worth knowing the cost of: the real client has ONE
// device id per install and never rotates it, so a per-login UUID is arguably
// the LESS authentic choice, but a single shared pin makes every account look
// like the same machine, which correlates accounts that should not be
// correlated. Existing credentials are never rewritten.
func resolveDeviceMid() string {
	identityMu.RLock()
	cfg := identityDeviceMid
	identityMu.RUnlock()
	return normalizePrintableHeaderValue(cfg)
}

// llmSDKUserAgentSuffix is the SDK UA suffix the real client appends to its
// User-Agent on LLM calls (bundle `Cm` merges ai-sdk/anthropic/3.0.81 into
// the UA; the suffix rides every LLM request, control-plane fetches keep the
// bare ZCode/… UA).
const llmSDKUserAgentSuffix = "ai-sdk/anthropic/3.0.81"

func orUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// detectOSRelease is the best-effort release string for X-Os-Version when
// identity_os_version is not configured.
//
// Go has no portable equivalent of `uname -r`. On Linux
// /proc/sys/kernel/osrelease is authoritative and always present on the server
// deployments CPA targets. Windows and macOS have no dependency-free reading
// path (Windows needs a registry walk, macOS a sysctl), so they return "" and
// the header is omitted.
//
// That omission is honest but it IS a fingerprint difference: a real client on
// those platforms reports a version, so this plugin running on Windows presents
// X-Os-Category: windows with no X-Os-Version beside it. identity_os_version
// closes it; the panel shows the effective value so the gap is visible rather
// than silent.
func detectOSRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return normalizePrintableHeaderValue(string(b))
}
