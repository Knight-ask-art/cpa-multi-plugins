// identity_config_test.go covers the fingerprint overrides (identity.go +
// usage_config.go): the derived default must speak the client's vocabulary, an
// override must win whole, and the values that feed X-Platform must agree with
// the ones the prompt prints.
package main

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

// identityConfigSnapshotValues is a plain copy of the 12 config variables, so a
// test can set and restore them without repeating itself twelve times.
type identityConfigSnapshotValues struct {
	appVersion, sourceTitle, referer, language, timezone string
	platform, osCategory, osVersion, releaseChannel      string
	deviceMid, sessionID, traceID                        string
}

func readIdentityConfig() identityConfigSnapshotValues {
	identityMu.RLock()
	defer identityMu.RUnlock()
	return identityConfigSnapshotValues{
		appVersion: identityAppVersion, sourceTitle: identitySourceTitle,
		referer: identityReferer, language: identityLanguage, timezone: identityTimezone,
		platform: identityPlatform, osCategory: identityOSCategory,
		osVersion: identityOSVersion, releaseChannel: identityReleaseChannel,
		deviceMid: identityDeviceMid, sessionID: identitySessionID, traceID: identityTraceID,
	}
}

func writeIdentityConfig(v identityConfigSnapshotValues) {
	identityMu.Lock()
	defer identityMu.Unlock()
	identityAppVersion, identitySourceTitle = v.appVersion, v.sourceTitle
	identityReferer, identityLanguage, identityTimezone = v.referer, v.language, v.timezone
	identityPlatform, identityOSCategory = v.platform, v.osCategory
	identityOSVersion, identityReleaseChannel = v.osVersion, v.releaseChannel
	identityDeviceMid, identitySessionID, identityTraceID = v.deviceMid, v.sessionID, v.traceID
}

// withCleanIdentity blanks every override and restores the real config after the
// test, so parallel-free tests cannot leak identity state into each other.
func withCleanIdentity(t *testing.T) {
	t.Helper()
	old := readIdentityConfig()
	t.Cleanup(func() { writeIdentityConfig(old) })
	writeIdentityConfig(identityConfigSnapshotValues{})
}

// ---------------------------------------------------------------------------
// vocabulary
// ---------------------------------------------------------------------------

// The client is an Electron app, so the platform/arch strings come from Node.
// Go's spellings would be a one-line distinguisher in a header whose only job is
// to look like the official client.
func TestPlatformVocabularyUsesNodeSpelling(t *testing.T) {
	platforms := []struct{ goos, want string }{
		{"windows", "win32"},
		{"darwin", "darwin"},
		{"linux", "linux"},
		{"freebsd", "freebsd"},
	}
	for _, c := range platforms {
		if got := clientPlatform(c.goos); got != c.want {
			t.Fatalf("clientPlatform(%q) = %q, want %q", c.goos, got, c.want)
		}
	}
	archs := []struct{ goarch, want string }{
		{"amd64", "x64"},
		{"386", "ia32"},
		{"arm64", "arm64"},
		{"arm", "arm"},
		{"riscv64", "riscv64"},
	}
	for _, c := range archs {
		if got := clientArch(c.goarch); got != c.want {
			t.Fatalf("clientArch(%q) = %q, want %q", c.goarch, got, c.want)
		}
	}
	// The pair Go would have produced must not be what reaches the wire.
	if p, a := clientPlatform("windows"), clientArch("amd64"); p+"-"+a == "windows-amd64" {
		t.Fatal("derived platform still uses Go's vocabulary")
	}
}

func TestResolvePlatformArch(t *testing.T) {
	// No override: derived from this runtime, in the client's spelling.
	value, platform, arch := resolvePlatformArch("")
	if platform == "" || arch == "" || value != platform+"-"+arch {
		t.Fatalf("derived = (%q, %q, %q)", value, platform, arch)
	}
	if platform != clientPlatform(runtime.GOOS) || arch != clientArch(runtime.GOARCH) {
		t.Fatalf("derived = (%q, %q), want the client mapping of Go's (%q, %q)",
			platform, arch, runtime.GOOS, runtime.GOARCH)
	}
	if strings.Contains(value, "amd64") {
		t.Fatalf("derived platform still carries Go's arch spelling: %q", value)
	}

	// An override wins WHOLE — never re-derived or half-substituted.
	value, platform, arch = resolvePlatformArch("linux-x64")
	if value != "linux-x64" || platform != "linux" || arch != "x64" {
		t.Fatalf("override = (%q, %q, %q)", value, platform, arch)
	}
	// Split on the LAST dash, so a multi-part platform keeps its head intact.
	if v, p, a := resolvePlatformArch("linux-gnu-x64"); v != "linux-gnu-x64" || p != "linux-gnu" || a != "x64" {
		t.Fatalf("multi-part override = (%q, %q, %q)", v, p, a)
	}
	// A dash-less override is still honoured verbatim on the wire.
	if v, p, a := resolvePlatformArch("bare"); v != "bare" || p != "bare" || a != "" {
		t.Fatalf("dash-less override = (%q, %q, %q)", v, p, a)
	}
	// A non-printable override is dropped by the gate and falls back to derived.
	if v, _, _ := resolvePlatformArch("bad\x01value"); v == "bad\x01value" {
		t.Fatalf("non-printable override reached the wire: %q", v)
	}
}

// ---------------------------------------------------------------------------
// the snapshot
// ---------------------------------------------------------------------------

func TestSnapshotAppliesEveryOverride(t *testing.T) {
	withCleanIdentity(t)
	writeIdentityConfig(identityConfigSnapshotValues{
		appVersion: "9.9.9", sourceTitle: "hunter2", referer: "https://example.test",
		language: "zh-CN", timezone: "Asia/Shanghai",
		platform: "linux-x64", osCategory: "linux", osVersion: "6.8.0-45-generic",
		releaseChannel: "test",
		deviceMid:      "11111111-2222-3333-4444-555555555555",
		sessionID:      "22222222-2222-3333-4444-555555555555",
		traceID:        "33333333-2222-3333-4444-555555555555",
	})

	id := zcodeIdentity()
	for _, c := range []struct{ name, got, want string }{
		{"appVersion", id.appVersion, "9.9.9"},
		{"sourceTitle", id.sourceTitle, "hunter2"},
		{"referer", id.referer, "https://example.test"},
		{"language", id.language, "zh-CN"},
		{"timezone", id.timezone, "Asia/Shanghai"},
		{"platformValue", id.platformValue, "linux-x64"},
		{"platform", id.platform, "linux"},
		{"arch", id.arch, "x64"},
		{"osCategory", id.osCategory, "linux"},
		{"osVersion", id.osVersion, "6.8.0-45-generic"},
		{"release", id.release, "test"},
		{"deviceMid", id.deviceMid, "11111111-2222-3333-4444-555555555555"},
		{"sessionID", id.sessionID, "22222222-2222-3333-4444-555555555555"},
		{"traceID", id.traceID, "33333333-2222-3333-4444-555555555555"},
	} {
		if c.got != c.want {
			t.Fatalf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

// An override that fails the printable-ASCII gate must fall back to the derived
// default, not be emitted raw — same rule the client applies to its own values.
func TestSnapshotDropsUnprintableOverrides(t *testing.T) {
	withCleanIdentity(t)
	writeIdentityConfig(identityConfigSnapshotValues{
		appVersion: "bad\x01ver", sourceTitle: "bad\ttitle", osVersion: "bad\x00rel",
		osCategory: "bad\x7fcat",
	})
	id := zcodeIdentity()
	if id.appVersion == "bad\x01ver" || id.sourceTitle == "bad\ttitle" {
		t.Fatalf("unprintable value escaped the gate: %+v", id)
	}
	if id.appVersion != zcodeAppVersion {
		t.Fatalf("appVersion = %q, want the bundled default", id.appVersion)
	}
	if id.sourceTitle != "cli" {
		t.Fatalf("sourceTitle = %q, want cli", id.sourceTitle)
	}
	if id.osCategory == "bad\x7fcat" || id.osCategory == "" {
		t.Fatalf("osCategory = %q, want a derived value", id.osCategory)
	}
}

// osCategory is fed either the client spelling (when identity_platform is set)
// or Go's (only through the derived path's fallback) — both must map the same.
func TestOsCategoryAcceptsBothSpellings(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"windows", "windows"}, {"win32", "windows"},
		{"darwin", "macos"}, {"macos", "macos"},
		{"linux", "linux"}, {"freebsd", "linux"},
	} {
		if got := osCategory(c.in); got != c.want {
			t.Fatalf("osCategory(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

func TestLlmHeadersCarryPlatformAndOsVersion(t *testing.T) {
	withCleanIdentity(t)
	writeIdentityConfig(identityConfigSnapshotValues{
		platform: "win32-x64", osVersion: "10.0.26100", osCategory: "windows",
	})
	h := buildLlmIdentityHeaders(zcodeIdentity())
	if h["X-Platform"] != "win32-x64" {
		t.Fatalf("X-Platform = %q", h["X-Platform"])
	}
	if h["X-Os-Version"] != "10.0.26100" {
		t.Fatalf("X-Os-Version = %q", h["X-Os-Version"])
	}
	if h["X-Os-Category"] != "windows" {
		t.Fatalf("X-Os-Category = %q", h["X-Os-Category"])
	}
	// The g6n plane must never emit a device id.
	if _, present := h["X-Device-Mid"]; present {
		t.Fatal("the LLM plane must not send X-Device-Mid")
	}
}

// An unknown OS version omits the header rather than sending an empty one — and
// that omission is visible, which is the point of surfacing it in the panel.
func TestLlmHeadersOmitUnknownOsVersion(t *testing.T) {
	withCleanIdentity(t)
	writeIdentityConfig(identityConfigSnapshotValues{platform: "win32-x64", osVersion: ""})
	id := zcodeIdentity()
	// Only meaningful when this host cannot read a release either.
	if id.osVersion != "" {
		t.Skipf("this host reports an OS release (%q); nothing to assert", id.osVersion)
	}
	h := buildLlmIdentityHeaders(id)
	if _, present := h["X-Os-Version"]; present {
		t.Fatalf("X-Os-Version must be omitted when unknown, got %q", h["X-Os-Version"])
	}
	if h["X-Os-Category"] != "windows" {
		t.Fatalf("X-Os-Category must still be sent: %q", h["X-Os-Category"])
	}
}

// The credential's own device id is the billing identity it was created with, so
// it always beats a global pin. Pairing an account with a device id it never
// used is a stronger tell than a missing header.
func TestContextHeadersPreferStoredDeviceMid(t *testing.T) {
	withCleanIdentity(t)
	writeIdentityConfig(identityConfigSnapshotValues{
		platform: "win32-x64", deviceMid: "pinned-device",
	})
	h := buildContextIdentityHeaders(zcodeIdentity(), "stored-device")
	if h["X-Device-Mid"] != "stored-device" {
		t.Fatalf("X-Device-Mid = %q, want the credential's own", h["X-Device-Mid"])
	}
	// ...and the pin fills the gap for a credential that has none.
	h = buildContextIdentityHeaders(zcodeIdentity(), "")
	if h["X-Device-Mid"] != "pinned-device" {
		t.Fatalf("X-Device-Mid = %q, want the pin", h["X-Device-Mid"])
	}
	// With no pin and no stored id the header is simply absent.
	writeIdentityConfig(identityConfigSnapshotValues{platform: "win32-x64"})
	if h := buildContextIdentityHeaders(zcodeIdentity(), ""); h["X-Device-Mid"] != "" {
		t.Fatalf("X-Device-Mid = %q, want absent", h["X-Device-Mid"])
	}
}

// A pinned device id applies to NEW credentials only; existing ones are never
// rewritten.
func TestDeviceMidPinAppliesToNewCredentials(t *testing.T) {
	withCleanIdentity(t)
	data := &cliPollData{Status: "ready", Token: "jwt"}
	data.User.UserID = "u-new"

	if got := buildStoredAuthFromPoll(data, providerZai, "k.s").Auth.DeviceMid; got == "" {
		t.Fatal("expected a generated device id by default")
	}
	writeIdentityConfig(identityConfigSnapshotValues{deviceMid: "pinned-device"})
	if got := buildStoredAuthFromPoll(data, providerZai, "k.s").Auth.DeviceMid; got != "pinned-device" {
		t.Fatalf("DeviceMid = %q, want the pin", got)
	}
}

// ---------------------------------------------------------------------------
// trace pins
// ---------------------------------------------------------------------------

// Every id is a fresh UUID in real traffic; a pin is per-id, so pinning the
// trace id must not freeze the session id or vice versa.
func TestTraceHeaderPinsArePerID(t *testing.T) {
	withCleanIdentity(t)
	trace := "33333333-2222-3333-4444-555555555555"
	session := "22222222-2222-3333-4444-555555555555"
	writeIdentityConfig(identityConfigSnapshotValues{traceID: trace, sessionID: session})

	req := httptest.NewRequest(http.MethodPost, "https://example.test/v1/chat/completions", nil)
	applyTraceHeaders(req)
	if got := req.Header.Get("x-zcode-trace-id"); got != trace {
		t.Fatalf("x-zcode-trace-id = %q, want the pin", got)
	}
	if got := req.Header.Get("x-session-id"); got != session {
		t.Fatalf("x-session-id = %q, want the pin", got)
	}
	// Unpinned ids stay freshly random — and differ between two calls.
	first := req.Header.Get("x-request-id")
	if first == "" {
		t.Fatal("x-request-id must still be generated")
	}
	req2 := httptest.NewRequest(http.MethodPost, "https://example.test/v1/chat/completions", nil)
	applyTraceHeaders(req2)
	if req2.Header.Get("x-request-id") == first {
		t.Fatal("an unpinned id must not repeat across calls")
	}
	if req2.Header.Get("x-zcode-session-type") != "main" {
		t.Fatalf("x-zcode-session-type = %q", req2.Header.Get("x-zcode-session-type"))
	}

	// Pinning only the trace id leaves the session id random.
	writeIdentityConfig(identityConfigSnapshotValues{traceID: trace})
	req3 := httptest.NewRequest(http.MethodPost, "https://example.test/v1/chat/completions", nil)
	applyTraceHeaders(req3)
	if req3.Header.Get("x-session-id") == session {
		t.Fatal("the session id must not inherit the trace pin")
	}
	if req3.Header.Get("x-session-id") == "" {
		t.Fatal("the session id must still be generated")
	}
}

// ---------------------------------------------------------------------------
// config decoding
// ---------------------------------------------------------------------------

func TestDecodeIdentityConfigBothShapes(t *testing.T) {
	block := []byte("login_provider: zai\n" +
		"identity_platform: win32-x64\n" +
		"identity_os_version: 10.0.26100\n" +
		"identity_session_id: \"quoted-session\"\n" +
		"lifecycle_auto: true\n")
	got := decodeIdentityConfig(block)
	if got["identity_platform"] != "win32-x64" {
		t.Fatalf("block platform = %q", got["identity_platform"])
	}
	if got["identity_os_version"] != "10.0.26100" {
		t.Fatalf("block os version = %q", got["identity_os_version"])
	}
	if got["identity_session_id"] != "quoted-session" {
		t.Fatalf("quotes must be trimmed: %q", got["identity_session_id"])
	}
	if _, present := got["login_provider"]; present {
		t.Fatal("the decoder must only read identity_* keys")
	}

	// Flow style is the shape the raw-line scan cannot match at all — this is
	// the case that silently lost the first five keys before.
	flow := []byte(`{identity_platform: linux-x64, identity_os_category: linux}`)
	got = decodeIdentityConfig(flow)
	if got["identity_platform"] != "linux-x64" {
		t.Fatalf("flow platform = %q", got["identity_platform"])
	}
	if got["identity_os_category"] != "linux" {
		t.Fatalf("flow os category = %q", got["identity_os_category"])
	}

	// A longer key that merely starts with an identity key must not match it.
	decoy := []byte("identity_os_version_extra: nope\n")
	if got := decodeIdentityConfig(decoy); got["identity_os_version"] != "" {
		t.Fatalf("identity_os_version was matched by a longer key: %q", got["identity_os_version"])
	}

	// Every declared key is decodable, so adding one to the list without a
	// matching read is caught here.
	for _, k := range identityConfigKeys {
		cfg := []byte(k + ": value-for-" + k + "\n")
		if got := decodeIdentityConfig(cfg); got[k] != "value-for-"+k {
			t.Fatalf("key %q decoded to %q", k, got[k])
		}
	}
}

// ---------------------------------------------------------------------------
// the prompt and the headers must never disagree
// ---------------------------------------------------------------------------

// system_prompt.go prints Platform / OsVersion into the model's Environment
// block. Feeding it the same snapshot as the headers is what keeps a mixed
// combination (which no real client produces) off the wire.
func TestPromptEnvAgreesWithIdentityHeaders(t *testing.T) {
	withCleanIdentity(t)
	writeIdentityConfig(identityConfigSnapshotValues{
		platform: "linux-x64", osVersion: "6.8.0-45-generic", osCategory: "linux",
		appVersion: "9.9.9", language: "zh-CN", timezone: "Asia/Shanghai",
	})

	env := resolveEnvPromptInfo()
	h := buildLlmIdentityHeaders(zcodeIdentity())

	// The header carries the whole pair.
	if got := h["X-Platform"]; got != "linux-x64" {
		t.Fatalf("X-Platform = %q", got)
	}
	// The prompt's Platform line carries the platform HALF taken from the same
	// source, and its osVersion is composed `${platform} ${release} ${arch}`.
	if env.Platform != "linux" {
		t.Fatalf("prompt platform = %q, want the header's platform half", env.Platform)
	}
	if env.OsVersion != "linux 6.8.0-45-generic x64" {
		t.Fatalf("prompt osVersion = %q, want it composed from the same snapshot", env.OsVersion)
	}
	if !strings.Contains(h["X-Os-Version"], "6.8.0-45-generic") {
		t.Fatalf("X-Os-Version = %q", h["X-Os-Version"])
	}
}

func TestIdentitySnapshotForPanelFlagsMissingOsVersion(t *testing.T) {
	withCleanIdentity(t)
	writeIdentityConfig(identityConfigSnapshotValues{platform: "win32-x64", osCategory: "windows"})

	got := identitySnapshotForPanel()
	if got["platform"] != "win32-x64" || got["os_category"] != "windows" {
		t.Fatalf("panel identity = %v", got)
	}
	if id := zcodeIdentity(); id.osVersion == "" {
		if got["os_version_missing"] != true {
			t.Fatalf("an empty os version must be flagged: %v", got)
		}
	}

	writeIdentityConfig(identityConfigSnapshotValues{
		platform: "win32-x64", osVersion: "10.0.26100", osCategory: "windows",
		deviceMid: "pinned",
	})
	got = identitySnapshotForPanel()
	if got["os_version"] != "10.0.26100" || got["os_version_missing"] != false {
		t.Fatalf("panel identity = %v", got)
	}
	if got["device_mid_pinned"] != true {
		t.Fatalf("the device pin must be visible: %v", got)
	}
}
