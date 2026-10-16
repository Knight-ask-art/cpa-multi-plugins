// client_import_test.go covers the local-client credential importer
// (client_import.go): the shape/schema-agnostic reader, the ambiguity and
// missing-field refusals, path resolution, and the end-to-end import.
//
// The key-resolution chain is NOT faked here: these tests run the real
// resolveCodingPlanKey against the same httptest stub auth_keyres_test.go uses,
// so they cover the importer and the resolver's contract together — which is
// the whole point of resolving the key at import time rather than copying a
// token out of the file.
package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// withClientImportConfig sets the two importer config values and restores them,
// so a test cannot leak "enabled" into another one.
func withClientImportConfig(t *testing.T, enabled bool, dir string) {
	t.Helper()
	clientImportMu.Lock()
	oldAllowed, oldDir := clientImportAllowed, clientDataDir
	clientImportAllowed, clientDataDir = enabled, dir
	clientImportMu.Unlock()
	t.Cleanup(func() {
		clientImportMu.Lock()
		clientImportAllowed, clientDataDir = oldAllowed, oldDir
		clientImportMu.Unlock()
	})
}

// writeClientConfig drops a document in a temp dir and points client_data_dir
// at it. The returned path is the FILE.
func writeClientConfig(t *testing.T, doc string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}
	withClientImportConfig(t, true, path)
	return path
}

// jwtWithAlg builds a syntactically valid JWT so the shape rule can fire.
func jwtWithAlg(alg string) string {
	header := "{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"}"
	return b64url(header) + "." + b64url("{\"sub\":\"x\"}") + "." + b64url("sig")
}

// b64url is the unpadded URL-safe encoding real JWTs use, which is what
// looksLikeJWT decodes with.
func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// -----------------------------------------------------------------------------
// the reader
// -----------------------------------------------------------------------------

func TestLooksLikeJWT(t *testing.T) {
	if !looksLikeJWT(jwtWithAlg("HS256")) {
		t.Fatal("a three-segment token with a JSON alg header must be identified")
	}
	for _, c := range []struct{ in, why string }{
		{"", "empty"},
		{"one.two", "two segments"},
		{"a.b.c.d", "four segments"},
		{"1.2.3", "segments that are not base64"},
		{"aaaa.bbbb.cccc", "base64 decodes to non-JSON"},
		{"eyJhbGciOiJIUzI1NiJ9..sig", "empty middle segment"},
		{"1.2.3 ", "trailing space is not part of a token"},
		{"1.5.0", "a version string is dotted but not a JWT"},
	} {
		if looksLikeJWT(c.in) {
			t.Fatalf("looksLikeJWT(%q) = true (%s)", c.in, c.why)
		}
	}
	// A JWT whose header carries no alg is not one we recognize.
	if looksLikeJWT(b64url("{\"typ\":\"JWT\"}") + "." + b64url("{}") + "." + b64url("s")) {
		t.Fatal("a header without alg must not classify as a JWT")
	}
}

// Field naming inside the client is unknown, so every spelling of a slot has to
// land on the same classification.
func TestClassifyClientKeyHints(t *testing.T) {
	oauth := "opaque-oauth-token-value"
	for _, path := range []string{
		"access_token", "accessToken", "access-token", "auth.accessToken",
		"oauthToken", "oauth_token", "credentials.refresh_token",
	} {
		kind, ok := classifyClientKey(path, oauth)
		if !ok || kind != kindOAuth {
			t.Fatalf("classifyClientKey(%q) = (%q, %v), want oauth", path, kind, ok)
		}
	}
	for _, path := range []string{"jwt", "planToken", "plan_token", "tokens.jwt"} {
		kind, ok := classifyClientKey(path, oauth)
		if !ok || kind != kindJWT {
			t.Fatalf("classifyClientKey(%q) = (%q, %v), want jwt", path, kind, ok)
		}
	}
	for _, path := range []string{"deviceMid", "device_mid", "deviceId"} {
		if kind, ok := classifyClientKey(path, "dev-1"); !ok || kind != kindDevice {
			t.Fatalf("classifyClientKey(%q) = (%q, %v), want device_mid", path, kind, ok)
		}
	}
	for _, c := range []struct {
		path, value string
		want        clientCredKind
	}{
		{"uid", "u-1", kindUID},
		{"userId", "u-1", kindUID},
		{"accountId", "u-1", kindUID},
		{"nickname", "nick", kindNickname},
		{"displayName", "nick", kindNickname},
		{"provider", "zai", kindProvider},
		{"chain", "bigmodel", kindProvider},
	} {
		if kind, ok := classifyClientKey(c.path, c.value); !ok || kind != c.want {
			t.Fatalf("classifyClientKey(%q) = (%q, %v), want %q", c.path, kind, ok, c.want)
		}
	}
	// Shape beats a name hint: a JWT is a JWT wherever it sits.
	if kind, ok := classifyClientKey("accessToken", jwtWithAlg("HS256")); !ok || kind != kindJWT {
		t.Fatalf("a JWT value under an oauth-looking key = (%q, %v), want jwt", kind, ok)
	}
	// Unrelated keys stay unclassified — nothing gets imported by accident.
	for _, path := range []string{"theme", "locale", "autoUpdate", "proxyUrl", "windowWidth"} {
		if kind, ok := classifyClientKey(path, "some-value"); ok {
			t.Fatalf("classifyClientKey(%q) = %q, want no classification", path, kind)
		}
	}
}

func TestCollectCandidatesWalksNestedDeterministically(t *testing.T) {
	doc := `{
	  "version": "2",
	  "auth": {"zai": {"accessToken": "oauth-value", "deviceMid": "dev-9"}},
	  "user": {"uid": "u-42", "nickname": "tester"},
	  "sessions": [{"jwt": "` + jwtWithAlg("HS256") + `"}],
	  "theme": "dark"
	}`
	path := writeClientConfig(t, doc)
	scan := readClientCredential()
	if scan.Path != path {
		t.Fatalf("scan path = %q, want %q", scan.Path, path)
	}
	if !scan.Exists || scan.Unreadable != "" {
		t.Fatalf("scan = %+v", scan)
	}
	got := map[string]clientCredKind{}
	for _, c := range scan.Candidates {
		got[c.Path] = c.Kind
	}
	for path, want := range map[string]clientCredKind{
		"auth.zai.accessToken": kindOAuth,
		"auth.zai.deviceMid":   kindDevice,
		"user.uid":             kindUID,
		"user.nickname":        kindNickname,
		"sessions[0].jwt":      kindJWT,
	} {
		if got[path] != want {
			t.Fatalf("candidate %q = %q, want %q (all: %v)", path, got[path], want, got)
		}
	}
	// Two scans of one file must produce the same order, or the report would
	// look like it changed when nothing did.
	again := readClientCredential()
	if len(again.Candidates) != len(scan.Candidates) {
		t.Fatalf("candidate count changed between scans")
	}
	for i := range again.Candidates {
		if again.Candidates[i].Path != scan.Candidates[i].Path {
			t.Fatalf("candidate order changed at %d: %q vs %q",
				i, again.Candidates[i].Path, scan.Candidates[i].Path)
		}
	}
}

// The report is the thing that leaves the plugin. It must never carry a token.
func TestScanReportCarriesNoTokenValues(t *testing.T) {
	secret := "super-secret-oauth-token-value-9f3a"
	doc := `{"accessToken":"` + secret + `","jwt":"` + jwtWithAlg("HS256") + `","uid":"u-1"}`
	writeClientConfig(t, doc)
	scan := readClientCredential()
	report := clientScanReport(scan)

	blob, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if strings.Contains(string(blob), secret) {
		t.Fatalf("the report leaked the token value: %s", blob)
	}
	// The JWT is just as sensitive.
	for _, c := range scan.Candidates {
		if c.Kind == kindJWT && strings.Contains(string(blob), c.Value) {
			t.Fatal("the report leaked the JWT value")
		}
	}
	// But the diagnostic part is present, which is the point of the report.
	if !strings.Contains(string(blob), "accessToken") {
		t.Fatalf("the report must name the key path it found: %s", blob)
	}
	var rows []map[string]any
	rawRows, _ := json.Marshal(report["candidates"])
	if err := json.Unmarshal(rawRows, &rows); err != nil {
		t.Fatalf("candidates: %v", err)
	}
	for _, r := range rows {
		if _, present := r["value"]; present {
			t.Fatalf("a candidate row carries a value field: %v", r)
		}
		if _, present := r["length"]; !present {
			t.Fatalf("a candidate row must carry its length: %v", r)
		}
	}
}

func TestClientCredPicksReportsAmbiguity(t *testing.T) {
	// Two DIFFERENT oauth tokens: we cannot tell which account is meant.
	two := &clientScan{Candidates: []clientCandidate{
		{Path: "a.accessToken", Kind: kindOAuth, Value: "oauth-a"},
		{Path: "b.accessToken", Kind: kindOAuth, Value: "oauth-b"},
	}}
	if _, problems := clientCredPicks(two); len(problems) != 1 {
		t.Fatalf("two distinct oauth tokens = %v, want one problem", problems)
	}
	// The SAME token under two names is one candidate, not an ambiguity.
	dup := &clientScan{Candidates: []clientCandidate{
		{Path: "a.accessToken", Kind: kindOAuth, Value: "oauth-a"},
		{Path: "b.oauthToken", Kind: kindOAuth, Value: "oauth-a"},
	}}
	picks, problems := clientCredPicks(dup)
	if len(problems) != 0 {
		t.Fatalf("a repeated value must not read as ambiguous: %v", problems)
	}
	if picks[kindOAuth].Value != "oauth-a" {
		t.Fatalf("pick = %+v", picks[kindOAuth])
	}
}

// -----------------------------------------------------------------------------
// path resolution
// -----------------------------------------------------------------------------

func TestClientCredPathResolution(t *testing.T) {
	dir := t.TempDir()

	// An explicit file path is used as given.
	file := filepath.Join(dir, "custom.json")
	if err := os.WriteFile(file, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	withClientImportConfig(t, false, file)
	if got := clientCredPath(); got != file {
		t.Fatalf("file path = %q, want %q", got, file)
	}

	// A directory containing config.json resolves to it.
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	withClientImportConfig(t, false, dir)
	if got := clientCredPath(); got != filepath.Join(dir, "config.json") {
		t.Fatalf("dir path = %q", got)
	}

	// A directory whose document lives under v2/ resolves there too.
	dir2 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir2, "v2"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "v2", "config.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	withClientImportConfig(t, false, dir2)
	if got := clientCredPath(); got != filepath.Join(dir2, "v2", "config.json") {
		t.Fatalf("v2 dir path = %q", got)
	}

	// Unset falls back to the documented per-user convention.
	withClientImportConfig(t, false, "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory to compare against")
	}
	want := filepath.Join(home, filepath.FromSlash(clientCredDefaultRelPath))
	if got := clientCredPath(); got != want {
		t.Fatalf("default path = %q, want %q", got, want)
	}
}

// "No client on this machine" is the normal answer and must read as a fact, not
// as an error.
func TestScanMissingFileIsNotAnError(t *testing.T) {
	withClientImportConfig(t, false, filepath.Join(t.TempDir(), "nope", "config.json"))
	scan := readClientCredential()
	if scan.Exists {
		t.Fatal("a missing file must not report Exists")
	}
	report := clientScanReport(scan)
	if report["importable"] != false {
		t.Fatalf("a missing file must not be importable: %v", report)
	}
	if _, present := report["error"]; present {
		t.Fatal("a missing file is an outcome, not an error field")
	}
}

// -----------------------------------------------------------------------------
// the import decision
// -----------------------------------------------------------------------------

func TestBuildImportedCredentialRefusals(t *testing.T) {
	jwt := jwtWithAlg("HS256")

	// A JWT alone is a refusal with a specific reason: the coding key cannot be
	// resolved without the OAuth token, and storing a credential parseStored
	// rejects would be worse than refusing.
	_, err := buildImportedCredential(&clientScan{
		Exists: true, Provider: providerZai,
		Candidates: []clientCandidate{{Path: "jwt", Kind: kindJWT, Value: jwt}},
	})
	if err == nil || !strings.Contains(err.Error(), "OAuth token") {
		t.Fatalf("jwt-only import error = %v, want one naming the OAuth token", err)
	}
	// Nothing recognizable at all.
	_, err = buildImportedCredential(&clientScan{Exists: true, Candidates: []clientCandidate{
		{Path: "theme", Kind: kindOAuth, Value: ""},
	}})
	if err == nil {
		t.Fatal("an empty document must be refused")
	}
	// Not found / unreadable are refusals too, each with its own copy.
	if _, err := buildImportedCredential(&clientScan{Path: "/nope"}); err == nil ||
		!strings.Contains(err.Error(), "/nope") {
		t.Fatalf("missing-file error = %v", err)
	}
	if _, err := buildImportedCredential(&clientScan{Exists: true, Unreadable: "不是合法 JSON"}); err == nil ||
		!strings.Contains(err.Error(), "不是合法 JSON") {
		t.Fatalf("unreadable error = %v", err)
	}

	// The happy shape, with the provider defaulted when the file has none.
	cred, err := buildImportedCredential(&clientScan{
		Exists: true, Provider: "",
		Candidates: []clientCandidate{
			{Path: "auth.accessToken", Kind: kindOAuth, Value: "oauth-1"},
			{Path: "auth.jwt", Kind: kindJWT, Value: jwt},
			{Path: "user.uid", Kind: kindUID, Value: "u-7"},
		},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cred.Provider != providerZai || cred.UID != "u-7" || cred.JWT != jwt || cred.OAuthToken != "oauth-1" {
		t.Fatalf("credential = %+v", cred)
	}
}

func TestClassifyClientProviderPrefersTheFile(t *testing.T) {
	// An explicit, known provider wins over the configured default.
	scan := &clientScan{Candidates: []clientCandidate{{Path: "auth.provider", Kind: kindProvider, Value: "bigmodel"}}}
	classifyClientProvider(scan)
	if scan.Provider != providerBigmodel || !strings.Contains(scan.ProviderSrc, "auth.provider") {
		t.Fatalf("provider = %q from %q", scan.Provider, scan.ProviderSrc)
	}
	// An unknown value is reported and falls back to the configured default,
	// so the operator learns the field exists but was not usable.
	scan = &clientScan{Candidates: []clientCandidate{{Path: "auth.site", Kind: kindProvider, Value: "zzz"}}}
	classifyClientProvider(scan)
	if scan.Provider != loadedLoginProvider() {
		t.Fatalf("provider = %q, want the configured default", scan.Provider)
	}
	if len(scan.Problems) != 1 {
		t.Fatalf("problems = %v, want the unusable field reported", scan.Problems)
	}
}

// -----------------------------------------------------------------------------
// the import
// -----------------------------------------------------------------------------

// importableDoc is a client document shaped the way the reader expects.
func importableDoc(accessToken, jwt string) string {
	return `{"auth":{"accessToken":"` + accessToken + `","provider":"zai"},` +
		`"user":{"uid":"u-import-1","nickname":"imported"},` +
		`"jwt":"` + jwt + `"}`
}

func TestImportWritesCredentialWithResolvedKey(t *testing.T) {
	fake := newFakeHostAuthStore(t)
	k := newKeyResServer(t)
	pointBasesAt(t, k, false)
	zaiHappyPath(t, k, "", `{"code":0,"data":[]}`, `{"code":0,"data":{"secretKey":"sec-9"}}`)

	writeClientConfig(t, importableDoc("oauth-imported", jwtWithAlg("HS256")))
	out := importClientCredential(readClientCredential(), false)
	if errText, bad := out["error"]; bad {
		t.Fatalf("import failed: %v", errText)
	}
	if out["ok"] != true {
		t.Fatalf("import = %v", out)
	}
	if out["has_coding"] != true || out["has_jwt"] != true {
		t.Fatalf("import must report both lanes: %v", out)
	}
	if len(fake.saved) != 1 {
		t.Fatalf("saved %d files, want 1", len(fake.saved))
	}
	// The stored credential must be the RESOLVED key, not the OAuth token —
	// that is what every chat path and the V4 signer consume.
	sa, err := parseStored(fake.saved[0].Raw)
	if err != nil {
		t.Fatalf("parseStored(persisted): %v", err)
	}
	if sa.Auth.AccessToken != "key-9.sec-9" {
		t.Fatalf("accessToken = %q, want the resolved key", sa.Auth.AccessToken)
	}
	if sa.Auth.OAuthToken != "oauth-imported" {
		t.Fatalf("oauthToken = %q, want the imported one", sa.Auth.OAuthToken)
	}
	if sa.Auth.JWT == "" || sa.Auth.Provider != providerZai {
		t.Fatalf("stored auth = %+v", sa.Auth)
	}
	if sa.Account.UID != "u-import-1" || sa.Account.Nickname != "imported" {
		t.Fatalf("stored account = %+v", sa.Account)
	}
	// The name follows the same convention a login writes, so the importer
	// cannot create a second record for one account.
	if fake.saved[0].Name != "zcode-zai-u-import-1.json" {
		t.Fatalf("saved name = %q", fake.saved[0].Name)
	}
	// The resolution ran the real chain.
	paths := paths(k.reqsOf())
	if len(paths) == 0 || paths[0] != "/api/auth/z/login" {
		t.Fatalf("the key resolution chain did not run: %v", paths)
	}
}

// A document with no uid must still import idempotently: the derived uid comes
// from the resolved key, so re-importing the same account writes the same file
// instead of a second record.
func TestImportWithoutUIDIsIdempotent(t *testing.T) {
	newFakeHostAuthStore(t)
	k := newKeyResServer(t)
	pointBasesAt(t, k, false)
	zaiHappyPath(t, k, "", `{"code":0,"data":[]}`, `{"code":0,"data":{"secretKey":"sec-9"}}`)

	writeClientConfig(t, `{"accessToken":"oauth-no-uid"}`)
	first := importClientCredential(readClientCredential(), false)
	if first["ok"] != true {
		t.Fatalf("first import = %v", first)
	}
	second := importClientCredential(readClientCredential(), false)
	if second["ok"] != true {
		t.Fatalf("second import = %v", second)
	}
	if first["name"] != second["name"] {
		t.Fatalf("a uid-less import is not idempotent: %q then %q", first["name"], second["name"])
	}
	if !strings.Contains(first["name"].(string), sha256hex8("key-9.sec-9")) {
		t.Fatalf("derived name = %q, want it keyed on the resolved credential", first["name"])
	}
}

func TestImportRefusesToClobberUnlessAsked(t *testing.T) {
	fake := newFakeHostAuthStore(t)
	fake.add(t, "auth-1", "id-1", "zcode-zai-u-import-1.json", "u-import-1", providerZai, nil)

	k := newKeyResServer(t)
	pointBasesAt(t, k, false)
	zaiHappyPath(t, k, "", `{"code":0,"data":[]}`, `{"code":0,"data":{"secretKey":"sec-9"}}`)

	writeClientConfig(t, importableDoc("oauth-imported", jwtWithAlg("HS256")))
	out := importClientCredential(readClientCredential(), false)
	if _, present := out["error"]; !present {
		t.Fatalf("importing over an existing account must be refused: %v", out)
	}
	if len(fake.saved) != 0 {
		t.Fatal("a refused import must not write anything")
	}
	existing, _ := out["existing"].(map[string]any)
	if existing == nil || existing["name"] != "zcode-zai-u-import-1.json" {
		t.Fatalf("the refusal must name the conflicting record: %v", out)
	}

	// With overwrite the same import goes through.
	out = importClientCredential(readClientCredential(), true)
	if out["ok"] != true {
		t.Fatalf("overwrite import = %v", out)
	}
	if len(fake.saved) != 1 {
		t.Fatalf("saved %d files, want 1", len(fake.saved))
	}
}

// A different provider with the same uid is a different account: moving a
// credential to another chain is the provider switch's job, not the importer's,
// so the uid clash must not read as a conflict here.
func TestImportDoesNotClobberAnotherProvider(t *testing.T) {
	fake := newFakeHostAuthStore(t)
	fake.add(t, "auth-1", "id-1", "zcode-bigmodel-u-import-1.json", "u-import-1", providerBigmodel, nil)

	k := newKeyResServer(t)
	pointBasesAt(t, k, false)
	zaiHappyPath(t, k, "", `{"code":0,"data":[]}`, `{"code":0,"data":{"secretKey":"sec-9"}}`)

	writeClientConfig(t, importableDoc("oauth-imported", jwtWithAlg("HS256")))
	out := importClientCredential(readClientCredential(), false)
	if out["ok"] != true {
		t.Fatalf("a same-uid account on the other provider is not a conflict: %v", out)
	}
}

func TestImportGatedOnTheConfigFlag(t *testing.T) {
	fake := newFakeHostAuthStore(t)
	writeClientConfig(t, importableDoc("oauth-x", ""))
	// writeClientConfig enables it; turn it off and confirm the gate holds.
	withClientImportConfig(t, false, clientCredPath())

	out := handleClientCredentialImport(pluginapi.ManagementRequest{Body: []byte(`{}`)})
	if _, present := out["error"]; !present {
		t.Fatalf("a disabled importer must refuse: %v", out)
	}
	if !strings.Contains(out["error"].(string), "import_client_credential") {
		t.Fatalf("the refusal must name the config key: %v", out["error"])
	}
	if len(fake.saved) != 0 {
		t.Fatal("a gated import must not write")
	}
}

// -----------------------------------------------------------------------------
// the report's own verdict
// -----------------------------------------------------------------------------

func TestScanReportImportable(t *testing.T) {
	// Found, unambiguous, enabled → importable.
	writeClientConfig(t, importableDoc("oauth-1", ""))
	if got := clientScanReport(readClientCredential()); got["importable"] != true {
		t.Fatalf("report = %v, want importable", got)
	}
	if got := clientScanReport(readClientCredential()); got["has_oauth"] != true {
		t.Fatalf("report = %v", got)
	}

	// Found but NOT enabled: the verdict is about what the FILE allows, so it
	// still reads importable — the panel needs both facts to say "found, but the
	// importer is switched off" rather than pretending nothing was found.
	withClientImportConfig(t, false, clientCredPath())
	report := clientScanReport(readClientCredential())
	if report["importable"] != true {
		t.Fatalf("the scan verdict is about possibility, not permission: %v", report)
	}
	if report["enabled"] != false {
		t.Fatalf("the report must state that the importer is switched off: %v", report)
	}

	// Ambiguous → not importable, with the problem stated.
	writeClientConfig(t, `{"a":{"accessToken":"oauth-a"},"b":{"accessToken":"oauth-b"}}`)
	report = clientScanReport(readClientCredential())
	if report["importable"] != false {
		t.Fatalf("an ambiguous document must not be importable: %v", report)
	}
	problems, _ := report["problems"].([]string)
	if len(problems) == 0 {
		t.Fatalf("the ambiguity must be reported: %v", report)
	}

	// Only a JWT → not importable, and the report says which slot is missing.
	writeClientConfig(t, `{"jwt":"`+jwtWithAlg("HS256")+`"}`)
	report = clientScanReport(readClientCredential())
	if report["importable"] != false || report["has_jwt"] != true || report["has_oauth"] != false {
		t.Fatalf("jwt-only report = %v", report)
	}
}

// The document is another application's file; a directory or a binary must not
// be read as if it were one.
func TestScanRejectsNonJSONAndOversized(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "config.json")
	if err := os.WriteFile(bad, []byte("\x00\x01not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	withClientImportConfig(t, false, bad)
	scan := readClientCredential()
	if !scan.Exists || scan.Unreadable == "" {
		t.Fatalf("invalid JSON must be reported as unreadable: %+v", scan)
	}
	if _, err := buildImportedCredential(scan); err == nil {
		t.Fatal("an unreadable document must not import")
	}

	huge := filepath.Join(dir, "huge.json")
	if err := os.WriteFile(huge, []byte(strings.Repeat(" ", clientCredMaxBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	withClientImportConfig(t, false, huge)
	scan = readClientCredential()
	if scan.Unreadable == "" {
		t.Fatalf("an oversized file must be refused before it is read: %+v", scan)
	}
}

// A guard on the file's own imports: the report type must be serializable
// without help, since it goes straight out over the management API.
func TestScanReportIsJSONSerializable(t *testing.T) {
	writeClientConfig(t, importableDoc("oauth-1", jwtWithAlg("HS256")))
	report := clientScanReport(readClientCredential())
	blob, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("empty report")
	}
	var back map[string]any
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	for _, key := range []string{"path", "exists", "candidates", "importable", "provider", "enabled"} {
		if _, present := back[key]; !present {
			t.Fatalf("report is missing %q: %s", key, blob)
		}
	}
}
