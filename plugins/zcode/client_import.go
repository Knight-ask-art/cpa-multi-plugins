// client_import.go imports a credential from a locally installed ZCode client,
// so someone already signed in there does not have to redo the browser OAuth
// flow through CPA.
//
// WHY THE READER IS SCHEMA-AGNOSTIC. The client's on-disk state is not a
// published format. What we have is a path convention (~/.zcode/v2/config.json,
// jethub's client_data_dir default) and nothing else — no ZCode client is
// installed on the machine this was written on, so the document has never been
// seen. A parser written against a guessed set of field names would fail in the
// worst possible way: it would import nothing and say nothing, and the user
// would conclude the feature is broken. So the reader walks the whole document
// and classifies by KEY NAME HINT plus, for the plan token, by VALUE SHAPE (a
// JWT is self-identifying; an opaque token is not). A renamed field inside the
// client costs precision, never correctness.
//
// WHY THE DRY RUN IS THE MAIN ENTRY POINT. Every scan reports the key path each
// candidate came from, its length, and its classification — the diagnostic shape
// loginPollSlots established for the same reason: the guess is visible, so a
// wrong guess is a thing you can see and fix rather than a silent no-op.
//
// TOKEN VALUES NEVER LEAVE THIS FILE. The report carries key paths and lengths
// only, built that way rather than redacted afterwards.
package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	// clientCredDefaultRelPath is the path convention under the user's home
	// directory, kept relative so one default works on every platform.
	clientCredDefaultRelPath = ".zcode/v2/config.json"
	// clientCredMaxBytes caps the read. The client's config is a small JSON
	// document; anything this size is not it, and reading it would turn a
	// mis-set client_data_dir into a memory problem.
	clientCredMaxBytes = 4 << 20
)

// clientCredKind classifies one candidate string.
type clientCredKind string

const (
	kindJWT      clientCredKind = "jwt"
	kindOAuth    clientCredKind = "oauth"
	kindUID      clientCredKind = "uid"
	kindNickname clientCredKind = "nickname"
	kindDevice   clientCredKind = "device_mid"
	kindProvider clientCredKind = "provider"
)

// clientCandidate is one string found in the document, with where it came from.
// Value is kept for the import step and deliberately never serialized: the
// report is what leaves the plugin, and it is built without values.
type clientCandidate struct {
	Path  string
	Kind  clientCredKind
	Value string
}

// clientScan is the whole result of reading the document.
type clientScan struct {
	Path        string
	Exists      bool
	Unreadable  string
	Candidates  []clientCandidate
	Problems    []string
	Provider    string
	ProviderSrc string
}

// clientCredPath resolves where to read from. client_data_dir may name either
// the document itself or the directory holding it; the default is the
// documented per-user convention.
func clientCredPath() string {
	configured := strings.TrimSpace(loadedClientDataDir())
	if configured == "" {
		home, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			return ""
		}
		return filepath.Join(home, filepath.FromSlash(clientCredDefaultRelPath))
	}
	configured = filepath.Clean(configured)
	// A directory resolves to the document inside it, so both "point me at the
	// folder" and "point me at the file" work.
	if st, err := os.Stat(configured); err == nil && st.IsDir() {
		for _, rel := range []string{"config.json", filepath.FromSlash("v2/config.json")} {
			candidate := filepath.Join(configured, rel)
			if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
				return candidate
			}
		}
		return filepath.Join(configured, "config.json")
	}
	return configured
}

// readClientCredential reads and scans the client document. It never writes and
// never fails: an unreadable path is a REPORTED outcome, because "no client on
// this machine" is the expected answer almost everywhere and must not read as
// an error.
func readClientCredential() *clientScan {
	scan := &clientScan{Path: clientCredPath()}
	if scan.Path == "" {
		scan.Problems = append(scan.Problems, "无法确定用户主目录，请显式配置 client_data_dir")
		return scan
	}
	st, err := os.Stat(scan.Path)
	if err != nil || st.IsDir() {
		return scan
	}
	scan.Exists = true
	if st.Size() > clientCredMaxBytes {
		scan.Unreadable = "文件过大（超过 4 MiB），不像是客户端配置"
		return scan
	}
	raw, err := os.ReadFile(scan.Path)
	if err != nil {
		scan.Unreadable = truncateRedacted(err.Error(), 200)
		return scan
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		scan.Unreadable = "不是合法 JSON：" + truncateRedacted(err.Error(), 120)
		return scan
	}
	collectClientCandidates(doc, "", scan)
	classifyClientProvider(scan)
	return scan
}

// collectClientCandidates walks the document and records every string whose key
// name hints at one of the credential slots.
func collectClientCandidates(node any, path string, scan *clientScan) {
	switch t := node.(type) {
	case map[string]any:
		// Sorted traversal so the report's order is stable across runs — map
		// iteration order would reshuffle the candidate list every scan and make
		// two reports of the same file look different.
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			collectClientCandidates(t[k], joinCredPath(path, k), scan)
		}
	case []any:
		for i, v := range t {
			collectClientCandidates(v, path+"["+strconv.Itoa(i)+"]", scan)
		}
	case string:
		value := strings.TrimSpace(t)
		if value == "" {
			return
		}
		if kind, ok := classifyClientKey(path, value); ok {
			scan.Candidates = append(scan.Candidates, clientCandidate{Path: path, Kind: kind, Value: value})
		}
	}
}

func joinCredPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

// normalizeCredKey folds a key name for hint matching: lowercase, separators
// removed, so access_token / accessToken / access-token all land on
// "accesstoken".
func normalizeCredKey(path string) string {
	last := path
	if i := strings.LastIndexAny(path, ".]"); i >= 0 && i+1 < len(path) {
		last = path[i+1:]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(last) {
		if r == '_' || r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// classifyClientKey maps one key name + value onto a credential slot. The rules
// are ordered most-specific first, and every one is a HINT: the report prints
// what matched, so a misclassification is visible rather than silent.
func classifyClientKey(path, value string) (clientCredKind, bool) {
	key := normalizeCredKey(path)
	switch {
	// A JWT is self-identifying, so shape alone decides — the one slot that
	// does not depend on the client's field naming at all.
	case looksLikeJWT(value):
		return kindJWT, true
	case strings.Contains(key, "jwt"):
		return kindJWT, true
	case strings.Contains(key, "plan") && strings.Contains(key, "token"):
		return kindJWT, true
	case strings.Contains(key, "device") && (strings.Contains(key, "mid") || strings.Contains(key, "id")):
		return kindDevice, true
	case strings.Contains(key, "oauth"):
		return kindOAuth, true
	case strings.Contains(key, "access") && strings.Contains(key, "token"):
		return kindOAuth, true
	case strings.Contains(key, "refresh") && strings.Contains(key, "token"):
		return kindOAuth, true
	case key == "uid" || key == "userid" || key == "accountid":
		return kindUID, true
	case key == "nickname" || key == "username" || key == "displayname":
		return kindNickname, true
	case key == "provider" || key == "chain":
		return kindProvider, true
	}
	return "", false
}

// looksLikeJWT requires three segments AND a decodable JSON header naming an
// algorithm. Dotted strings are common in configs; a JWT header is not, so this
// is a strong positive rather than a guess.
func looksLikeJWT(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || strings.ContainsAny(p, " \t\r\n") {
			return false
		}
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(header, &hdr); err != nil {
		return false
	}
	return strings.TrimSpace(hdr.Alg) != ""
}

// classifyClientProvider picks the upstream chain. An explicit provider/chain
// field wins; otherwise the configured login_provider is the best available
// answer, and ProviderSrc records which was used so the report never pretends
// to know more than it does.
func classifyClientProvider(scan *clientScan) {
	for _, c := range scan.Candidates {
		if c.Kind != kindProvider {
			continue
		}
		if provider, ok := parseProviderArg(c.Value); ok {
			scan.Provider, scan.ProviderSrc = provider, "文件里的 "+c.Path
			return
		}
		scan.Problems = append(scan.Problems,
			"字段 "+c.Path+" 的值不是已知上游（zai / bigmodel），已忽略")
	}
	scan.Provider = loadedLoginProvider()
	scan.ProviderSrc = "配置的 login_provider（文件里没有 provider 字段）"
}

// clientCredPicks collapses candidates into one value per slot, and reports
// every slot that is ambiguous rather than picking for the user: two different
// OAuth tokens in one document means we cannot tell which account is meant, and
// importing the wrong one would attach someone else's quota to this instance.
func clientCredPicks(scan *clientScan) (map[clientCredKind]clientCandidate, []string) {
	byKind := map[clientCredKind]map[string]clientCandidate{}
	for _, c := range scan.Candidates {
		if byKind[c.Kind] == nil {
			byKind[c.Kind] = map[string]clientCandidate{}
		}
		// First path wins for a repeated value, so a token stored under two
		// names is one candidate, not an ambiguity.
		if _, seen := byKind[c.Kind][c.Value]; !seen {
			byKind[c.Kind][c.Value] = c
		}
	}
	picks := map[clientCredKind]clientCandidate{}
	var problems []string
	for kind, values := range byKind {
		if len(values) == 1 {
			for _, c := range values {
				picks[kind] = c
			}
			continue
		}
		paths := make([]string, 0, len(values))
		for _, c := range values {
			paths = append(paths, c.Path)
		}
		sort.Strings(paths)
		problems = append(problems, "找到 "+string(kind)+" 的多个不同取值（"+strings.Join(paths, " / ")+"），无法判断用哪个")
	}
	// Map iteration order would reshuffle the refusal text between runs; two
	// reports of one document must read the same.
	sort.Strings(problems)
	return picks, problems
}

// clientScanReport is the serializable view: key paths, lengths and
// classifications — no token values, by construction.
func clientScanReport(scan *clientScan) map[string]any {
	picks, problems := clientCredPicks(scan)
	rows := make([]map[string]any, 0, len(scan.Candidates))
	for _, c := range scan.Candidates {
		rows = append(rows, map[string]any{
			"path": c.Path, "kind": string(c.Kind), "length": len(c.Value),
		})
	}
	problems = append(problems, scan.Problems...)
	sort.Strings(problems)

	// The slot a chat call actually needs is the OAuth token: the coding key is
	// resolved from it (see importClientCredential), and parseStored rejects a
	// credential without that key. The JWT is a bonus — it is what covers the
	// JWT anthropic lane.
	hasJWT, hasOAuth := picks[kindJWT].Value != "", picks[kindOAuth].Value != ""
	out := map[string]any{
		"path":          scan.Path,
		"exists":        scan.Exists,
		"unreadable":    scan.Unreadable,
		"candidates":    rows,
		"problems":      problems,
		"enabled":       clientImportEnabled(),
		"has_jwt":       hasJWT,
		"has_oauth":     hasOAuth,
		"provider":      scan.Provider,
		"provider_from": scan.ProviderSrc,
		"default_path":  clientCredDefaultRelPath,
	}
	out["importable"] = scan.Exists && scan.Unreadable == "" && len(problems) == 0 && hasOAuth
	if uid := picks[kindUID]; uid.Value != "" {
		out["uid_path"] = uid.Path
	}
	return out
}

// -----------------------------------------------------------------------------
// import
// -----------------------------------------------------------------------------

// importedCredential is a credential assembled from the client document, before
// the coding key is resolved.
type importedCredential struct {
	OAuthToken string
	JWT        string
	Provider   string
	UID        string
	Nickname   string
	DeviceMid  string
}

// buildImportedCredential turns a scan into a credential, or explains why it
// cannot. It performs no I/O, so the decision is testable on its own.
//
// An OAuth token is REQUIRED. Not because the JWT is worthless, but because the
// resolved coding key comes from it and parseStored rejects a credential without
// that key — so a JWT-only import would write a host record this plugin then
// cannot parse, which is worse than refusing.
func buildImportedCredential(scan *clientScan) (*importedCredential, error) {
	if !scan.Exists {
		return nil, errClientImport("本机没有找到客户端配置：" + scan.Path)
	}
	if scan.Unreadable != "" {
		return nil, errClientImport("读不了客户端配置：" + scan.Unreadable)
	}
	picks, problems := clientCredPicks(scan)
	if len(problems) > 0 {
		return nil, errClientImport(strings.Join(problems, "；"))
	}
	if picks[kindOAuth].Value == "" {
		if picks[kindJWT].Value != "" {
			return nil, errClientImport(
				"只找到 plan JWT，没有 OAuth token。coding-plan key 必须用 OAuth token 去换，" +
					"缺了它会写出一个本插件读不进来的凭据（parseStored 要求 accessToken）——" +
					"请在客户端里重新登录一次，或用面板的 OAuth 入口登录")
		}
		return nil, errClientImport("客户端配置里没有找到任何凭据字段（既没有 OAuth token 也没有 plan JWT）")
	}
	cred := &importedCredential{
		OAuthToken: picks[kindOAuth].Value,
		JWT:        picks[kindJWT].Value,
		Provider:   scan.Provider,
		UID:        picks[kindUID].Value,
		Nickname:   picks[kindNickname].Value,
		DeviceMid:  picks[kindDevice].Value,
	}
	if cred.Provider == "" {
		cred.Provider = providerZai
	}
	return cred, nil
}

// clientImportError marks a refusal the operator can act on.
type clientImportError struct{ msg string }

func (e *clientImportError) Error() string { return e.msg }

func errClientImport(msg string) error { return &clientImportError{msg: msg} }

// importClientCredential performs the import: resolve the coding-plane key from
// the imported OAuth token, then persist a credential under the same name and
// note the OAuth login flow would have used.
//
// The coding key is RESOLVED rather than read from the file. The client stores
// the OAuth token and resolves its plan key on demand through the business chain
// (auth_keyres.go); the resolved key is what every chat path needs. Resolving
// here is what makes an imported credential the same kind of credential a login
// produces, down to the V4 signer's input.
func importClientCredential(scan *clientScan, overwrite bool) map[string]any {
	cred, err := buildImportedCredential(scan)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	// Refuse to silently replace a working credential. Re-importing the same
	// account is legitimate (the client rotated its token), but doing it by
	// accident because a uid happens to match must be a deliberate choice.
	if existing, name := findExistingAuthByUID(cred.UID, cred.Provider); existing != nil && !overwrite {
		return map[string]any{
			"error":    "该账号已存在（" + name + "）；确认要覆盖请带 overwrite=true 重试",
			"existing": map[string]any{"auth_index": existing.AuthIndex, "name": name},
		}
	}
	chatKey, kerr := resolveCodingPlanKey(cred.OAuthToken, cred.Provider)
	if kerr != nil {
		return map[string]any{"error": "用导入的 OAuth token 换 coding-plan key 失败：" + truncateRedacted(kerr.Error(), 200)}
	}
	uid := cred.UID
	if uid == "" {
		// Same rule as the login flow: without a uid, derive one from something
		// stable about the credential so a re-import is idempotent instead of
		// creating a second record.
		uid = "u-" + sha256hex8(chatKey)
	}
	sa := &storedAuth{
		Auth: zcodeTokens{
			AccessToken: chatKey,
			OAuthToken:  cred.OAuthToken,
			JWT:         cred.JWT,
			Provider:    cred.Provider,
			Plan:        planCoding,
			// The client's own device id when it has one: that is the billing
			// identity this account was created with, so reusing it is more
			// faithful than minting a new one. A fresh UUID otherwise, exactly
			// as a login does.
			DeviceMid: firstNonEmpty(cred.DeviceMid, resolveDeviceMid(), uuid.NewString()),
		},
		Account: zcodeAccount{UID: uid, Nickname: cred.Nickname},
	}
	note := displayNote(sa, nil, false)
	raw, berr := buildAuthFileJSON(sa, false, note, nil)
	if berr != nil {
		return map[string]any{"error": berr.Error()}
	}
	name := authFileNameFor(sa)
	if perr := hostAuthPersistFn(name, raw); perr != nil {
		return map[string]any{"error": perr.Error()}
	}
	return map[string]any{
		"ok":         true,
		"name":       name,
		"uid":        sa.Account.UID,
		"provider":   authProviderFor(sa),
		"has_jwt":    strings.TrimSpace(sa.Auth.JWT) != "",
		"has_coding": true,
	}
}

// findExistingAuthByUID returns the host record already holding this uid on the
// same provider. An empty uid never matches: it is not an identity.
func findExistingAuthByUID(uid, provider string) (*hostAuthPhysical, string) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return nil, ""
	}
	files, err := hostAuthList()
	if err != nil {
		return nil, ""
	}
	for _, f := range files {
		sa, err := hostAuthGet(f.AuthIndex)
		if err != nil {
			continue
		}
		if strings.TrimSpace(sa.Account.UID) != uid {
			continue
		}
		if authProviderFor(sa) != normalizeProvider(provider) {
			continue
		}
		return &hostAuthPhysical{AuthIndex: f.AuthIndex, Name: f.Name, Path: f.Path}, f.Name
	}
	return nil, ""
}

// handleClientCredentialScan serves the read-only report. Always available: it
// is how an operator finds out whether importing is even possible here, and it
// writes nothing.
func handleClientCredentialScan() map[string]any {
	return clientScanReport(readClientCredential())
}

// handleClientCredentialImport performs the import, gated on the config flag.
func handleClientCredentialImport(req pluginapi.ManagementRequest) map[string]any {
	if !clientImportEnabled() {
		return map[string]any{
			"error": "导入功能未启用：在插件配置里把 import_client_credential 设为 true 后重试",
		}
	}
	var body struct {
		Overwrite bool `json:"overwrite"`
	}
	_ = json.Unmarshal(req.Body, &body)
	// Re-read rather than trusting an earlier scan: the file may have changed
	// between the dry run and the confirmation click, and the confirmation is
	// about what is on disk now.
	return importClientCredential(readClientCredential(), body.Overwrite)
}
