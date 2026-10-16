// panel_test.go is the first in-process coverage for the management surface.
//
// Every handler in panel.go opens with hostAuthList(), which reaches the host
// over cgo — so before host_auth.go grew the hostAuthList/hostAuthGet/
// hostAuthGetBundle seams there was no way to exercise any of it without a
// live CLIProxyAPI process. fakeHostAuthStore below stands in for that store
// and mirrors its one behaviour that matters here: hostAuthGet re-parses the
// stored JSON on every call, so a handler that mutates the struct it was
// handed changes nothing unless it also persists.
//
// The key-resolution chain reached by the switch path is NOT faked: it runs
// for real against the existing keyResServer stub, so these tests cover the
// handler and the resolver's contract together.
package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type savedAuthFile struct {
	Name string
	Raw  []byte
}

type fakeHostAuthStore struct {
	files   []pluginapi.HostAuthFileEntry
	raw     map[string][]byte
	phys    map[string]*hostAuthPhysical
	saved   []savedAuthFile
	listErr error
}

func newFakeHostAuthStore(t *testing.T) *fakeHostAuthStore {
	t.Helper()
	f := &fakeHostAuthStore{
		raw:  map[string][]byte{},
		phys: map[string]*hostAuthPhysical{},
	}
	oldList, oldGet, oldBundle := hostAuthList, hostAuthGet, hostAuthGetBundle
	oldPhys, oldPersist := hostAuthGetPhysicalFn, hostAuthPersistFn

	hostAuthList = func() ([]pluginapi.HostAuthFileEntry, error) {
		if f.listErr != nil {
			return nil, f.listErr
		}
		return f.files, nil
	}
	hostAuthGet = func(authIndex string) (*storedAuth, error) {
		raw, ok := f.raw[authIndex]
		if !ok {
			return nil, fmt.Errorf("fake host: no auth %q", authIndex)
		}
		return parseStored(raw)
	}
	hostAuthGetBundle = func(authIndex string) (*storedAuth, *hostAuthPhysical, error) {
		sa, err := hostAuthGet(authIndex)
		if err != nil {
			return nil, nil, err
		}
		return sa, f.phys[authIndex], nil
	}
	hostAuthGetPhysicalFn = func(authIndex string) (*hostAuthPhysical, error) {
		return f.phys[authIndex], nil
	}
	hostAuthPersistFn = func(name string, raw []byte) error {
		f.saved = append(f.saved, savedAuthFile{Name: name, Raw: raw})
		return nil
	}
	t.Cleanup(func() {
		hostAuthList, hostAuthGet, hostAuthGetBundle = oldList, oldGet, oldBundle
		hostAuthGetPhysicalFn, hostAuthPersistFn = oldPhys, oldPersist
	})
	return f
}

// add registers one account the way the host would report it: a list entry
// plus the credential JSON the plugin wrote at login. alt is the parked
// other-provider OAuth token map (zcodeTokens.AltOAuthTokens).
func (f *fakeHostAuthStore) add(t *testing.T, authIndex, id, fileName, uid, provider string, alt map[string]string) *storedAuth {
	t.Helper()
	sa := &storedAuth{
		Auth: zcodeTokens{
			AccessToken:    "old-key-" + provider,
			OAuthToken:     "old-oauth-" + provider,
			JWT:            "plan-jwt",
			Provider:       provider,
			Plan:           planCoding,
			DeviceMid:      "11111111-2222-3333-4444-555555555555",
			AltOAuthTokens: alt,
		},
		Account: zcodeAccount{UID: uid, Nickname: "acct-" + provider},
	}
	raw, err := buildAuthFileJSON(sa, false, "zcode ["+strings.ToUpper(provider)+"]", nil)
	if err != nil {
		t.Fatalf("buildAuthFileJSON: %v", err)
	}
	f.raw[authIndex] = raw
	f.phys[authIndex] = &hostAuthPhysical{AuthIndex: authIndex, Name: fileName, JSON: raw}
	f.files = append(f.files, pluginapi.HostAuthFileEntry{
		AuthIndex: authIndex, ID: id, Name: fileName, Label: "ZCode", Provider: provider,
	})
	return sa
}

// reread returns what the host would serve on the next call — i.e. the state
// the switch actually committed, as opposed to the struct the handler mutated.
func (f *fakeHostAuthStore) reread(t *testing.T, authIndex string) *storedAuth {
	t.Helper()
	if len(f.saved) > 0 {
		sa, err := parseStored(f.saved[len(f.saved)-1].Raw)
		if err != nil {
			t.Fatalf("parseStored(persisted): %v", err)
		}
		return sa
	}
	sa, err := parseStored(f.raw[authIndex])
	if err != nil {
		t.Fatalf("parseStored(original): %v", err)
	}
	return sa
}

func switchReq(body string) pluginapi.ManagementRequest {
	return pluginapi.ManagementRequest{Method: "POST", Body: []byte(body)}
}

// ---------------------------------------------------------------------------
// swappableProviders — the panel's affordance signal
// ---------------------------------------------------------------------------

func TestSwappableProviders(t *testing.T) {
	mk := func(provider string, alt map[string]string) *storedAuth {
		return &storedAuth{Auth: zcodeTokens{Provider: provider, AltOAuthTokens: alt}}
	}
	cases := []struct {
		name string
		sa   *storedAuth
		want []string
	}{
		{"nil", nil, nil},
		{"no alt slot (pre-upgrade credential)", mk(providerZai, nil), nil},
		// A token for the provider already in use is not a swap target.
		{"alt equals active", mk(providerZai, map[string]string{providerZai: "t"}), nil},
		{"blank is absent", mk(providerZai, map[string]string{providerBigmodel: "   "}), nil},
		{"zai can reach bigmodel", mk(providerZai, map[string]string{providerBigmodel: "t"}), []string{providerBigmodel}},
		{"bigmodel can reach zai", mk(providerBigmodel, map[string]string{providerZai: "t"}), []string{providerZai}},
		{"only the other one is offered", mk(providerZai, map[string]string{
			providerZai: "self", providerBigmodel: "t",
		}), []string{providerBigmodel}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := swappableProviders(c.sa)
			if len(got) != len(c.want) {
				t.Fatalf("swappableProviders = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("swappableProviders = %v, want %v", got, c.want)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseProviderArg — a typo must not silently mean zai
// ---------------------------------------------------------------------------

func TestParseProviderArgRejectsTypos(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"zai", providerZai, true},
		{"Z.AI", providerZai, true},
		{" zai ", providerZai, true},
		{providerBigmodel, providerBigmodel, true},
		{"bigmodel.cn", providerBigmodel, true},
		{"GLM", providerBigmodel, true},
		// normalizeProvider folds every one of these to zai; a switch that did
		// the same would move the account to the wrong upstream on a typo.
		{"bigmodle", "", false},
		{"", "", false},
		{"openai", "", false},
		{"zai\n", providerZai, true},
	}
	for _, c := range cases {
		got, ok := parseProviderArg(c.in)
		if ok != c.ok || got != c.want {
			t.Fatalf("parseProviderArg(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// ---------------------------------------------------------------------------
// handleProviderSwitch
// ---------------------------------------------------------------------------

// bigmodelTargetChain stubs the bigmodel key-resolution chain on k so that
// switching to bigmodel can succeed against a token we invented.
func bigmodelTargetChain(k *keyResServer, copyBody string) {
	const customer = `{"code":0,"data":{"organizations":[{"organizationId":"org-bm","organizationName":"默认机构","projects":[{"projectId":"proj-bm","projectName":"默认项目"}]}]}}`
	base := "/api/biz/v1/organization/org-bm/projects/proj-bm/api_keys"
	k.handle("/api/biz/customer/getCustomerInfo", 200, customer)
	k.handle(base, 200, `{"code":0,"data":[{"apiKey":"key-bm","name":"zcode-api-key"}]}`)
	k.handle(base+"/copy/key-bm", 200, copyBody)
}

func TestProviderSwitchMovesAccountAndParksTheOldToken(t *testing.T) {
	f := newFakeHostAuthStore(t)
	f.add(t, "idx-1", "auth-1", "zcode-zai-u-1.json", "u-1", providerZai,
		map[string]string{providerBigmodel: "oauth-bm-1"})

	k := newKeyResServer(t)
	pointBasesAt(t, k, false)
	bigmodelTargetChain(k, `{"code":0,"data":{"secretKey":"sec-bm"}}`)

	res := handleProviderSwitch(switchReq(`{"auth_index":"idx-1","provider":"bigmodel"}`))
	if res["ok"] != true {
		t.Fatalf("switch failed: %v", res)
	}

	got := f.reread(t, "idx-1")
	if got.Auth.Provider != providerBigmodel {
		t.Fatalf("provider = %q, want bigmodel", got.Auth.Provider)
	}
	if got.Auth.AccessToken != "key-bm.sec-bm" {
		t.Fatalf("access token = %q, want the freshly resolved key-bm.sec-bm", got.Auth.AccessToken)
	}
	if got.Auth.OAuthToken != "oauth-bm-1" {
		t.Fatalf("oauth token = %q, want the bigmodel token", got.Auth.OAuthToken)
	}
	// The outgoing token is parked, so the switch is reversible without
	// another browser round trip — which is the whole point of the alt slot.
	if got.Auth.AltOAuthTokens[providerZai] != "old-oauth-zai" {
		t.Fatalf("alt = %v, want the zai token parked", got.Auth.AltOAuthTokens)
	}
	if _, stale := got.Auth.AltOAuthTokens[providerBigmodel]; stale {
		t.Fatalf("the token that is now active must not stay in the alt map: %v", got.Auth.AltOAuthTokens)
	}
	if sw := swappableProviders(got); len(sw) != 1 || sw[0] != providerZai {
		t.Fatalf("after the switch the account should offer zai back, got %v", sw)
	}
	// The file name keeps the old provider: renaming would write a second
	// file (the host ABI has no auth-delete) and duplicate the record.
	if len(f.saved) != 1 {
		t.Fatalf("persist calls = %d, want exactly 1", len(f.saved))
	}
	if f.saved[0].Name != "zcode-zai-u-1.json" {
		t.Fatalf("persisted as %q, want the existing physical name", f.saved[0].Name)
	}
}

// A missing alt token is the expected state for every credential written
// before the alt slot existed, and for any login whose poll carried only its
// own provider. The switch must say so instead of writing a broken credential.
func TestProviderSwitchNeedsReloginWithoutStoredToken(t *testing.T) {
	f := newFakeHostAuthStore(t)
	f.add(t, "idx-1", "auth-1", "zcode-zai-u-1.json", "u-1", providerZai, nil)

	res := handleProviderSwitch(switchReq(`{"auth_index":"idx-1","provider":"bigmodel"}`))
	if res["needs_relogin"] != true {
		t.Fatalf("want needs_relogin, got %v", res)
	}
	if res["error"] == nil {
		t.Fatalf("want an explanatory error, got %v", res)
	}
	if len(f.saved) != 0 {
		t.Fatalf("nothing may be written when the target token is absent")
	}
	got := f.reread(t, "idx-1")
	if got.Auth.Provider != providerZai || got.Auth.AccessToken != "old-key-zai" {
		t.Fatalf("credential changed on a failed switch: %+v", got.Auth)
	}
}

// Resolution happens before any mutation is persisted. When the target chain
// rejects the token the credential must be untouched — including the in-memory
// struct, which the next hostAuthGet rebuilds from disk.
func TestProviderSwitchLeavesCredentialIntactWhenResolveFails(t *testing.T) {
	f := newFakeHostAuthStore(t)
	f.add(t, "idx-1", "auth-1", "zcode-zai-u-1.json", "u-1", providerZai,
		map[string]string{providerBigmodel: "oauth-bm-1"})

	k := newKeyResServer(t)
	pointBasesAt(t, k, false)
	k.handle("/api/biz/customer/getCustomerInfo", 200, `{"code":5001,"msg":"denied"}`)

	res := handleProviderSwitch(switchReq(`{"auth_index":"idx-1","provider":"bigmodel"}`))
	if res["error"] == nil {
		t.Fatalf("want an error from the failed resolution, got %v", res)
	}
	if len(f.saved) != 0 {
		t.Fatalf("a failed switch must not persist anything")
	}
	got := f.reread(t, "idx-1")
	if got.Auth.Provider != providerZai {
		t.Fatalf("provider = %q, want zai (unchanged)", got.Auth.Provider)
	}
	if got.Auth.AccessToken != "old-key-zai" {
		t.Fatalf("access token = %q, want the original", got.Auth.AccessToken)
	}
	if got.Auth.AltOAuthTokens[providerBigmodel] != "oauth-bm-1" {
		t.Fatalf("alt slot = %v, want it untouched so the switch can be retried", got.Auth.AltOAuthTokens)
	}
}

func TestProviderSwitchRejectsUnknownProviderSpelling(t *testing.T) {
	f := newFakeHostAuthStore(t)
	f.add(t, "idx-1", "auth-1", "zcode-zai-u-1.json", "u-1", providerZai,
		map[string]string{providerBigmodel: "oauth-bm-1"})

	res := handleProviderSwitch(switchReq(`{"auth_index":"idx-1","provider":"bigmodle"}`))
	if res["error"] == nil {
		t.Fatalf("a typo must be rejected, got %v", res)
	}
	if res["got"] != "bigmodle" {
		t.Fatalf("got = %v, want the rejected spelling echoed back", res["got"])
	}
	if len(f.saved) != 0 {
		t.Fatalf("nothing may be written for an invalid provider")
	}
}

func TestProviderSwitchToCurrentProviderIsANoOp(t *testing.T) {
	f := newFakeHostAuthStore(t)
	f.add(t, "idx-1", "auth-1", "zcode-zai-u-1.json", "u-1", providerZai,
		map[string]string{providerBigmodel: "oauth-bm-1"})

	res := handleProviderSwitch(switchReq(`{"auth_index":"idx-1","provider":"zai"}`))
	if res["unchanged"] != true {
		t.Fatalf("want unchanged, got %v", res)
	}
	// No write and no key resolution either: hostAuthPersistFn is the only
	// observable side effect after the early return, and against a real account
	// a redundant resolve would mint another API key upstream.
	if len(f.saved) != 0 {
		t.Fatalf("an idempotent switch must not rewrite the file")
	}
}

func TestProviderSwitchRejectsMissingAuthIndex(t *testing.T) {
	f := newFakeHostAuthStore(t)
	f.add(t, "idx-1", "auth-1", "zcode-zai-u-1.json", "u-1", providerZai, nil)
	res := handleProviderSwitch(switchReq(`{"provider":"bigmodel"}`))
	if res["error"] == nil || len(f.saved) != 0 {
		t.Fatalf("want a validation error and no write, got %v", res)
	}
}

func TestProviderSwitchUnknownAccount(t *testing.T) {
	f := newFakeHostAuthStore(t)
	f.add(t, "idx-1", "auth-1", "zcode-zai-u-1.json", "u-1", providerZai,
		map[string]string{providerBigmodel: "oauth-bm-1"})
	res := handleProviderSwitch(switchReq(`{"auth_index":"idx-nope","provider":"bigmodel"}`))
	if res["error"] == nil || len(f.saved) != 0 {
		t.Fatalf("want account-not-found and no write, got %v", res)
	}
}

// ---------------------------------------------------------------------------
// login-time capture
// ---------------------------------------------------------------------------

func TestBuildStoredAuthFromPollKeepsTheOtherProvidersToken(t *testing.T) {
	both := &cliPollData{Status: "ready", Token: "plan-jwt"}
	both.User.UserID = "u-9"
	both.Zai.AccessToken = "oauth-zai"
	both.Bigmodel.AccessToken = "oauth-bm"

	sa := buildStoredAuthFromPoll(both, providerZai, "key.part")
	if sa.Auth.OAuthToken != "oauth-zai" {
		t.Fatalf("pinned provider token = %q", sa.Auth.OAuthToken)
	}
	if sa.Auth.AltOAuthTokens[providerBigmodel] != "oauth-bm" {
		t.Fatalf("alt slot = %v, want the bigmodel token kept", sa.Auth.AltOAuthTokens)
	}
	if _, self := sa.Auth.AltOAuthTokens[providerZai]; self {
		t.Fatalf("the pinned provider must not also be parked: %v", sa.Auth.AltOAuthTokens)
	}

	// The only shape the recorded fixtures ever show: one provider, no alt.
	single := &cliPollData{Status: "ready", Token: "plan-jwt"}
	single.Zai.AccessToken = "oauth-zai"
	if got := buildStoredAuthFromPoll(single, providerZai, "key.part").Auth.AltOAuthTokens; got != nil {
		t.Fatalf("alt slot = %v, want nil for a single-provider poll", got)
	}
}

// The slot diagnostic exists to answer "did the poll carry both providers?"
// after the fact, so it must be informative — and it must never carry the
// token itself, since it goes to a log file.
func TestLoginPollSlotsReportsLengthsOnly(t *testing.T) {
	data := &cliPollData{Status: "ready"}
	data.Zai.AccessToken = "oauth-zai-secret"
	got := loginPollSlots(data)
	if got != "zai=len16 bigmodel=absent" {
		t.Fatalf("loginPollSlots = %q", got)
	}
	data.Bigmodel.AccessToken = "bm-token"
	both := loginPollSlots(data)
	if both != "zai=len16 bigmodel=len8" {
		t.Fatalf("loginPollSlots = %q", both)
	}
	for _, leak := range []string{"oauth", "secret", "bm-token", "zai-secret"} {
		if strings.Contains(both, leak) {
			t.Fatalf("diagnostic leaked token material %q: %q", leak, both)
		}
	}
}

// ---------------------------------------------------------------------------
// the credential shape survives a round trip
// ---------------------------------------------------------------------------

func TestAltOAuthTokensRoundTripThroughBothStorageShapes(t *testing.T) {
	sa := &storedAuth{
		Auth: zcodeTokens{
			AccessToken: "k.s", OAuthToken: "o", JWT: "j", Provider: providerZai,
			Plan: planCoding, AltOAuthTokens: map[string]string{providerBigmodel: "bm"},
		},
		Account: zcodeAccount{UID: "u-1"},
	}
	nested, err := buildAuthFileJSON(sa, false, "note", nil)
	if err != nil {
		t.Fatalf("buildAuthFileJSON: %v", err)
	}
	got, err := parseStored(nested)
	if err != nil {
		t.Fatalf("parseStored(nested): %v", err)
	}
	if got.Auth.AltOAuthTokens[providerBigmodel] != "bm" {
		t.Fatalf("nested round trip lost the alt slot: %v", got.Auth.AltOAuthTokens)
	}

	// The flat shape is what manager-written files look like; adopting one
	// must not silently drop the token that makes a switch possible.
	flat := []byte(`{"accessToken":"k.s","provider":"zai","uid":"u-1","altOAuthTokens":{"bigmodel":"bm"}}`)
	gotFlat, err := parseStored(flat)
	if err != nil {
		t.Fatalf("parseStored(flat): %v", err)
	}
	if gotFlat.Auth.AltOAuthTokens[providerBigmodel] != "bm" {
		t.Fatalf("flat round trip lost the alt slot: %v", gotFlat.Auth.AltOAuthTokens)
	}
}
