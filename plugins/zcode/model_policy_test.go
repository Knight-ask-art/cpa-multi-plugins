// model_policy_test.go covers the client-facing model namespace
// (model_policy.go): alias resolution, how aliases enter and leave the catalog,
// the display prefix, and the output-token ceiling on both body paths.
//
// The two properties worth stating up front, because most of these tests exist
// to pin them down:
//
//   - An alias exists only while its TARGET survives every filter. That is what
//     keeps a start-plan credential from being offered a model its plan cannot
//     serve just because someone mapped a friendly name onto it.
//   - A name in the catalog always means the same thing to the executor as it
//     does to the reader. An alias may never shadow a real model id, because the
//     panel would then advertise one model while the upstream received another.
package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// withCleanModelPolicy blanks the policy and restores it afterwards, so no test
// can leak an alias or a prefix into another.
func withCleanModelPolicy(t *testing.T) {
	t.Helper()
	old := loadedModelPolicy()
	t.Cleanup(func() { configureModelPolicy(old) })
	configureModelPolicy(modelPolicyConfig{})
}

func modelIDs(models []pluginapi.ModelInfo) []string {
	out := make([]string, 0, len(models))
	for _, m := range models {
		out = append(out, m.ID)
	}
	return out
}

func hasModelID(models []pluginapi.ModelInfo, id string) bool {
	for _, m := range models {
		if m.ID == id {
			return true
		}
	}
	return false
}

// healthyCodingAuth is a plain coding-plan credential, the shape most of these
// tests need; the catalog filters leave it with the full pinned set.
func healthyCodingAuth() *storedAuth {
	return &storedAuth{
		Auth: zcodeTokens{
			AccessToken: "k.s", OAuthToken: "o", JWT: "j",
			Provider: providerZai, Plan: planCoding,
		},
		Account: zcodeAccount{UID: "uid-model-policy"},
	}
}

// catalogFor runs the real for-auth pipeline and returns the advertised ids.
func catalogFor(t *testing.T, sa *storedAuth, host pluginapi.HostConfigSummary) []string {
	t.Helper()
	storage, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("marshal auth: %v", err)
	}
	req, err := json.Marshal(pluginapi.AuthModelRequest{
		AuthID: "a", AuthProvider: providerName, StorageJSON: storage, Host: host,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	out, err := handleModelForAuth(req)
	if err != nil {
		t.Fatalf("handleModelForAuth: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("not ok: %s", out)
	}
	var resp pluginapi.ModelResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("model response: %v", err)
	}
	return modelIDs(resp.Models)
}

// exclusions builds the oauth-excluded-models host config for zcode.
func exclusions(models ...string) pluginapi.HostConfigSummary {
	return pluginapi.HostConfigSummary{
		ExcludedModels: map[string][]string{providerName: models},
	}
}

// ---------------------------------------------------------------------------
// resolveUpstreamModel
// ---------------------------------------------------------------------------

func TestResolveUpstreamModel(t *testing.T) {
	withCleanModelPolicy(t)
	configureModelPolicy(modelPolicyConfig{aliases: map[string]string{
		"gpt-4o":            "glm-4.6",
		"claude-3-5-sonnet": "glm-5.3",
	}})

	for _, c := range []struct{ in, want, why string }{
		{"gpt-4o", "glm-4.6", "a bare alias resolves"},
		{"GPT-4O", "glm-4.6", "alias matching ignores case"},
		{"  gpt-4o  ", "glm-4.6", "surrounding space is not part of the name"},
		{"zcode/gpt-4o", "glm-4.6", "a prefixed alias resolves via its stripped form"},
		{"zcode/glm-4.6", "glm-4.6", "a prefixed catalog id is stripped"},
		{"glm-4.6", "glm-4.6", "a catalog id passes through"},
		{"glm-5.3", "glm-5.3", "an unmapped catalog id passes through"},
		{"something-else", "something-else", "an unknown name is not invented"},
		{"", "", "an empty name stays empty"},
	} {
		if got := resolveUpstreamModel(c.in); got != c.want {
			t.Fatalf("resolveUpstreamModel(%q) = %q, want %q (%s)", c.in, got, c.want, c.why)
		}
	}

	// Idempotent for anything the catalog actually serves — cooldown keys pass
	// through this function twice on some paths.
	for _, id := range modelIDs(zcodeModels()) {
		c := resolveUpstreamModel(id)
		if resolveUpstreamModel(c) != c {
			t.Fatalf("resolveUpstreamModel is not idempotent for %q", id)
		}
		if c != id {
			t.Fatalf("catalog id %q was rewritten to %q", id, c)
		}
	}
}

// The catalog advertises glm-4.6 and the executor must send glm-4.6. An alias
// that shadows a real id would break exactly that, so it is refused outright.
func TestAliasNeverShadowsACatalogModel(t *testing.T) {
	withCleanModelPolicy(t)
	configureModelPolicy(modelPolicyConfig{aliases: map[string]string{
		"glm-4.6": "glm-5.3",
		"gpt-4o":  "glm-4.6",
	}})

	if got := resolveUpstreamModel("glm-4.6"); got != "glm-4.6" {
		t.Fatalf("a shadowing alias rewrote a real model id to %q", got)
	}
	// ...and the colliding entry is not published either, so the catalog and the
	// executor agree on what "glm-4.6" means.
	catalog := decorateCatalog(zcodeModels())
	count := 0
	for _, m := range catalog {
		if m.ID == "glm-4.6" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("catalog lists glm-4.6 %d times, want exactly 1", count)
	}
	// An unshadowed alias from the same table still works.
	if got := resolveUpstreamModel("gpt-4o"); got != "glm-4.6" {
		t.Fatalf("gpt-4o resolved to %q", got)
	}
}

// Resolution is single-hop: a→b must not chase b→c, which would let a typo in
// one entry silently retarget another.
func TestAliasResolutionIsSingleHop(t *testing.T) {
	withCleanModelPolicy(t)
	configureModelPolicy(modelPolicyConfig{aliases: map[string]string{
		"alpha": "glm-5.3",
		"beta":  "alpha",
	}})
	if got := resolveUpstreamModel("beta"); got != "alpha" {
		t.Fatalf("beta = %q, want the single hop to alpha", got)
	}
}

// ---------------------------------------------------------------------------
// withAliases / applyModelPrefix
// ---------------------------------------------------------------------------

func TestWithAliasesOnlyForSurvivingTargets(t *testing.T) {
	withCleanModelPolicy(t)
	aliases := map[string]string{"gpt-4o": "glm-4.6", "gone": "not-in-catalog"}

	full := withAliases(zcodeModels(), aliases)
	if !hasModelID(full, "gpt-4o") {
		t.Fatal("an alias whose target is present must be published")
	}
	if hasModelID(full, "gone") {
		t.Fatal("an alias whose target is absent must not be published")
	}
	// The alias inherits its target's numbers and says what it resolves to.
	for _, m := range full {
		if m.ID != "gpt-4o" {
			continue
		}
		var target pluginapi.ModelInfo
		for _, x := range zcodeModels() {
			if x.ID == "glm-4.6" {
				target = x
			}
		}
		if m.ContextLength != target.ContextLength || m.MaxCompletionTokens != target.MaxCompletionTokens {
			t.Fatalf("alias spec = %d/%d, want the target's %d/%d",
				m.ContextLength, m.MaxCompletionTokens, target.ContextLength, target.MaxCompletionTokens)
		}
		if !strings.Contains(m.Name, target.Name) {
			t.Fatalf("alias name %q does not name its target %q", m.Name, target.Name)
		}
	}

	// A target removed by an earlier filter takes its alias with it — this is
	// the whole mechanism, exercised through a real narrowing filter.
	startPlan := healthyCodingAuth()
	startPlan.Auth.Plan = planStart
	narrowed := filterPlanModels(startPlan, zcodeModels())
	if got := withAliases(narrowed, aliases); hasModelID(got, "gpt-4o") {
		t.Fatal("an alias survived its target being filtered out by the plan tier")
	}
	if got := withAliases(narrowed, map[string]string{"flash": "glm-5.3-flash"}); !hasModelID(got, "flash") {
		t.Fatal("an alias for a model the plan does serve must survive")
	}
}

// Map iteration order would reshuffle the host's model list on every request.
func TestWithAliasesIsDeterministic(t *testing.T) {
	withCleanModelPolicy(t)
	aliases := map[string]string{"zeta": "glm-4.6", "alpha": "glm-5.3", "mid": "glm-5"}
	first := modelIDs(withAliases(zcodeModels(), aliases))
	for i := 0; i < 20; i++ {
		got := modelIDs(withAliases(zcodeModels(), aliases))
		if len(got) != len(first) {
			t.Fatalf("length changed between calls")
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("catalog order changed between calls at %d: %q vs %q", j, got[j], first[j])
			}
		}
	}
	// Aliases are appended after the real models, in sorted order.
	tail := first[len(first)-3:]
	if tail[0] != "alpha" || tail[1] != "mid" || tail[2] != "zeta" {
		t.Fatalf("alias tail = %v, want sorted [alpha mid zeta]", tail)
	}
}

func TestApplyModelPrefix(t *testing.T) {
	base := zcodeModels()
	got := modelIDs(applyModelPrefix(base, "zcode"))
	if !hasModelID2(got, "zcode/glm-5.3") || hasModelID2(got, "glm-5.3") {
		t.Fatalf("prefix not applied: %v", got[:3])
	}
	// A trailing slash in the config is not doubled.
	if again := modelIDs(applyModelPrefix(base, "zcode/")); again[0] != got[0] {
		t.Fatalf("trailing slash changed the result: %q vs %q", again[0], got[0])
	}
	// Idempotent: applying twice must not produce "zcode/zcode/...".
	twice := modelIDs(applyModelPrefix(applyModelPrefix(base, "zcode"), "zcode"))
	for _, id := range twice {
		if strings.Count(id, "zcode/") > 1 {
			t.Fatalf("prefix applied twice: %q", id)
		}
	}
	// The empty prefix is a no-op and must not copy the slice.
	if same := applyModelPrefix(base, ""); &same[0] != &base[0] {
		t.Fatal("an empty prefix should return the input unchanged")
	}
}

func hasModelID2(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// the catalog as a whole
// ---------------------------------------------------------------------------

func TestCatalogAdvertisesAliasesAndPrefix(t *testing.T) {
	withCleanModelPolicy(t)
	sa := healthyCodingAuth()
	base := catalogFor(t, sa, pluginapi.HostConfigSummary{})
	if !hasModelID2(base, "glm-4.6") {
		t.Fatal("precondition: the bare catalog must serve glm-4.6")
	}

	configureModelPolicy(modelPolicyConfig{
		prefix:  "zcode",
		aliases: map[string]string{"gpt-4o": "glm-4.6"},
	})
	got := catalogFor(t, sa, pluginapi.HostConfigSummary{})
	for _, want := range []string{"zcode/glm-4.6", "zcode/gpt-4o"} {
		if !hasModelID2(got, want) {
			t.Fatalf("catalog is missing %q: %v", want, got)
		}
	}
	if hasModelID2(got, "glm-4.6") {
		t.Fatal("a prefixed catalog must not also advertise the bare id")
	}

	// Whatever the catalog advertises, the executor must send something the
	// upstream accepts — that is the invariant the whole file rests on.
	known := map[string]bool{}
	for _, m := range zcodeModels() {
		known[m.ID] = true
	}
	for _, id := range got {
		if !known[resolveUpstreamModel(id)] {
			t.Fatalf("advertised %q resolves to %q, which is not a catalog model",
				id, resolveUpstreamModel(id))
		}
	}
}

// A start-plan credential must gain an alias only for a model its tier serves.
// This is the case the ordering in handleModelForAuth exists to protect.
func TestAliasRespectsThePlanTier(t *testing.T) {
	withCleanModelPolicy(t)
	sa := healthyCodingAuth()
	sa.Auth.Plan = planStart
	configureModelPolicy(modelPolicyConfig{aliases: map[string]string{
		"big":  "glm-4.7",       // not on the start-plan tier
		"fast": "glm-5.3-flash", // is
	}})

	got := catalogFor(t, sa, pluginapi.HostConfigSummary{})
	if hasModelID2(got, "big") {
		t.Fatalf("an alias for an off-tier model leaked into the catalog: %v", got)
	}
	if !hasModelID2(got, "fast") {
		t.Fatalf("an alias for an on-tier model is missing: %v", got)
	}
}

// A cooling target takes its alias out of the catalog with it: the pair is
// degraded upstream under every name the client might use for it.
func TestAliasDisappearsWithItsCoolingTarget(t *testing.T) {
	withCleanModelPolicy(t)
	sa := healthyCodingAuth()
	authID := cooldownAuthIDFor(sa)
	t.Cleanup(func() { clearModelCooldown(authID, "") })
	clearModelCooldown(authID, "")

	configureModelPolicy(modelPolicyConfig{aliases: map[string]string{"gpt-4o": "glm-4.6"}})
	if got := catalogFor(t, sa, pluginapi.HostConfigSummary{}); !hasModelID2(got, "gpt-4o") {
		t.Fatalf("precondition: the alias must be offered while healthy: %v", got)
	}

	markModelCooldown(authID, "glm-4.6", cooldownReasonRateLimit)
	got := catalogFor(t, sa, pluginapi.HostConfigSummary{})
	if hasModelID2(got, "glm-4.6") {
		t.Fatal("a cooling model must be withdrawn")
	}
	if hasModelID2(got, "gpt-4o") {
		t.Fatal("the alias of a cooling model must be withdrawn too")
	}
}

// ---------------------------------------------------------------------------
// exclusion versus the new names
// ---------------------------------------------------------------------------

func TestExclusionMatchesEveryNameAModelHas(t *testing.T) {
	sa := healthyCodingAuth()

	// The pre-existing behaviour: a bare catalog id bans that model.
	withCleanModelPolicy(t)
	got := catalogFor(t, sa, exclusions("glm-4.6"))
	if hasModelID2(got, "glm-4.6") {
		t.Fatal("a bare-id exclusion stopped working")
	}

	// A prefixed id, as the panel's picker now offers them.
	withCleanModelPolicy(t)
	configureModelPolicy(modelPolicyConfig{prefix: "zcode"})
	got = catalogFor(t, sa, exclusions("zcode/glm-4.6"))
	if hasModelID2(got, "zcode/glm-4.6") {
		t.Fatal("a prefixed exclusion did not match its own advertised id")
	}
	// ...and the bare spelling of a prefixed catalog still works, because
	// operators have hand-written configs in that form.
	got = catalogFor(t, sa, exclusions("glm-4.6"))
	if hasModelID2(got, "zcode/glm-4.6") {
		t.Fatal("a bare-id exclusion did not match the prefixed catalog")
	}

	// Banning an ALIAS removes the alias alone; its target stays served.
	withCleanModelPolicy(t)
	configureModelPolicy(modelPolicyConfig{aliases: map[string]string{"gpt-4o": "glm-4.6"}})
	got = catalogFor(t, sa, exclusions("gpt-4o"))
	if hasModelID2(got, "gpt-4o") {
		t.Fatal("banning the alias left the alias in the catalog")
	}
	if !hasModelID2(got, "glm-4.6") {
		t.Fatal("banning the alias also removed its target, which it must not")
	}

	// Banning the TARGET removes it and every alias pointing at it.
	got = catalogFor(t, sa, exclusions("glm-4.6"))
	if hasModelID2(got, "glm-4.6") || hasModelID2(got, "gpt-4o") {
		t.Fatalf("banning the target must remove it and its aliases: %v", got)
	}
}

// ---------------------------------------------------------------------------
// cooldown key space
// ---------------------------------------------------------------------------

// A cooldown is a fact about an upstream (account, model) pair. Keying it on the
// client-facing name would let "gpt-4o" cool while the catalog kept offering
// glm-4.6 — the same upstream, the same limit.
func TestCooldownKeyIsSharedByAliasAndTarget(t *testing.T) {
	withCleanModelPolicy(t)
	configureModelPolicy(modelPolicyConfig{aliases: map[string]string{"gpt-4o": "glm-4.6"}})
	for _, name := range []string{"gpt-4o", "GPT-4O", "zcode/gpt-4o", "glm-4.6", "zcode/glm-4.6"} {
		if got := normalizeCooldownModel(name); got != "glm-4.6" {
			t.Fatalf("normalizeCooldownModel(%q) = %q, want glm-4.6", name, got)
		}
	}
	// requestModelForCooldown feeds it from both req.Model and host metadata.
	got := requestModelForCooldown("gpt-4o", map[string]any{"auth_selection_model": "zcode/gpt-4o"})
	if got != "glm-4.6" {
		t.Fatalf("metadata path = %q", got)
	}
}

// ---------------------------------------------------------------------------
// decodeModelPolicy
// ---------------------------------------------------------------------------

func TestDecodeModelPolicyBothShapes(t *testing.T) {
	// Block-style nested mapping — what a YAML author writes.
	block := []byte("login_provider: zai\n" +
		"model_prefix: zcode\n" +
		"model_max_tokens: 4096\n" +
		"model_map:\n" +
		"  gpt-4o: glm-4.6\n" +
		"  \"claude-3-5-sonnet\": glm-5.3\n")
	got := decodeModelPolicy(block)
	if got.prefix != "zcode" {
		t.Fatalf("prefix = %q", got.prefix)
	}
	if got.maxTokens != 4096 {
		t.Fatalf("maxTokens = %d", got.maxTokens)
	}
	if len(got.aliases) != 2 || got.aliases["gpt-4o"] != "glm-4.6" || got.aliases["claude-3-5-sonnet"] != "glm-5.3" {
		t.Fatalf("aliases = %v", got.aliases)
	}

	// Flow style — the shape the raw-line scan cannot match at all.
	flow := []byte("{model_prefix: z, model_map: {gpt-4o: glm-4.6}, model_max_tokens: 100}")
	got = decodeModelPolicy(flow)
	if got.prefix != "z" || got.aliases["gpt-4o"] != "glm-4.6" || got.maxTokens != 100 {
		t.Fatalf("flow decode = %+v", got)
	}
	// The flow form must not be re-read as CSV by the line scan (which would
	// produce an alias literally named "{model_prefix").
	for alias := range got.aliases {
		if strings.ContainsAny(alias, "{}:") {
			t.Fatalf("flow syntax leaked into an alias name: %q", alias)
		}
	}

	// Flat CSV — readable by the line scan, and the form the host UI can write
	// into a single string field.
	flat := []byte("model_map: \"gpt-4o=glm-4.6, claude-3-5-sonnet=glm-5.3\"\n")
	got = decodeModelPolicy(flat)
	if got.aliases["gpt-4o"] != "glm-4.6" || got.aliases["claude-3-5-sonnet"] != "glm-5.3" {
		t.Fatalf("csv decode = %v", got.aliases)
	}

	// Junk is dropped, not guessed at.
	junk := decodeModelPolicy([]byte("model_map: \"no-equals-here, =empty, self=self, ok=glm-5\"\n"))
	if len(junk.aliases) != 1 || junk.aliases["ok"] != "glm-5" {
		t.Fatalf("junk decode = %v", junk.aliases)
	}

	// A longer key that merely starts with a policy key must not match it.
	decoy := decodeModelPolicy([]byte("model_max_tokens_extra: 99\nmodel_prefixes: nope\n"))
	if decoy.maxTokens != 0 || decoy.prefix != "" {
		t.Fatalf("decoy keys were matched: %+v", decoy)
	}

	// An empty payload clears the policy rather than keeping a stale one.
	empty := decodeModelPolicy(nil)
	if empty.prefix != "" || len(empty.aliases) != 0 || empty.maxTokens != 0 {
		t.Fatalf("empty decode = %+v", empty)
	}
}

// ---------------------------------------------------------------------------
// the output-token ceiling
// ---------------------------------------------------------------------------

func rawBody(t *testing.T, s string) map[string]json.RawMessage {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &obj); err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return obj
}

func fieldInt(t *testing.T, obj map[string]json.RawMessage, key string) int64 {
	t.Helper()
	var n int64
	if err := json.Unmarshal(obj[key], &n); err != nil {
		t.Fatalf("field %s: %v", key, err)
	}
	return n
}

func TestClampBodyMaxTokens(t *testing.T) {
	withCleanModelPolicy(t)
	configureModelPolicy(modelPolicyConfig{maxTokens: 1000})

	// A larger ceiling is lowered.
	obj := rawBody(t, `{"model":"glm-5.3","max_tokens":5000}`)
	clampBodyMaxTokens(obj)
	if got := fieldInt(t, obj, "max_tokens"); got != 1000 {
		t.Fatalf("max_tokens = %d, want the cap", got)
	}

	// A smaller one is left ALONE — the cap lowers, it never raises.
	obj = rawBody(t, `{"max_tokens":10}`)
	clampBodyMaxTokens(obj)
	if got := fieldInt(t, obj, "max_tokens"); got != 10 {
		t.Fatalf("max_tokens = %d, want it untouched", got)
	}

	// Exactly at the cap is not over it.
	obj = rawBody(t, `{"max_tokens":1000}`)
	clampBodyMaxTokens(obj)
	if got := fieldInt(t, obj, "max_tokens"); got != 1000 {
		t.Fatalf("max_tokens = %d", got)
	}

	// The newer spelling of the same field is clamped too, or the cap is
	// bypassable by sending one key instead of the other.
	obj = rawBody(t, `{"max_completion_tokens":9000}`)
	clampBodyMaxTokens(obj)
	if got := fieldInt(t, obj, "max_completion_tokens"); got != 1000 {
		t.Fatalf("max_completion_tokens = %d", got)
	}

	// A body with no ceiling keeps none: the upstream's default is a better
	// answer than one this plugin invents.
	obj = rawBody(t, `{"model":"glm-5.3"}`)
	clampBodyMaxTokens(obj)
	if _, present := obj["max_tokens"]; present {
		t.Fatal("a cap must not invent a max_tokens the client did not send")
	}

	// Null and non-numeric values are left untouched rather than coerced.
	for _, body := range []string{`{"max_tokens":null}`, `{"max_tokens":"lots"}`} {
		obj = rawBody(t, body)
		clampBodyMaxTokens(obj)
		if string(obj["max_tokens"]) == "1000" {
			t.Fatalf("%s was coerced to the cap", body)
		}
	}

	// With no cap configured the body is byte-identical to before.
	configureModelPolicy(modelPolicyConfig{})
	obj = rawBody(t, `{"model":"glm-5.3","max_tokens":5000}`)
	clampBodyMaxTokens(obj)
	if got := fieldInt(t, obj, "max_tokens"); got != 5000 {
		t.Fatalf("max_tokens = %d with no cap configured", got)
	}
}

func TestClampAnthropicMaxTokens(t *testing.T) {
	withCleanModelPolicy(t)
	configureModelPolicy(modelPolicyConfig{maxTokens: 1000})

	body := map[string]any{"max_tokens": int64(5000)}
	clampAnthropicMaxTokens(body)
	if got, _ := body["max_tokens"].(int64); got != 1000 {
		t.Fatalf("max_tokens = %v", body["max_tokens"])
	}
	// Under the cap: untouched.
	body = map[string]any{"max_tokens": int64(500)}
	clampAnthropicMaxTokens(body)
	if got, _ := body["max_tokens"].(int64); got != 500 {
		t.Fatalf("max_tokens = %v", body["max_tokens"])
	}
	// Absent: not invented.
	body = map[string]any{"model": "glm-5.3"}
	clampAnthropicMaxTokens(body)
	if _, present := body["max_tokens"]; present {
		t.Fatal("a cap must not invent max_tokens")
	}
	// float64 arrives when the body was round-tripped through interface{}.
	body = map[string]any{"max_tokens": float64(5000)}
	clampAnthropicMaxTokens(body)
	if got, _ := body["max_tokens"].(int64); got != 1000 {
		t.Fatalf("float form = %v", body["max_tokens"])
	}
}

// buildChatBody is the OpenAI-path funnel for both the streaming and the
// non-streaming branch, so one clamp there covers both.
func TestBuildChatBodyHonoursTheCeiling(t *testing.T) {
	withCleanModelPolicy(t)
	payload := []byte(`{"model":"gpt-4o","max_tokens":5000,"messages":[{"role":"user","content":"hi"}]}`)

	plain, err := buildChatBody(payload, "glm-4.6", false)
	if err != nil {
		t.Fatalf("buildChatBody: %v", err)
	}
	if !strings.Contains(plain, "5000") {
		t.Fatalf("with no cap the body must be untouched: %s", plain)
	}

	configureModelPolicy(modelPolicyConfig{maxTokens: 1000})
	capped, err := buildChatBody(payload, "glm-4.6", false)
	if err != nil {
		t.Fatalf("buildChatBody: %v", err)
	}
	if strings.Contains(capped, "5000") {
		t.Fatalf("the cap did not reach the body: %s", capped)
	}
	if !strings.Contains(capped, `"max_tokens":1000`) {
		t.Fatalf("capped body = %s", capped)
	}
	// The rest of the body survives the round trip.
	for _, want := range []string{"glm-4.6", `"stream":false`, "messages"} {
		if !strings.Contains(capped, want) {
			t.Fatalf("capped body lost %q: %s", want, capped)
		}
	}
}

// The anthropic path folds a reasoning budget into max_tokens AFTER the value is
// first chosen, so a clamp placed before that would be undone by it.
func TestAnthropicClampRunsAfterTheThinkingBudget(t *testing.T) {
	withCleanModelPolicy(t)
	payload := []byte(`{"model":"glm-5.3","max_tokens":500,"messages":[{"role":"user","content":"hi"}]}`)

	uncapped, err := translateOpenAIToAnthropicBody(payload, "glm-5.3", false, providerZai, "dev", time.Now())
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var unbounded map[string]any
	if err := json.Unmarshal(uncapped, &unbounded); err != nil {
		t.Fatalf("parse uncapped: %v", err)
	}
	base, _ := unbounded["max_tokens"].(float64)
	if base <= 500 {
		t.Skipf("this model takes no reasoning budget (max_tokens=%v); nothing to assert", unbounded["max_tokens"])
	}

	configureModelPolicy(modelPolicyConfig{maxTokens: 600})
	capped, err := translateOpenAIToAnthropicBody(payload, "glm-5.3", false, providerZai, "dev", time.Now())
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var bounded map[string]any
	if err := json.Unmarshal(capped, &bounded); err != nil {
		t.Fatalf("parse capped: %v", err)
	}
	got, _ := bounded["max_tokens"].(float64)
	if got != 600 {
		t.Fatalf("max_tokens = %v, want the cap 600 (uncapped was %v)", got, base)
	}
	// The thinking block itself is not disturbed by the clamp.
	if _, present := bounded["thinking"]; !present {
		t.Fatal("the clamp removed the thinking block")
	}
}

// ---------------------------------------------------------------------------
// panel
// ---------------------------------------------------------------------------

func TestModelPolicySnapshotFlagsUnresolvedTargets(t *testing.T) {
	withCleanModelPolicy(t)
	if got := modelPolicySnapshotForPanel(); got["active"] != false {
		t.Fatalf("an empty policy must read as inactive: %v", got)
	}

	configureModelPolicy(modelPolicyConfig{
		prefix:    "zcode",
		maxTokens: 2048,
		aliases:   map[string]string{"gpt-4o": "glm-4.6", "typo": "glm-4.7x"},
	})
	got := modelPolicySnapshotForPanel()
	if got["prefix"] != "zcode" || got["max_tokens"] != int64(2048) || got["active"] != true {
		t.Fatalf("snapshot = %v", got)
	}
	unresolved, _ := got["unresolved"].([]string)
	if len(unresolved) != 1 || !strings.Contains(unresolved[0], "typo") {
		t.Fatalf("a target that is not in the catalog must be named: %v", got["unresolved"])
	}
	rows, _ := got["aliases"].([]map[string]string)
	if len(rows) != 2 {
		t.Fatalf("alias rows = %v", rows)
	}
	// The resolvable alias reports what it becomes; the typo says so.
	for _, r := range rows {
		switch r["alias"] {
		case "gpt-4o":
			if r["target_name"] != "GLM 4.6" {
				t.Fatalf("resolved alias row = %v", r)
			}
		case "typo":
			if r["target_name"] != "（不在目录中）" {
				t.Fatalf("unresolved alias row = %v", r)
			}
		}
	}
}

// The exclusion picker must offer exactly the ids the operator sees in their
// client, or a pick would silently exclude nothing.
func TestModelCatalogPickerUsesAdvertisedIDs(t *testing.T) {
	withCleanModelPolicy(t)
	ids := func() []string {
		raw := handleModelCatalog()
		blob, err := json.Marshal(raw["groups"])
		if err != nil {
			t.Fatalf("marshal groups: %v", err)
		}
		var groups []struct {
			Models []struct {
				ID string `json:"id"`
			} `json:"models"`
		}
		if err := json.Unmarshal(blob, &groups); err != nil {
			t.Fatalf("groups: %v", err)
		}
		out := []string{}
		for _, g := range groups {
			for _, m := range g.Models {
				out = append(out, m.ID)
			}
		}
		return out
	}

	if got := ids(); !hasModelID2(got, "glm-4.6") {
		t.Fatalf("bare catalog picker = %v", got)
	}
	configureModelPolicy(modelPolicyConfig{
		prefix:  "zcode",
		aliases: map[string]string{"gpt-4o": "glm-4.6"},
	})
	got := ids()
	for _, want := range []string{"zcode/glm-4.6", "zcode/gpt-4o"} {
		if !hasModelID2(got, want) {
			t.Fatalf("prefixed picker is missing %q: %v", want, got)
		}
	}
	// And every offered id really does exclude something, which is the point: a
	// picker entry the exclusion filter cannot match would be a dead control.
	sa := healthyCodingAuth()
	for _, id := range got {
		if hasModelID2(catalogFor(t, sa, exclusions(id)), id) {
			t.Fatalf("picking %q from the picker would exclude nothing", id)
		}
	}
}
