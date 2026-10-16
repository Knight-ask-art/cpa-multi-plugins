// plane.go owns the entitlement-plane model routing added 2026-09-27.
//
// Why this exists: the billing plane (zcode.z.ai, JWT) can carry activity /
// trial packages (e.g. the "ZCode Weekend Build" start-plan bucket granting
// model:glm-5.3-flash) that do NOT exist on the coding plane the resolved
// plan key talks to (api.z.ai/api/coding/paas/v4). A credential tagged
// coding-plan used to send every model to the coding plane and got
// `429 {"error":{"code":"1113","message":"Insufficient balance or no
// resource package. Please recharge."}}` for models whose only entitlement
// lives on the JWT plane (measured live: coding plane 429/1113 with the
// resolved key on both /api/coding/paas/v4 and /api/paas/v4, while
// billing/balance shows the 300M glm-5.3-flash bucket under plan
// zcode-v3-start-plan-0924-wk-2; the zcode-plan anthropic gateway
// authenticates the same JWT — bogus JWT → 401, real JWT passes auth and
// only trips the risk-control captcha layer).
//
// Two mechanisms cooperate:
//   - proactive: every billing/balance fetch harvests bucket
//     capabilities ("model:<id>") into a small per-UID cache; routeFor
//     pre-routes those models to the JWT anthropic lane.
//   - reactive: a coding-plane failure with no-resource-package semantics
//     (1113 family) triggers ONE fallback attempt on the JWT anthropic
//     lane; success memoizes the model so later calls pre-route.
package main

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// startPlaneEntry is one credential's JWT-plane model coverage snapshot.
type startPlaneEntry struct {
	models  map[string]struct{}
	fetched time.Time
}

var (
	startPlaneMu     sync.RWMutex
	startPlaneModels = map[string]*startPlaneEntry{} // account UID -> entry
	startPlaneTTL    = 6 * time.Hour
)

// harvestStartPlaneCapabilities folds balance-row capabilities
// ("model:<id>") into the per-UID cache. Called after every successful
// billing/balance parse. Rows without capabilities contribute nothing; an
// account whose buckets carry no model capabilities keeps whatever was
// cached before until the entry expires.
func harvestStartPlaneCapabilities(uid string, rows []zcodeBalance) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return
	}
	models := make(map[string]struct{})
	for _, row := range rows {
		for _, cap := range row.Capabilities {
			cap = strings.TrimSpace(cap)
			if !strings.HasPrefix(cap, "model:") {
				continue
			}
			if id := strings.TrimSpace(strings.TrimPrefix(cap, "model:")); id != "" {
				models[id] = struct{}{}
			}
		}
	}
	if len(models) == 0 {
		return
	}
	startPlaneMu.Lock()
	startPlaneModels[uid] = &startPlaneEntry{models: models, fetched: time.Now()}
	startPlaneMu.Unlock()
}

// noteStartPlaneModel memoizes a reactively discovered JWT-plane model.
func noteStartPlaneModel(uid, model string) {
	uid = strings.TrimSpace(uid)
	model = strings.TrimSpace(model)
	if uid == "" || model == "" {
		return
	}
	startPlaneMu.Lock()
	entry, ok := startPlaneModels[uid]
	if !ok || entry == nil || time.Since(entry.fetched) > startPlaneTTL {
		entry = &startPlaneEntry{models: map[string]struct{}{}, fetched: time.Now()}
		startPlaneModels[uid] = entry
	}
	entry.models[model] = struct{}{}
	startPlaneMu.Unlock()
}

// startPlaneModelSet returns a snapshot of the cached JWT-plane models for
// one credential (nil when nothing is cached or the entry expired).
func startPlaneModelSet(uid string) map[string]struct{} {
	startPlaneMu.RLock()
	defer startPlaneMu.RUnlock()
	entry, ok := startPlaneModels[uid]
	if !ok || entry == nil || time.Since(entry.fetched) > startPlaneTTL {
		return nil
	}
	out := make(map[string]struct{}, len(entry.models))
	for k := range entry.models {
		out[k] = struct{}{}
	}
	return out
}

// clearStartPlane starts a fresh entitlement snapshot for one account, or for
// every account when uid is empty. Returns how many entries were dropped.
//
// The cache is keyed by UID and holds model->plane entitlement harvested from
// the billing buckets, with a 6-hour TTL and — until now — no way to expire it
// early. That was survivable while a credential's identity never changed, but
// anything that swaps a credential underneath an account (a provider switch, a
// re-login with a different plan) leaves this table asserting entitlements the
// new credential may not have. Callers that mutate a credential must call this.
func clearStartPlane(uid string) int {
	uid = strings.TrimSpace(uid)
	startPlaneMu.Lock()
	defer startPlaneMu.Unlock()
	if uid == "" {
		n := len(startPlaneModels)
		startPlaneModels = map[string]*startPlaneEntry{}
		return n
	}
	if _, ok := startPlaneModels[uid]; !ok {
		return 0
	}
	delete(startPlaneModels, uid)
	return 1
}

// modelRidesStartPlane reports whether this model's entitlement is known to
// live on the JWT plane. Only coding-plan credentials consult the override —
// start-plan credentials already route there wholesale.
func modelRidesStartPlane(sa *storedAuth, model string) bool {
	if sa == nil || sa.Auth.Plan == planStart {
		return false
	}
	if strings.TrimSpace(sa.Auth.JWT) == "" {
		return false
	}
	set := startPlaneModelSet(sa.Account.UID)
	if set == nil {
		return false
	}
	_, ok := set[model]
	return ok
}

// isNoResourcePackageError reports whether an upstream chat rejection means
// "the credential this request rode has no package covering the model".
// Observed shapes: HTTP 429 + biz 1113 ("Insufficient balance or no
// resource package. Please recharge.") on the coding plane; the same body
// can arrive under 402/400. Status-wise 429/402 dominate; 400 is included
// because the family shares the body markers.
func isNoResourcePackageError(status int, body string) bool {
	if status != http.StatusTooManyRequests &&
		status != http.StatusPaymentRequired &&
		status != http.StatusBadRequest {
		return false
	}
	return isHardQuotaError(status, body)
}

// startPlaneFallbackRoute builds the JWT anthropic route used by the
// reactive fallback (same shape routeFor returns for start-plan).
func startPlaneFallbackRoute() chatRoute {
	return chatRoute{endpoint: startPlanAnthropicEndpoint, anthropic: true, applyHeaders: applyStartPlanChatHeaders, plane: planeJWTAnthropic}
}

// startPlaneFallbackBody decides and builds the JWT-lane retry for a failed
// coding-plane chat: ok=true exactly when the first attempt rode the coding
// plane (no off-peak ticket), the credential carries a JWT, and the failure
// reads as no-resource-package (1113 family). The returned body is the
// ORIGINAL payload re-translated to the anthropic dialect with the caller's
// stream flag — the coding-plane body cannot be reused across dialects.
func startPlaneFallbackBody(sa *storedAuth, route chatRoute, status int, failBody string, origPayload []byte, model string, stream bool) (chatRoute, string, bool) {
	if route.anthropic || route.offPeakTicketID != "" {
		return chatRoute{}, "", false
	}
	if sa == nil || strings.TrimSpace(sa.Auth.JWT) == "" || len(origPayload) == 0 {
		return chatRoute{}, "", false
	}
	if !isNoResourcePackageError(status, failBody) {
		return chatRoute{}, "", false
	}
	anthropicBody, err := translateOpenAIToAnthropicBody(origPayload, model, stream, authProviderFor(sa), sa.Auth.DeviceMid, time.Now())
	if err != nil {
		return chatRoute{}, "", false
	}
	// The primary route was wrong about this model's entitlement; count it so
	// the panel can show how often the proactive harvest missed.
	recordPlaneFallback(sa)
	return startPlaneFallbackRoute(), string(anthropicBody), true
}

// credKindForRoute names the credential a route actually carries. The off-peak
// lane is the odd one: it is anthropic-dialect like the JWT lane, but its
// headers authenticate with the resolved plan KEY plus a ticket (offpeak.go), so
// a failure there says nothing about the JWT.
func credKindForRoute(route chatRoute) credKind {
	if route.anthropic && route.offPeakTicketID == "" {
		return credKindJWT
	}
	return credKindKey
}

// credFallbackRoute builds the coding-plane OpenAI route used by the
// dual-credential fallback: the OTHER credential of the same account, on the
// endpoint its provider serves.
func credFallbackRoute(sa *storedAuth) chatRoute {
	plane := planeZaiCoding
	if authProviderFor(sa) == providerBigmodel {
		plane = planeBigmodelCoding
	}
	return chatRoute{endpoint: chatEndpointFor(sa), applyHeaders: applyChatHeaders, plane: plane}
}

// credFallbackBody decides and builds the API-key retry for a failed JWT-lane
// chat — the mirror of startPlaneFallbackBody, in the opposite direction.
//
// THE QUESTION THIS CANNOT ANSWER. Whether the coding plane serves a model the
// entitlement harvest routed to the JWT lane is not knowable from here: the
// harvest records that a model's bucket capabilities name it, and a model can be
// entitled on both planes, so the fallback is a one-shot bet rather than a
// certainty. It is only taken for failures that are about the CREDENTIAL or the
// GATEWAY rather than about entitlement (see credFailureFor), and the panel's
// "helped" counter is what turns the bet into a measurement.
//
// Refused when:
//   - the account is on the start-plan tier, which the coding plane does not
//     serve at all (offpeak.go documents the same rejection);
//   - the credential has no resolved key, so there is nothing to fall back TO;
//   - the key is already parked (cred_state.go) — re-learning a known answer
//     costs the caller a round trip;
//   - the failure does not classify as credential-scoped.
func credFallbackBody(hostID string, sa *storedAuth, route chatRoute, status int, failBody string, hdrs http.Header, origPayload []byte, model string, stream bool) (chatRoute, string, bool) {
	if sa == nil || !route.anthropic || route.offPeakTicketID != "" {
		return chatRoute{}, "", false
	}
	if authPlanFor(sa) == planStart {
		return chatRoute{}, "", false
	}
	if strings.TrimSpace(sa.Auth.AccessToken) == "" || len(origPayload) == 0 {
		return chatRoute{}, "", false
	}
	if credBlockedFor(hostID, sa, credKindKey) {
		return chatRoute{}, "", false
	}
	challenged := false
	if hdrs != nil {
		challenged = startPlanCaptchaChallenge(status, strings.TrimSpace(hdrs.Get("x-aliyun-captcha-verify-param")), failBody)
	}
	if _, ok := credFailureFor(status, failBody, challenged); !ok {
		return chatRoute{}, "", false
	}
	// The dialects differ, so the coding-plane body is rebuilt from the original
	// payload rather than reused — same reason startPlaneFallbackBody rebuilds
	// in the other direction.
	body, err := buildChatBody(origPayload, model, stream)
	if err != nil {
		return chatRoute{}, "", false
	}
	recordCredFallback()
	return credFallbackRoute(sa), body, true
}

// noteRouteFailure parks a credential after a SURFACED upstream answer. Only
// real answers qualify: a body-build or parse failure never reaches this, and
// must not, because it says nothing about the credential.
func noteRouteFailure(hostID string, sa *storedAuth, route chatRoute, status int, failBody string) {
	reason, ok := credFailureFor(status, failBody, false)
	if !ok {
		return
	}
	markCredFailureFor(hostID, sa, credKindForRoute(route), reason, status)
}

// tryStartPlaneStream performs ONE send on the JWT anthropic route. ok=false
// on any transport/status failure; a non-nil returned stream is the
// caller's to drain and Close. On a rejected send, failBody carries the
// drained upstream body so callers can surface the JWT plane's own answer.
// Nothing here memoizes — callers do that on a
// downstream success so a merely-accepted request is not mistaken for a
// charged completion.
func tryStartPlaneStream(sa *storedAuth, route chatRoute, body string) (*hostHTTPStream, int, http.Header, string, bool) {
	buildReq := func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, route.endpoint, strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		route.applyHeaders(req, sa, body)
		return req, nil
	}
	recordPlaneHit(route.plane, sa)
	stream, sc, hdrs, err := sendChatWithSigning(sa, buildReq)
	if err != nil || sc >= 400 {
		failBody := ""
		if stream != nil {
			raw, _ := io.ReadAll(newHostStreamReader(stream))
			failBody = string(raw)
			stream.Close()
		}
		return nil, sc, hdrs, failBody, false
	}
	return stream, sc, hdrs, "", true
}

// tryStartPlaneSend is tryStartPlaneStream drained to a body (non-stream path).
func tryStartPlaneSend(sa *storedAuth, route chatRoute, body string) ([]byte, int, http.Header, string, bool) {
	stream, sc, hdrs, failBody, ok := tryStartPlaneStream(sa, route, body)
	if !ok {
		return nil, sc, hdrs, failBody, false
	}
	payload, rerr := io.ReadAll(newHostStreamReader(stream))
	stream.Close()
	if rerr != nil {
		return nil, sc, hdrs, "", false
	}
	return payload, sc, hdrs, "", true
}

// noPackageNoJWTHint returns the diagnostic suffix for a no-resource-package
// failure on a credential that carries NO plan JWT — the one configuration in
// which the JWT-plane fallback can never run (both the pre-route and the
// reactive retry require it). Without the hint that account just 1113s with
// no visible reason (issue #21 follow-up: claimed weekend bucket, old
// credential, nothing works and nothing says why).
func noPackageNoJWTHint(sa *storedAuth, status int, body string) string {
	if sa == nil || strings.TrimSpace(sa.Auth.JWT) != "" {
		return ""
	}
	if !isNoResourcePackageError(status, body) {
		return ""
	}
	return "该账号凭证没有 plan JWT（旧版登录或导入的凭据），活动/周末套餐额度永远路由不到 JWT 平面——请重新登录一次补齐 JWT"
}
