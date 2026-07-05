package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Kong/go-pdk"
	"github.com/golang-jwt/jwt/v5"
)

func exitJSON(kong *pdk.PDK, status int, v any, headers map[string][]string) {
	body, _ := json.Marshal(v)
	if headers == nil {
		headers = map[string][]string{}
	}
	headers["Content-Type"] = []string{"application/json"}
	kong.Response.Exit(status, body, headers)
}

// hasCtrl reports whether s contains a control character (incl. CR/LF). Such a
// byte in a claim that is forwarded as a header value could split or smuggle an
// upstream header, and in a scope string would be swallowed by strings.Fields.
func hasCtrl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// claimToString renders a claim that may be a single string or a JSON array of
// strings — aud is allowed to be either (RFC 7519 §4.1.3) — into one
// space-joined value so it can be forwarded as a single header. Non-string
// array members are skipped; an absent or wrong-typed claim yields "".
func claimToString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	}
	return ""
}

func hasAllScopes(scope string, required []string) bool {
	have := strings.Fields(scope)
	for _, r := range required {
		if !slices.Contains(have, r) {
			return false
		}
	}
	return true
}

func (conf *Config) Access(kong *pdk.PDK) {
	if err := conf.setup(); err != nil {
		_ = kong.Log.Crit(err.Error())
		exitJSON(kong, 500, map[string]string{
			"error":             "server_error",
			"error_description": "plugin misconfigured; see gateway logs",
		}, nil)
		return
	}

	path, err := kong.Request.GetPath()
	if err != nil {
		exitJSON(kong, 500, map[string]string{
			"error":             "server_error",
			"error_description": "cannot read request path",
		}, nil)
		return
	}

	// (3) serve Protected Resource Metadata — matched exactly (plus a
	// trailing-slash variant) so a prefix route can never answer for another
	// resource's metadata path; safe methods only (GET per RFC 9728 §3.1, plus
	// HEAD), everything else -> 405
	if strings.TrimSuffix(path, "/") == conf.prmPath {
		if method, _ := kong.Request.GetMethod(); method != "GET" && method != "HEAD" {
			exitJSON(kong, 405, map[string]string{
				"error":             "method_not_allowed",
				"error_description": "resource metadata is served via GET",
			}, map[string][]string{"Allow": {"GET, HEAD"}})
			return
		}
		prm := map[string]any{
			// RFC 9728 §3.3: must equal the identifier the well-known URL was
			// derived from — never the aud override, which only tunes token
			// validation
			"resource":                 conf.GatewayOrigin + conf.ResourcePath,
			"authorization_servers":    []string{conf.Issuer},
			"bearer_methods_supported": []string{"header"},
		}
		if len(conf.RequiredScopes) > 0 { // optional member: omit rather than null
			prm["scopes_supported"] = conf.RequiredScopes
		}
		exitJSON(kong, 200, prm, nil)
		return
	}

	challenge := func(status int, wwwAuth, errCode, desc string) {
		exitJSON(kong, status,
			map[string]string{"error": errCode, "error_description": desc},
			map[string][]string{"WWW-Authenticate": {wwwAuth}})
	}

	// (2) challenge unless the client presented a Bearer token (RFC 6750 §2.1);
	// other Authorization schemes are rejected, not parsed as a token. No
	// error attribute here: a bare challenge means "no credentials yet" (§3.1).
	// Read every occurrence: the request is forwarded with all of its headers,
	// so validating one Authorization value while proxying others would let a
	// client smuggle an unvalidated credential past the gateway. A PDK error
	// is a gateway fault, not "no credentials" — answer 5xx, not a challenge.
	headers, err := kong.Request.GetHeaders(1000)
	if err != nil {
		exitJSON(kong, 500, map[string]string{
			"error":             "server_error",
			"error_description": "cannot read request headers",
		}, nil)
		return
	}
	var auths []string
	for name, values := range headers {
		if strings.EqualFold(name, "Authorization") {
			auths = append(auths, values...)
		}
	}
	if len(auths) > 1 {
		challenge(400, conf.bearerMeta+`, error="invalid_request"`,
			"invalid_request", "multiple Authorization headers are not allowed")
		return
	}
	var raw string
	if len(auths) == 1 {
		if auth := auths[0]; len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
			raw = strings.TrimSpace(auth[7:])
		}
	}
	if raw == "" {
		challenge(401, conf.bearerMeta, "unauthorized", "missing bearer token")
		return
	}

	// (5) validate RS256 (JWKS) + exp (+ iss and aud unless the matching
	// skip_* toggle is set)
	claims := jwt.MapClaims{}
	if _, err := conf.parser.ParseWithClaims(raw, claims, conf.keyFunc); err != nil {
		if errors.Is(err, errJWKSUnavailable) {
			// infrastructure problem, not a token problem: don't tell the
			// client to re-run OAuth, and keep the details in the logs
			_ = kong.Log.Err("JWKS fetch failed: ", err.Error())
			exitJSON(kong, 503, map[string]string{
				"error":             "temporarily_unavailable",
				"error_description": "token verification keys are unavailable",
			}, nil)
			return
		}
		_ = kong.Log.Info("rejected token: ", err.Error())
		challenge(401, conf.bearerMeta+`, error="invalid_token"`,
			"invalid_token", "invalid or expired access token")
		return
	}

	// When debug_claims is on, dump the full decoded claim set at debug level so
	// an operator can see exactly which claim carries the scopes (or aud, type,
	// etc.) for a given issuer when diagnosing a 401/403. Gated by config rather
	// than log level alone because kong.Log.Debug ships to Kong on every call
	// regardless of log_level — so without this guard the marshal + PDK
	// round-trip would run on every accepted request even at notice level, where
	// the line is discarded. Set debug_claims=true AND log_level=debug to see it.
	if conf.DebugClaims {
		if dbg, err := json.Marshal(claims); err == nil {
			_ = kong.Log.Debug("decoded token claims: ", string(dbg))
		}
	}

	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)
	iss, _ := claims["iss"].(string)
	aud := claimToString(claims["aud"])
	// client_id is the RFC 8693/8707 name; azp is the OIDC equivalent some
	// authorization servers emit instead. Prefer the spec name, fall back to azp.
	clientID, _ := claims["client_id"].(string)
	if clientID == "" {
		clientID, _ = claims["azp"].(string)
	}
	jti, _ := claims["jti"].(string)

	// reject anything that is not an access token: AuthGate signs refresh
	// tokens with the same key, iss, aud, and scope — only the "type" claim and
	// a longer exp differ — so without this check a leaked refresh token would
	// be accepted as a bearer credential, defeating the short access-token TTL.
	// Mirrors AuthGate's own resource-server validation.
	if t, _ := claims["type"].(string); t != "access" && !conf.SkipTypeCheck {
		_ = kong.Log.Info("rejected non-access token; type=", t)
		challenge(401, conf.bearerMeta+`, error="invalid_token"`,
			"invalid_token", "not an access token")
		return
	}

	// exp is a JSON number (NumericDate, seconds since epoch); render it as
	// RFC 3339 UTC so the backend gets a human-readable expiry. Absent or
	// wrong-typed -> "" -> the header is cleared, never set.
	var expStr string
	if exp, ok := claims["exp"].(float64); ok {
		expStr = time.Unix(int64(exp), 0).UTC().Format(time.RFC3339)
	}

	// the identity surfaced to the MCP backend — one source of truth for both
	// the control-char guard and the forwarding loop, so the two can never drift.
	trusted := []struct{ name, value string }{
		{"X-MCP-Subject", sub},
		{"X-MCP-Scope", scope},
		{"X-MCP-Issuer", iss},
		{"X-MCP-Audience", aud},
		{"X-MCP-Client", clientID},
		{"X-MCP-Token-Id", jti},
		{"X-MCP-Expires", expStr},
	}

	// every value here is forwarded as an upstream header (and scope also feeds
	// the check below); a control char (CR/LF) could split a header or smuggle a
	// scope token (strings.Fields would swallow it). A real AuthGate token never
	// carries one, so reject rather than forward. (X-MCP-Expires is rendered from
	// a number, so the guard over it is a harmless no-op.)
	if !conf.SkipControlChars {
		for _, h := range trusted {
			if hasCtrl(h.value) {
				_ = kong.Log.Info("rejected token with control chars in forwarded claims")
				challenge(401, conf.bearerMeta+`, error="invalid_token"`,
					"invalid_token", "malformed token claims")
				return
			}
		}
	}

	if len(conf.RequiredScopes) > 0 && !hasAllScopes(scope, conf.RequiredScopes) {
		challenge(403,
			fmt.Sprintf(`%s, error="insufficient_scope", scope="%s"`, conf.bearerMeta, conf.requiredScopeStr),
			"insufficient_scope", "requires scope: "+conf.requiredScopeStr)
		return
	}

	// surface identity to the MCP backend. SetHeader overrides any inbound copy,
	// so a client can never smuggle its own values through the trusted headers;
	// an absent claim instead clears the inbound copy. Fail closed: if a set/clear
	// is not confirmed, proxying anyway would forward client-supplied values on
	// headers the backend is told to trust.
	for _, h := range trusted {
		var err error
		if h.value != "" {
			err = kong.ServiceRequest.SetHeader(h.name, h.value)
		} else {
			err = kong.ServiceRequest.ClearHeader(h.name)
		}
		if err != nil {
			_ = kong.Log.Err("failed to set trusted header ", h.name, ": ", err.Error())
			exitJSON(kong, 500, map[string]string{
				"error":             "server_error",
				"error_description": "cannot set identity headers",
			}, nil)
			return
		}
	}
	// fall through -> Kong forwards to upstream (Authorization preserved)
}
