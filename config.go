package main

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// wellKnownPrefix is fixed by RFC 9728 — clients derive it themselves, so
	// it is not configurable.
	wellKnownPrefix = "/.well-known/oauth-protected-resource"
)

// rsMethods pins accepted algorithms to the RS family: never accept HS* when
// expecting RS -> no alg confusion.
var rsMethods = []string{"RS256", "RS384", "RS512"}

// upstream_auth_mode values: what the MCP backend receives in place of the
// client's bearer token after validation. The default is strip — the backend's
// identity source is the X-MCP-* headers, so forwarding a live, replayable
// user credential is unnecessary exposure; passthrough is the explicit opt-out
// that restores the pre-0.6 behavior.
const (
	upstreamModePassthrough = "passthrough"
	upstreamModeStrip       = "strip"
	upstreamModeStatic      = "static"
)

// headerKV is one upstream header to set — shared by the trusted X-MCP-*
// forwarding loop and the parsed upstream_extra_headers, so both go through
// the same set-and-fail-closed path in Access.
type headerKV struct{ name, value string }

// Config is the plugin schema (one instance per MCP resource/service).
type Config struct {
	Issuer         string   `json:"issuer"`          // Signet base URL == token iss
	GatewayOrigin  string   `json:"gateway_origin"`  // externally reachable Kong origin
	ResourcePath   string   `json:"resource_path"`   // e.g. /mcp/server
	Audience       string   `json:"audience"`        // expected aud; default GatewayOrigin+ResourcePath
	RequiredScopes []string `json:"required_scopes"` // all must be present
	JWKSURI        string   `json:"jwks_uri"`        // Signet JWKS endpoint (RS256); empty => discover via RFC 8414 from Issuer
	LeewaySeconds  int      `json:"leeway_seconds"`  // clock-skew tolerance for exp/nbf

	// Upstream auth — what the backend receives in place of the client's
	// bearer token. Modes: "strip" (default) removes Authorization, "static"
	// replaces it with a configured upstream credential, "passthrough" keeps
	// the client token (pre-0.6 behavior; the backend then holds a live,
	// replayable user credential).
	UpstreamAuthMode     string   `json:"upstream_auth_mode"`     // passthrough | strip | static; empty => strip
	UpstreamAuthToken    string   `json:"upstream_auth_token"`    // static: the upstream credential; required in that mode
	UpstreamAuthHeader   string   `json:"upstream_auth_header"`   // static: header carrying it; empty => Authorization (adds "Bearer " prefix)
	UpstreamExtraHeaders []string `json:"upstream_extra_headers"` // "Name: value" pairs set in every mode (tenancy/source tags)

	// Leniency toggles — disable only when the upstream token issuer is known
	// to omit these fields or when temporarily debugging.
	SkipIssuerCheck   bool `json:"skip_issuer_check"`   // accept tokens that lack/mismatch iss
	SkipTypeCheck     bool `json:"skip_type_check"`     // accept tokens whose type != "access"
	SkipControlChars  bool `json:"skip_control_chars"`  // skip CR/LF header-injection guard on token claims (never on config values)
	SkipAudienceCheck bool `json:"skip_audience_check"` // accept tokens that lack/mismatch aud (allows cross-resource replay)

	// DebugClaims dumps the full decoded claim set to Kong's debug log for each
	// request it decodes — an operator aid for seeing which claim carries the
	// scopes/aud/type behind an unexpected 401/403. OFF by default and gated by
	// config, NOT by log level alone: kong.Log.Debug ships to Kong on every call
	// regardless of log_level (go-pdk exposes no level check), so an ungated dump
	// would add a JSON marshal + a per-request PDK round-trip to every accepted
	// request for nothing. Claims can contain PII, so enable deliberately and
	// briefly, together with log_level=debug to actually see the output.
	DebugClaims bool `json:"debug_claims"`

	// derived once per instance — Access runs per request, config never changes
	setupOnce        sync.Once
	setupErr         error
	parser           *jwt.Parser
	prmPath          string // wellKnownPrefix + ResourcePath
	bearerMeta       string // WWW-Authenticate challenge pointing at this resource's PRM
	requiredScopeStr string // RequiredScopes joined with spaces (for the 403 challenge)

	upstreamMode   string     // UpstreamAuthMode with the strip default applied
	upstreamHeader string     // static only: resolved header carrying the upstream credential
	upstreamValue  string     // static only: credential value, "Bearer "-prefixed on Authorization
	extraHeaders   []headerKV // UpstreamExtraHeaders parsed and validated
	modeLogOnce    sync.Once  // one "upstream auth mode" info line, not one per request
}

func New() any { return &Config{} }

// setup validates required fields and derives per-instance values. go-pdk's
// generated schema cannot mark fields required, so this is the only layer that
// can reject a half-filled config — better one loud 500 than e.g. silently
// skipping issuer validation (golang-jwt ignores WithIssuer("")).
func (conf *Config) setup() error {
	conf.setupOnce.Do(func() {
		var missing []string
		for _, f := range []struct{ name, value string }{
			{"issuer", conf.Issuer},
			{"gateway_origin", conf.GatewayOrigin},
			{"resource_path", conf.ResourcePath},
		} {
			if f.value == "" {
				missing = append(missing, f.name)
			}
		}
		if len(missing) > 0 {
			conf.setupErr = fmt.Errorf("missing required plugin config: %s", strings.Join(missing, ", "))
			return
		}

		// shape checks: a non-empty but malformed path/origin would otherwise
		// concatenate into a silently-broken PRM URL that no Kong route matches
		// (e.g. resource_path "mcp/server" -> ".../oauth-protected-resourcemcp/server"),
		// failing every request with no diagnostic. Fail loudly instead.
		var invalid []string
		if !strings.HasPrefix(conf.ResourcePath, "/") {
			invalid = append(invalid, `resource_path must start with "/"`)
		}
		// a trailing slash makes prmPath end in "/", which the exact match in
		// Access (TrimSuffix(path,"/") == prmPath) can never satisfy, so the
		// metadata route would silently never serve.
		if strings.HasSuffix(conf.ResourcePath, "/") {
			invalid = append(invalid, `resource_path must not end with "/"`)
		}
		if strings.HasSuffix(conf.GatewayOrigin, "/") {
			invalid = append(invalid, `gateway_origin must not end with "/"`)
		}
		// issuer/gateway_origin/jwks_uri are concatenated into URLs (PRM URL,
		// audience) and fetched (JWKS, AS metadata); a relative or schemeless
		// value would otherwise surface only at traffic time as an opaque
		// per-request 503 (jwks_uri) or a silent universal 401 (issuer).
		for _, u := range []struct{ name, value string }{
			{"issuer", conf.Issuer},
			{"gateway_origin", conf.GatewayOrigin},
			{"jwks_uri", conf.JWKSURI}, // optional: empty means RFC 8414 discovery
		} {
			// only jwks_uri can be empty here — missing required fields
			// already returned above
			if u.value != "" && !isAbsHTTPURL(u.value) {
				invalid = append(invalid, u.name+` must be an absolute http(s) URL`)
			}
		}
		// RFC 8414 §2 forbids query/fragment in an issuer identifier, and
		// discovery builds the well-known URLs from scheme://host+path only —
		// a query would be dropped silently and the metadata issuer check
		// could then never match. Reject loudly instead. (A trailing slash is
		// NOT rejected: some ASes — e.g. Auth0 — legitimately use one, and it
		// works as long as the token's iss and the metadata issuer carry it too.)
		if parsed, err := url.Parse(conf.Issuer); err == nil && (parsed.RawQuery != "" || parsed.Fragment != "") {
			invalid = append(invalid, "issuer must not contain a query or fragment (RFC 8414)")
		}
		if conf.LeewaySeconds < 0 {
			invalid = append(invalid, "leeway_seconds must not be negative")
		}

		// Upstream auth: everything here is validated unconditionally —
		// skip_control_chars only relaxes the per-request guard on token
		// claims, never on config values, where a CR/LF is always a typo or an
		// injection attempt. A bad combination must fail loudly (500 on every
		// request), never silently degrade to a less safe mode.
		mode := conf.UpstreamAuthMode
		if mode == "" {
			mode = upstreamModeStrip
		}
		switch mode {
		case upstreamModePassthrough, upstreamModeStrip, upstreamModeStatic:
		default:
			invalid = append(invalid, `upstream_auth_mode must be "passthrough", "strip", or "static"`)
		}
		if mode == upstreamModeStatic && conf.UpstreamAuthToken == "" {
			invalid = append(invalid, `upstream_auth_token is required when upstream_auth_mode is "static"`)
		}
		if hasCtrl(conf.UpstreamAuthToken) {
			invalid = append(invalid, "upstream_auth_token must not contain control characters")
		}
		if conf.UpstreamAuthHeader != "" && !isHeaderName(conf.UpstreamAuthHeader) {
			invalid = append(invalid, "upstream_auth_header must be a valid HTTP header name")
		}
		credHeader := conf.UpstreamAuthHeader
		if credHeader == "" {
			credHeader = "Authorization"
		}
		// static-only fields set in another mode are silently ignored at
		// request time (upstreamValue is only populated for static), which is
		// exactly the "degrade to a less safe mode" this block forbids: under
		// passthrough the operator believes a static credential replaced the
		// live client token when it is in fact still forwarded. Fail loudly.
		if mode != upstreamModeStatic && (conf.UpstreamAuthToken != "" || conf.UpstreamAuthHeader != "") {
			invalid = append(invalid, `upstream_auth_token and upstream_auth_header require upstream_auth_mode: "static"`)
		}
		// the static credential is applied AFTER the trusted X-MCP-* loop, so
		// aiming it at that namespace would overwrite verified identity with a
		// fixed value (and leak the secret onto a header the backend logs as
		// identity). Same reservation the extra headers get below.
		if isMCPHeaderName(credHeader) {
			invalid = append(invalid, "upstream_auth_header must not be in the X-MCP-* namespace")
		}
		var extras []headerKV
		for _, kv := range conf.UpstreamExtraHeaders {
			// split at the FIRST colon only, so values containing colons
			// (URLs) stay intact
			name, value, found := strings.Cut(kv, ":")
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			if !found || !isHeaderName(name) {
				// echo only the name, never the raw entry: a malformed value
				// may be a secret, and setupErr is logged at Crit on every
				// request (Access), so echoing the value would leak it per-request.
				invalid = append(invalid, fmt.Sprintf("upstream_extra_headers entry for %q must be \"Name: value\" with a valid header name", name))
				continue
			}
			// reserved names: Authorization belongs to upstream_auth_mode,
			// X-MCP-* carries verified token identity, hop-by-hop/framing and
			// routing names would corrupt the proxied request (Host also
			// rewrites the upstream SNI), and the static credential header must
			// not be silently overridden — an extra header on any of these would
			// fight the trusted values or the transport with order-of-application
			// deciding the winner
			if strings.EqualFold(name, "Authorization") ||
				isMCPHeaderName(name) ||
				isForbiddenUpstreamHeader(name) ||
				(mode == upstreamModeStatic && strings.EqualFold(name, credHeader)) {
				invalid = append(invalid, fmt.Sprintf("upstream_extra_headers must not set reserved header %q", name))
				continue
			}
			if hasCtrl(value) {
				invalid = append(invalid, fmt.Sprintf("upstream_extra_headers value for %q must not contain control characters", name))
				continue
			}
			extras = append(extras, headerKV{name: name, value: value})
		}

		if len(invalid) > 0 {
			conf.setupErr = fmt.Errorf("invalid plugin config: %s", strings.Join(invalid, "; "))
			return
		}

		conf.upstreamMode = mode
		if mode == upstreamModeStatic {
			conf.upstreamHeader = credHeader
			conf.upstreamValue = conf.UpstreamAuthToken
			if strings.EqualFold(credHeader, "Authorization") {
				conf.upstreamValue = "Bearer " + conf.UpstreamAuthToken
			}
		}
		conf.extraHeaders = extras

		conf.prmPath = wellKnownPrefix + conf.ResourcePath
		conf.bearerMeta = fmt.Sprintf(`Bearer resource_metadata="%s"`, conf.GatewayOrigin+conf.prmPath)
		conf.requiredScopeStr = strings.Join(conf.RequiredScopes, " ")

		opts := []jwt.ParserOption{
			jwt.WithValidMethods(rsMethods),
			jwt.WithExpirationRequired(),
		}
		if !conf.SkipIssuerCheck {
			opts = append(opts, jwt.WithIssuer(conf.Issuer))
		}
		if conf.LeewaySeconds > 0 {
			opts = append(opts, jwt.WithLeeway(time.Duration(conf.LeewaySeconds)*time.Second))
		}
		// aud is enforced by default (RFC 8707 / MCP spec: the resource server
		// MUST verify the token was issued for it). A token whose aud is missing
		// or does not contain the expected value fails validation — golang-jwt
		// treats an absent aud as ErrTokenRequiredClaimMissing once an expected
		// audience is set (pinned by TestAudienceValidation).
		if !conf.SkipAudienceCheck {
			opts = append(opts, jwt.WithAudience(conf.audience()))
		}
		conf.parser = jwt.NewParser(opts...) // goroutine-safe, reused across requests
	})
	return conf.setupErr
}

func (conf *Config) audience() string {
	if conf.Audience != "" {
		return conf.Audience
	}
	return conf.GatewayOrigin + conf.ResourcePath
}

// isAbsHTTPURL reports whether s parses as an absolute http(s) URL — the one
// shape rule shared by setup()'s config checks and the discovered jwks_uri.
func isAbsHTTPURL(s string) bool {
	parsed, err := url.Parse(s)
	return err == nil && parsed.IsAbs() && (parsed.Scheme == "http" || parsed.Scheme == "https")
}

// isMCPHeaderName reports whether name is in the trusted X-MCP-* namespace, in
// either the hyphen or underscore form. Some proxies deliver X_MCP_Subject
// (underscores_in_headers), which a CGI-style backend folds onto the same key
// as X-MCP-Subject — so the underscore form must be treated as part of the
// namespace too. Shared by the request-time sweep (unknownMCPHeaders) and the
// config reserved-name checks so the boundary lives in exactly one place.
func isMCPHeaderName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "x-mcp-") || strings.HasPrefix(lower, "x_mcp_")
}

// isForbiddenUpstreamHeader reports whether name controls transport framing or
// routing rather than carrying data: set on a proxied request these corrupt it
// (go-pdk's SetHeader on "host" also rewrites the upstream SNI;
// Content-Length/Transfer-Encoding desynchronize body framing). They are never
// valid tenancy tags, so upstream_extra_headers rejects them.
func isForbiddenUpstreamHeader(name string) bool {
	switch strings.ToLower(name) {
	case "host", "content-length", "transfer-encoding", "connection":
		return true
	}
	return false
}

// isHeaderName reports whether s is a valid HTTP field name (RFC 9110 token:
// one or more tchars). Stricter than "no control chars": a space or colon in
// a header name would already have been mangled by any proxy hop.
func isHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}
