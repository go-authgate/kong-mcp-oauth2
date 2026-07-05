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

// Config is the plugin schema (one instance per MCP resource/service).
type Config struct {
	Issuer         string   `json:"issuer"`          // AuthGate base URL == token iss
	GatewayOrigin  string   `json:"gateway_origin"`  // externally reachable Kong origin
	ResourcePath   string   `json:"resource_path"`   // e.g. /mcp/server
	Audience       string   `json:"audience"`        // expected aud; default GatewayOrigin+ResourcePath
	RequiredScopes []string `json:"required_scopes"` // all must be present
	JWKSURI        string   `json:"jwks_uri"`        // AuthGate JWKS endpoint (RS256); empty => discover via RFC 8414 from Issuer
	LeewaySeconds  int      `json:"leeway_seconds"`  // clock-skew tolerance for exp/nbf

	// Leniency toggles — disable only when the upstream token issuer is known
	// to omit these fields or when temporarily debugging.
	SkipIssuerCheck   bool `json:"skip_issuer_check"`   // accept tokens that lack/mismatch iss
	SkipTypeCheck     bool `json:"skip_type_check"`     // accept tokens whose type != "access"
	SkipControlChars  bool `json:"skip_control_chars"`  // skip CR/LF header-injection guard
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
		if len(invalid) > 0 {
			conf.setupErr = fmt.Errorf("invalid plugin config: %s", strings.Join(invalid, "; "))
			return
		}

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
