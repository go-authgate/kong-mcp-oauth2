// Package main: Kong (go-pdk) plugin — unified MCP OAuth front door (steps 2/3/5)
// in front of any number of MCP servers, backed by AuthGate and verifying tokens
// with RS256 + JWKS.
//
// The MCP authorization handshake (2025-06 spec, building on RFC 9728 / RFC 6750):
//
//	(2) 401 + WWW-Authenticate: Bearer resource_metadata="<PRM URL>"
//	    — tell an unauthenticated client *where the flow lives*, not how to run it.
//	(3) GET /.well-known/oauth-protected-resource/<resource>
//	    — serve Protected Resource Metadata (RFC 9728): which AuthGate to use,
//	      which scopes, how to present the token.
//	(5) verify the RS256 access token against AuthGate's JWKS
//	    (signature + iss + exp + type, plus scope when required_scopes is set and
//	    aud only when require_audience is on), then forward upstream to the MCP server.
//
// Kong never runs the OAuth flow. The MCP client drives Auth Code + PKCE against
// AuthGate itself; Kong only advertises the entry point and validates what comes
// back. One plugin config protects one MCP resource; attach it to as many
// services as you have MCP servers.
//
// Accepted algorithms are pinned to the RS family, so a token signed HS256 with
// the RSA *public* key (the classic alg-confusion forgery) is rejected. JWKS
// fetch / cache / background rotation / rate-limited refetch on an unknown kid
// are handled by MicahParks/keyfunc + jwkset, configured to fail fast: a failed
// initial fetch surfaces as 503 instead of being cached as an empty key set
// (once keys are cached, an unknown kid is a 401 — see Access), and the fetch
// runs under a per-URI lock so a slow AuthGate cannot stall the whole gateway.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

var (
	Version  = "0.4.0"
	Priority = 1000
)

const (
	// wellKnownPrefix is fixed by RFC 9728 — clients derive it themselves, so
	// it is not configurable.
	wellKnownPrefix = "/.well-known/oauth-protected-resource"
	// jwksHTTPTimeout caps every JWKS fetch and unknown-kid refetch wait; the
	// library default of one minute would let a slow AuthGate stall requests.
	jwksHTTPTimeout = 10 * time.Second
	// metadataTTL bounds how long a discovered jwks_uri is trusted before the
	// AS metadata is re-fetched (matches Kong's metadata_cache_ttl of 3600s).
	metadataTTL = time.Hour
)

// rsMethods pins accepted algorithms to the RS family: never accept HS* when
// expecting RS -> no alg confusion.
var rsMethods = []string{"RS256", "RS384", "RS512"}

// Config is the plugin schema (one instance per MCP resource/service).
type Config struct {
	Issuer          string   `json:"issuer"`           // AuthGate base URL == token iss
	GatewayOrigin   string   `json:"gateway_origin"`   // externally reachable Kong origin
	ResourcePath    string   `json:"resource_path"`    // e.g. /mcp/gitea
	Audience        string   `json:"audience"`         // expected aud; default GatewayOrigin+ResourcePath
	RequiredScopes  []string `json:"required_scopes"`  // all must be present
	JWKSURI         string   `json:"jwks_uri"`         // AuthGate JWKS endpoint (RS256); empty => discover via RFC 8414 from Issuer
	RequireAudience bool     `json:"require_audience"` // false until AuthGate emits per-resource aud
	LeewaySeconds   int      `json:"leeway_seconds"`   // clock-skew tolerance for exp/nbf

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
		// (e.g. resource_path "mcp/gitea" -> ".../oauth-protected-resourcemcp/gitea"),
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
			jwt.WithIssuer(conf.Issuer),
			jwt.WithExpirationRequired(),
		}
		if conf.LeewaySeconds > 0 {
			opts = append(opts, jwt.WithLeeway(time.Duration(conf.LeewaySeconds)*time.Second))
		}
		if conf.RequireAudience {
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

// JWKS cache: the plugin server is long-lived, so one self-refreshing keyfunc
// per JWKS URI is shared across the whole process. Construction performs a
// synchronous initial HTTP fetch (up to jwksHTTPTimeout); it runs under a
// per-URI lock, never a process-global one, so a slow or unreachable AuthGate
// stalls only the first cold caller for that URI — not warm requests, and not
// requests for a different URI.
var (
	jwksMu     sync.RWMutex                   // guards jwksCache reads/writes
	jwksCache  = map[string]keyfunc.Keyfunc{} // built keyfuncs, keyed by URI
	jwksInitMu sync.Mutex                     // guards jwksInit
	jwksInit   = map[string]*sync.Mutex{}     // per-URI construction lock
)

// errJWKSUnavailable marks verification-infrastructure failures (as opposed to
// defects in the presented token) so Access can answer 503 instead of 401.
var errJWKSUnavailable = errors.New("JWKS unavailable")

// getJWKS builds (once per URI) a keyfunc with hourly background refresh and
// rate-limited refetch on an unknown kid. Unlike keyfunc.NewDefault, a failed
// first fetch is returned as an error — not cached as an empty key set that
// would 401 every token until the next refresh window — so the next request
// simply retries.
//
// Entries are never evicted. With discovery this means an issuer that MOVES
// its advertised jwks_uri strands the old URI's keyfunc here: one goroutine
// plus one HTTP fetch (and, once the old URL dies, one error log) per hour,
// per orphan, until restart. Cancelling the old context on change would break
// in-flight verifications still holding that keyfunc, so the leak is accepted
// — it is bounded by how often an AS relocates its JWKS, which is rare.
func getJWKS(uri string) (keyfunc.Keyfunc, error) {
	jwksMu.RLock()
	k, ok := jwksCache[uri]
	jwksMu.RUnlock()
	if ok {
		return k, nil
	}

	// cold path: serialize construction per URI so concurrent first callers
	// build exactly one keyfunc — but hold only this URI's lock (not jwksMu)
	// across the blocking fetch below, so other URIs and warm reads never wait.
	jwksInitMu.Lock()
	initMu, ok := jwksInit[uri]
	if !ok {
		initMu = &sync.Mutex{}
		jwksInit[uri] = initMu
	}
	jwksInitMu.Unlock()

	initMu.Lock()
	defer initMu.Unlock()

	// another caller may have built it while we waited for initMu
	jwksMu.RLock()
	k, ok = jwksCache[uri]
	jwksMu.RUnlock()
	if ok {
		return k, nil
	}

	// the context lives as long as the cached keyfunc; cancel only on
	// construction failure so the refresh goroutine doesn't leak per retry
	ctx, cancel := context.WithCancel(context.Background())
	cached := false
	defer func() {
		if !cached {
			cancel()
		}
	}()
	store, err := jwkset.NewStorageFromHTTP(uri, jwkset.HTTPClientStorageOptions{
		Ctx:             ctx,
		HTTPTimeout:     jwksHTTPTimeout,
		RefreshInterval: time.Hour,
		RefreshErrorHandler: func(ctx context.Context, err error) {
			slog.Error("failed to refresh JWK Set", "url", uri, "error", err)
		},
	})
	if err != nil {
		return nil, err
	}
	client, err := jwkset.NewHTTPClient(jwkset.HTTPClientOptions{
		HTTPURLs:          map[string]jwkset.Storage{uri: store},
		RateLimitWaitMax:  jwksHTTPTimeout,
		RefreshUnknownKID: rate.NewLimiter(rate.Every(5*time.Minute), 1),
	})
	if err != nil {
		return nil, err
	}
	k, err = keyfunc.New(keyfunc.Options{Ctx: ctx, Storage: client})
	if err != nil {
		return nil, err
	}
	jwksMu.Lock()
	jwksCache[uri] = k
	jwksMu.Unlock()
	cached = true
	return k, nil
}

// AS metadata discovery (RFC 8414): when jwks_uri is not configured, it is
// looked up from the issuer's authorization-server metadata instead — the same
// document MCP clients read in step ③→④. Mirrors the JWKS cache: per-issuer
// construction lock, failures never cached, and a discovery failure is an
// infrastructure 503, not a token 401. One caveat the explicit jwks_uri config
// exists for: discovery fetches FROM THE GATEWAY, so the issuer (and the
// jwks_uri its metadata advertises) must be reachable from inside Kong — in
// the docker-compose demos that means host.docker.internal, which is why those
// configs keep setting jwks_uri by hand.
var (
	metaMu     sync.RWMutex               // guards metaCache reads/writes
	metaCache  = map[string]metaEntry{}   // discovered jwks_uri, keyed by issuer
	metaInitMu sync.Mutex                 // guards metaInit
	metaInit   = map[string]*sync.Mutex{} // per-issuer discovery lock

	metadataHTTPClient = &http.Client{Timeout: jwksHTTPTimeout}
)

type metaEntry struct {
	jwksURI string
	expires time.Time
}

// metadataURLs returns the discovery documents to try for issuer, in order:
// RFC 8414 (well-known inserted between host and path) first, then OIDC
// discovery (well-known appended) — AuthGate serves both, other ASes at least
// one.
func metadataURLs(issuer string) []string {
	u, err := url.Parse(issuer)
	if err != nil { // setup() already validated; defensive
		return []string{strings.TrimSuffix(issuer, "/") + "/.well-known/oauth-authorization-server"}
	}
	origin := u.Scheme + "://" + u.Host
	path := strings.TrimSuffix(u.Path, "/")
	return []string{
		origin + "/.well-known/oauth-authorization-server" + path,
		origin + path + "/.well-known/openid-configuration",
	}
}

// fetchJWKSURI fetches the issuer's AS metadata and returns its jwks_uri.
// The document's issuer must equal the configured one (RFC 8414 §3.3) — a
// mismatched document could otherwise point verification at attacker keys —
// and the advertised jwks_uri must be an absolute http(s) URL, the same shape
// rule setup() applies to a hand-configured one.
func fetchJWKSURI(issuer string) (string, error) {
	// every attempt's error is kept and joined: the RFC 8414 attempt usually
	// carries the diagnostic one (e.g. an issuer mismatch), and a trailing
	// OIDC-fallback 404 must not mask it
	var errs []error
	for _, mdURL := range metadataURLs(issuer) {
		resp, err := metadataHTTPClient.Get(mdURL)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// read one byte past the cap so an oversized document fails loudly
		// instead of being truncated into a confusing JSON parse error
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
		_ = resp.Body.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", mdURL, err))
			continue
		}
		if len(body) > 1<<20 {
			errs = append(errs, fmt.Errorf("%s: metadata document exceeds 1 MiB", mdURL))
			continue
		}
		if resp.StatusCode != http.StatusOK {
			errs = append(errs, fmt.Errorf("%s: HTTP %d", mdURL, resp.StatusCode))
			continue
		}
		var meta struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := json.Unmarshal(body, &meta); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", mdURL, err))
			continue
		}
		if meta.Issuer != issuer {
			errs = append(errs, fmt.Errorf("%s: metadata issuer %q does not match configured issuer %q", mdURL, meta.Issuer, issuer))
			continue
		}
		if !isAbsHTTPURL(meta.JWKSURI) {
			errs = append(errs, fmt.Errorf("%s: metadata jwks_uri %q is not an absolute http(s) URL", mdURL, meta.JWKSURI))
			continue
		}
		return meta.JWKSURI, nil
	}
	return "", errors.Join(errs...)
}

// discoverJWKSURI returns the issuer's jwks_uri, re-fetching the AS metadata
// at most once per metadataTTL. A failed refresh keeps serving the previously
// discovered value (traffic should not break because a metadata fetch blipped
// — key freshness is keyfunc's job, not this lookup's); only a cold cache with
// no fallback surfaces the error, which Access answers with 503.
func discoverJWKSURI(issuer string) (string, error) {
	metaMu.RLock()
	e, ok := metaCache[issuer]
	metaMu.RUnlock()
	if ok && time.Now().Before(e.expires) {
		return e.jwksURI, nil
	}

	// serialize discovery per issuer; same pattern as getJWKS
	metaInitMu.Lock()
	initMu, found := metaInit[issuer]
	if !found {
		initMu = &sync.Mutex{}
		metaInit[issuer] = initMu
	}
	metaInitMu.Unlock()

	initMu.Lock()
	defer initMu.Unlock()

	// another caller may have refreshed it while we waited for initMu
	metaMu.RLock()
	e, ok = metaCache[issuer]
	metaMu.RUnlock()
	if ok && time.Now().Before(e.expires) {
		return e.jwksURI, nil
	}

	uri, err := fetchJWKSURI(issuer)
	if err != nil {
		if ok { // stale entry: extend it rather than failing live traffic
			slog.Error("AS metadata refresh failed; keeping cached jwks_uri", "issuer", issuer, "error", err)
			uri = e.jwksURI
		} else {
			return "", err
		}
	}
	metaMu.Lock()
	metaCache[issuer] = metaEntry{jwksURI: uri, expires: time.Now().Add(metadataTTL)}
	metaMu.Unlock()
	return uri, nil
}

// resolveJWKSURI returns the JWKS endpoint to verify against: the configured
// jwks_uri, or — when it is left empty — the one discovered from the issuer's
// AS metadata. A discovery failure is an infrastructure error (503), same as
// a failed JWKS fetch.
func (conf *Config) resolveJWKSURI() (string, error) {
	if conf.JWKSURI != "" {
		return conf.JWKSURI, nil
	}
	uri, err := discoverJWKSURI(conf.Issuer)
	if err != nil {
		return "", fmt.Errorf("AS metadata discovery: %w", err)
	}
	return uri, nil
}

func (conf *Config) keyFunc(token *jwt.Token) (any, error) {
	uri, err := conf.resolveJWKSURI()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errJWKSUnavailable, err)
	}
	kf, err := getJWKS(uri)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errJWKSUnavailable, err)
	}
	return kf.Keyfunc(token)
}

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
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
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

	// (5) validate RS256 (JWKS) + iss + aud + exp
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

	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)

	// reject anything that is not an access token: AuthGate signs refresh
	// tokens with the same key, iss, aud, and scope — only the "type" claim and
	// a longer exp differ — so without this check a leaked refresh token would
	// be accepted as a bearer credential, defeating the short access-token TTL.
	// Mirrors AuthGate's own resource-server validation.
	if t, _ := claims["type"].(string); t != "access" {
		_ = kong.Log.Info("rejected non-access token; type=", t)
		challenge(401, conf.bearerMeta+`, error="invalid_token"`,
			"invalid_token", "not an access token")
		return
	}

	// sub/scope are forwarded as upstream headers and scope feeds the check
	// below; a control char (CR/LF) could split a header or smuggle a scope
	// token (strings.Fields would swallow it). A real AuthGate token never
	// carries one, so reject rather than forward.
	if hasCtrl(sub) || hasCtrl(scope) {
		_ = kong.Log.Info("rejected token with control chars in sub/scope")
		challenge(401, conf.bearerMeta+`, error="invalid_token"`,
			"invalid_token", "malformed token claims")
		return
	}

	if len(conf.RequiredScopes) > 0 && !hasAllScopes(scope, conf.RequiredScopes) {
		challenge(403,
			fmt.Sprintf(`%s, error="insufficient_scope", scope="%s"`, conf.bearerMeta, conf.requiredScopeStr),
			"insufficient_scope", "requires scope: "+conf.requiredScopeStr)
		return
	}

	// surface identity to the MCP backend — clear inbound copies first so a
	// client can never smuggle its own values through the trusted headers.
	// Fail closed: if a clear/set is not confirmed, proxying anyway would
	// forward client-supplied values on headers the backend is told to trust.
	for _, h := range []struct{ name, value string }{
		{"X-MCP-Subject", sub},
		{"X-MCP-Scope", scope},
	} {
		err := kong.ServiceRequest.ClearHeader(h.name)
		if err == nil && h.value != "" {
			err = kong.ServiceRequest.SetHeader(h.name, h.value)
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

// main exits non-zero on a failed start: server.StartServer returns socket
// errors without logging, and a silent exit 0 reads as a healthy pluginserver.
func main() {
	if err := server.StartServer(New, Version, Priority); err != nil {
		slog.Error("plugin server exited", "error", err)
		os.Exit(1)
	}
}
