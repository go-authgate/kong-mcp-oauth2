package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// metadataTTL bounds how long a discovered jwks_uri is trusted before the
// AS metadata is re-fetched (matches Kong's metadata_cache_ttl of 3600s).
const metadataTTL = time.Hour

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
	initMu := perKeyLock(&metaInitMu, metaInit, issuer)
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
