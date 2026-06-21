package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"golang.org/x/time/rate"
)

// jwksHTTPTimeout caps every JWKS fetch and unknown-kid refetch wait; the
// library default of one minute would let a slow AuthGate stall requests.
const jwksHTTPTimeout = 10 * time.Second

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

// perKeyLock returns key's construction lock, lazily creating it under mapMu on
// first use. Callers Lock/Unlock the result to serialize cold construction for
// that key while leaving other keys (and warm cache reads) unblocked — the
// shared half of getJWKS's and discoverJWKSURI's double-checked locking.
func perKeyLock(mapMu *sync.Mutex, locks map[string]*sync.Mutex, key string) *sync.Mutex {
	mapMu.Lock()
	defer mapMu.Unlock()
	mu := locks[key]
	if mu == nil {
		mu = &sync.Mutex{}
		locks[key] = mu
	}
	return mu
}

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
	initMu := perKeyLock(&jwksInitMu, jwksInit, uri)
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
