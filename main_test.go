package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestMetadataURLs(t *testing.T) {
	tests := []struct {
		issuer string
		want   []string
	}{
		{
			// origin-only issuer: both conventions collapse to the simple form
			issuer: "https://auth.example.com",
			want: []string{
				"https://auth.example.com/.well-known/oauth-authorization-server",
				"https://auth.example.com/.well-known/openid-configuration",
			},
		},
		{
			// issuer with a path: RFC 8414 inserts the well-known segment
			// between host and path, OIDC appends it
			issuer: "https://auth.example.com/tenant1",
			want: []string{
				"https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
				"https://auth.example.com/tenant1/.well-known/openid-configuration",
			},
		},
		{
			issuer: "https://auth.example.com/tenant1/",
			want: []string{
				"https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
				"https://auth.example.com/tenant1/.well-known/openid-configuration",
			},
		},
		{
			// trailing-slash origin: the "/" is a path and is trimmed, so the
			// well-known URLs don't end up with a double slash
			issuer: "https://auth.example.com/",
			want: []string{
				"https://auth.example.com/.well-known/oauth-authorization-server",
				"https://auth.example.com/.well-known/openid-configuration",
			},
		},
	}
	for _, tt := range tests {
		got := metadataURLs(tt.issuer)
		if len(got) != len(tt.want) {
			t.Errorf("metadataURLs(%q) = %v, want %v", tt.issuer, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("metadataURLs(%q)[%d] = %q, want %q", tt.issuer, i, got[i], tt.want[i])
			}
		}
	}
}

// metaServer serves AS metadata on the given paths; issuerOf lets the metadata
// reference the server's own runtime URL.
func metaServer(t *testing.T, hits *atomic.Int64, paths map[string]func(issuer string) map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	for path, doc := range paths {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if hits != nil {
				hits.Add(1)
			}
			_ = json.NewEncoder(w).Encode(doc(srv.URL))
		})
	}
	return srv
}

func TestFetchJWKSURI(t *testing.T) {
	t.Run("RFC 8414 document", func(t *testing.T) {
		srv := metaServer(t, nil, map[string]func(string) map[string]string{
			"/.well-known/oauth-authorization-server": func(iss string) map[string]string {
				return map[string]string{"issuer": iss, "jwks_uri": iss + "/.well-known/jwks.json"}
			},
		})
		got, err := fetchJWKSURI(srv.URL)
		if err != nil {
			t.Fatalf("fetchJWKSURI: %v", err)
		}
		if want := srv.URL + "/.well-known/jwks.json"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("falls back to OIDC discovery", func(t *testing.T) {
		srv := metaServer(t, nil, map[string]func(string) map[string]string{
			"/.well-known/openid-configuration": func(iss string) map[string]string {
				return map[string]string{"issuer": iss, "jwks_uri": iss + "/keys"}
			},
		})
		got, err := fetchJWKSURI(srv.URL)
		if err != nil {
			t.Fatalf("fetchJWKSURI: %v", err)
		}
		if want := srv.URL + "/keys"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("rejects issuer mismatch", func(t *testing.T) {
		srv := metaServer(t, nil, map[string]func(string) map[string]string{
			"/.well-known/oauth-authorization-server": func(string) map[string]string {
				return map[string]string{"issuer": "https://evil.example.com", "jwks_uri": "https://evil.example.com/keys"}
			},
		})
		if _, err := fetchJWKSURI(srv.URL); err == nil {
			t.Error("expected issuer-mismatch error, got nil")
		}
	})

	t.Run("rejects non-absolute jwks_uri", func(t *testing.T) {
		srv := metaServer(t, nil, map[string]func(string) map[string]string{
			"/.well-known/oauth-authorization-server": func(iss string) map[string]string {
				return map[string]string{"issuer": iss, "jwks_uri": "/.well-known/jwks.json"}
			},
		})
		if _, err := fetchJWKSURI(srv.URL); err == nil {
			t.Error("expected invalid-jwks_uri error, got nil")
		}
	})

	t.Run("unreachable issuer", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		srv.Close() // connection refused from here on
		if _, err := fetchJWKSURI(srv.URL); err == nil {
			t.Error("expected fetch error, got nil")
		}
	})
}

func TestDiscoverJWKSURICaches(t *testing.T) {
	var hits atomic.Int64
	srv := metaServer(t, &hits, map[string]func(string) map[string]string{
		"/.well-known/oauth-authorization-server": func(iss string) map[string]string {
			return map[string]string{"issuer": iss, "jwks_uri": iss + "/keys"}
		},
	})
	for range 3 {
		got, err := discoverJWKSURI(srv.URL)
		if err != nil {
			t.Fatalf("discoverJWKSURI: %v", err)
		}
		if want := srv.URL + "/keys"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("metadata endpoint hit %d times, want 1 (cached)", n)
	}
}
