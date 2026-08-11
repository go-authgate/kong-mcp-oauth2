package main

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testKey is generated once, lazily: RSA keygen is the expensive part of these
// tests and the key's identity is irrelevant — only that signer and keyfunc
// agree. OnceValue keeps unrelated test runs (go test -run TestMetadataURLs)
// from paying the keygen at package init.
var testKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

// signToken issues an RS256 token with the given claims, filling in the
// iss/exp every parser configuration in these tests requires.
func signToken(t *testing.T, issuer string, extra jwt.MapClaims) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": issuer,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	maps.Copy(claims, extra)
	raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(testKey())
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return raw
}

// TestUpstreamAuthConfig pins setup()'s upstream_auth_* handling: the strip
// default, enum enforcement, the static-mode required token, header-name and
// control-char hygiene (unconditional — skip_control_chars must NOT relax
// config validation), and the first-colon-only split of extra headers. Every
// invalid combination must fail setup loudly; nothing may silently degrade to
// a less safe mode.
func TestUpstreamAuthConfig(t *testing.T) {
	base := func(mutate func(*Config)) *Config {
		conf := &Config{
			Issuer:        "https://auth.example.com",
			GatewayOrigin: "https://gw.example.com",
			ResourcePath:  "/mcp/server",
		}
		if mutate != nil {
			mutate(conf)
		}
		return conf
	}

	t.Run("default mode is strip", func(t *testing.T) {
		conf := base(nil)
		if err := conf.setup(); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if conf.upstreamMode != upstreamModeStrip {
			t.Errorf("upstreamMode = %q, want %q", conf.upstreamMode, upstreamModeStrip)
		}
	})

	t.Run("passthrough accepted as explicit opt-out", func(t *testing.T) {
		conf := base(func(c *Config) { c.UpstreamAuthMode = "passthrough" })
		if err := conf.setup(); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if conf.upstreamMode != upstreamModePassthrough {
			t.Errorf("upstreamMode = %q, want %q", conf.upstreamMode, upstreamModePassthrough)
		}
	})

	t.Run("static on default header gets Bearer prefix", func(t *testing.T) {
		conf := base(func(c *Config) {
			c.UpstreamAuthMode = "static"
			c.UpstreamAuthToken = "s3cret"
		})
		if err := conf.setup(); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if conf.upstreamHeader != "Authorization" || conf.upstreamValue != "Bearer s3cret" {
			t.Errorf("credential = %q: %q, want Authorization: Bearer s3cret", conf.upstreamHeader, conf.upstreamValue)
		}
	})

	t.Run("static on custom header omits Bearer prefix", func(t *testing.T) {
		conf := base(func(c *Config) {
			c.UpstreamAuthMode = "static"
			c.UpstreamAuthToken = "s3cret"
			c.UpstreamAuthHeader = "X-Api-Key"
		})
		if err := conf.setup(); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if conf.upstreamHeader != "X-Api-Key" || conf.upstreamValue != "s3cret" {
			t.Errorf("credential = %q: %q, want X-Api-Key: s3cret", conf.upstreamHeader, conf.upstreamValue)
		}
	})

	t.Run("extra headers split at first colon only", func(t *testing.T) {
		conf := base(func(c *Config) {
			c.UpstreamExtraHeaders = []string{"X-Tenant: acme", "X-Callback:https://cb.example.com/hook"}
		})
		if err := conf.setup(); err != nil {
			t.Fatalf("setup: %v", err)
		}
		want := []headerKV{
			{name: "X-Tenant", value: "acme"},
			{name: "X-Callback", value: "https://cb.example.com/hook"},
		}
		if len(conf.extraHeaders) != len(want) {
			t.Fatalf("extraHeaders = %v, want %v", conf.extraHeaders, want)
		}
		for i := range want {
			if conf.extraHeaders[i] != want[i] {
				t.Errorf("extraHeaders[%d] = %v, want %v", i, conf.extraHeaders[i], want[i])
			}
		}
	})

	rejected := []struct {
		name    string
		mutate  func(*Config)
		wantSub string // substring the setup error must carry
	}{
		{
			name:    "unknown mode",
			mutate:  func(c *Config) { c.UpstreamAuthMode = "exchange" },
			wantSub: "upstream_auth_mode",
		},
		{
			name:    "static without token",
			mutate:  func(c *Config) { c.UpstreamAuthMode = "static" },
			wantSub: "upstream_auth_token is required",
		},
		{
			name: "control chars in token rejected even with skip_control_chars",
			mutate: func(c *Config) {
				c.UpstreamAuthMode = "static"
				c.UpstreamAuthToken = "s3c\r\nret"
				c.SkipControlChars = true // gates token claims only, never config
			},
			wantSub: "upstream_auth_token must not contain control characters",
		},
		{
			name: "invalid credential header name",
			mutate: func(c *Config) {
				c.UpstreamAuthMode = "static"
				c.UpstreamAuthToken = "s3cret"
				c.UpstreamAuthHeader = "X Api Key"
			},
			wantSub: "upstream_auth_header",
		},
		{
			name:    "extra header without colon",
			mutate:  func(c *Config) { c.UpstreamExtraHeaders = []string{"X-Tenant"} },
			wantSub: "upstream_extra_headers",
		},
		{
			name:    "extra header must not set Authorization",
			mutate:  func(c *Config) { c.UpstreamExtraHeaders = []string{"Authorization: Bearer x"} },
			wantSub: "reserved",
		},
		{
			name:    "extra header must not set X-MCP-*",
			mutate:  func(c *Config) { c.UpstreamExtraHeaders = []string{"X-MCP-Subject: admin"} },
			wantSub: "reserved",
		},
		{
			name: "extra header must not shadow the static credential header",
			mutate: func(c *Config) {
				c.UpstreamAuthMode = "static"
				c.UpstreamAuthToken = "s3cret"
				c.UpstreamAuthHeader = "X-Api-Key"
				c.UpstreamExtraHeaders = []string{"x-api-key: other"}
			},
			wantSub: "reserved",
		},
		{
			name:    "control chars in extra header value",
			mutate:  func(c *Config) { c.UpstreamExtraHeaders = []string{"X-Tenant: ac\rme"} },
			wantSub: "control characters",
		},
		{
			// credential fields set without static mode are silently ignored
			// at request time (a live token would leak under passthrough), so
			// setup must reject the combination rather than degrade.
			name: "credential fields require static mode",
			mutate: func(c *Config) {
				c.UpstreamAuthMode = "passthrough"
				c.UpstreamAuthToken = "s3cret"
			},
			wantSub: `require upstream_auth_mode: "static"`,
		},
		{
			// the static credential is applied after the trusted loop, so
			// aiming it at an X-MCP-* header would overwrite verified identity.
			name: "credential header must not be in X-MCP-* namespace",
			mutate: func(c *Config) {
				c.UpstreamAuthMode = "static"
				c.UpstreamAuthToken = "s3cret"
				c.UpstreamAuthHeader = "X-MCP-Subject"
			},
			wantSub: "X-MCP-*",
		},
		{
			name:    "extra header must not set a framing/routing header",
			mutate:  func(c *Config) { c.UpstreamExtraHeaders = []string{"Host: internal.example.com"} },
			wantSub: "reserved",
		},
		{
			// underscore form folds onto the same key as X-MCP-Subject on
			// CGI-style backends, so it is part of the reserved namespace.
			name:    "extra header must not set X_MCP_ underscore variant",
			mutate:  func(c *Config) { c.UpstreamExtraHeaders = []string{"X_MCP_Subject: admin"} },
			wantSub: "reserved",
		},
	}
	for _, tt := range rejected {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			err := base(tt.mutate).setup()
			if err == nil {
				t.Fatal("expected setup to fail, got nil error")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not mention %q", err, tt.wantSub)
			}
		})
	}
}

// TestAudienceValidation exercises setup()'s parser at the level a request
// would hit it: aud binding is enforced by default (RFC 8707), relaxable only
// via skip_audience_check, with the audience override taking precedence over
// the derived gateway_origin+resource_path value.
func TestAudienceValidation(t *testing.T) {
	const (
		issuer   = "https://auth.example.com"
		origin   = "https://gw.example.com"
		path     = "/mcp/server"
		expected = origin + path // derived audience
	)
	staticKeyFunc := func(*jwt.Token) (any, error) { return &testKey().PublicKey, nil }

	tests := []struct {
		name    string
		conf    *Config // pointer: Config holds sync.Once fields and must not be copied
		aud     any     // value of the aud claim; nil = omit the claim
		wantOK  bool
		wantErr error // sentinel the failure must carry, so a case can't fail for an unrelated reason (iss/exp/alg)
	}{
		{
			name:   "happy path: aud as string",
			conf:   &Config{Issuer: issuer, GatewayOrigin: origin, ResourcePath: path},
			aud:    expected,
			wantOK: true,
		},
		{
			name:   "happy path: aud as array containing expected",
			conf:   &Config{Issuer: issuer, GatewayOrigin: origin, ResourcePath: path},
			aud:    []string{"https://other.example.com", expected},
			wantOK: true,
		},
		{
			name:    "cross-resource replay: sibling resource aud rejected",
			conf:    &Config{Issuer: issuer, GatewayOrigin: origin, ResourcePath: path},
			aud:     origin + "/mcp/sentry",
			wantOK:  false,
			wantErr: jwt.ErrTokenInvalidAudience,
		},
		{
			// pins golang-jwt v5 behavior: once an expected audience is set, a
			// token with no aud claim at all must fail (not silently pass)
			name:    "missing aud claim rejected",
			conf:    &Config{Issuer: issuer, GatewayOrigin: origin, ResourcePath: path},
			aud:     nil,
			wantOK:  false,
			wantErr: jwt.ErrTokenRequiredClaimMissing,
		},
		{
			name:   "skip_audience_check: sibling resource aud accepted",
			conf:   &Config{Issuer: issuer, GatewayOrigin: origin, ResourcePath: path, SkipAudienceCheck: true},
			aud:    origin + "/mcp/sentry",
			wantOK: true,
		},
		{
			name:   "skip_audience_check: missing aud accepted",
			conf:   &Config{Issuer: issuer, GatewayOrigin: origin, ResourcePath: path, SkipAudienceCheck: true},
			aud:    nil,
			wantOK: true,
		},
		{
			name:   "audience override takes precedence: override matches",
			conf:   &Config{Issuer: issuer, GatewayOrigin: origin, ResourcePath: path, Audience: "custom-aud"},
			aud:    "custom-aud",
			wantOK: true,
		},
		{
			name:    "audience override takes precedence: derived value no longer accepted",
			conf:    &Config{Issuer: issuer, GatewayOrigin: origin, ResourcePath: path, Audience: "custom-aud"},
			aud:     expected,
			wantOK:  false,
			wantErr: jwt.ErrTokenInvalidAudience,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.conf.setup(); err != nil {
				t.Fatalf("setup: %v", err)
			}
			extra := jwt.MapClaims{}
			if tt.aud != nil {
				extra["aud"] = tt.aud
			}
			raw := signToken(t, issuer, extra)
			_, err := tt.conf.parser.ParseWithClaims(raw, jwt.MapClaims{}, staticKeyFunc)
			if tt.wantOK && err != nil {
				t.Errorf("expected token to validate, got: %v", err)
			}
			if !tt.wantOK && err == nil {
				t.Error("expected validation to fail, got nil error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("expected error %v, got: %v", tt.wantErr, err)
			}
		})
	}
}
