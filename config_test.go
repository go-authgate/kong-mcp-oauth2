package main

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"maps"
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
