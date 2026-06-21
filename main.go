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
//
// The implementation is split across files within this package:
//
//	config.go    — Config schema, setup() validation, derived per-instance values
//	jwks.go      — shared JWKS keyfunc cache (per-URI build lock, fail-fast fetch)
//	metadata.go  — RFC 8414 AS-metadata discovery and the keyFunc bridge
//	access.go    — the per-request Access handler (steps 2/3/5)
//	main.go      — plugin server bootstrap
package main

import (
	"log/slog"
	"os"

	"github.com/Kong/go-pdk/server"
)

var (
	Version  = "0.4.0"
	Priority = 1000
)

// main exits non-zero on a failed start: server.StartServer returns socket
// errors without logging, and a silent exit 0 reads as a healthy pluginserver.
func main() {
	if err := server.StartServer(New, Version, Priority); err != nil {
		slog.Error("plugin server exited", "error", err)
		os.Exit(1)
	}
}
