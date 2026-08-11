// Minimal MCP server that echoes the trusted identity headers Kong's
// mcp-oauth2 plugin injects upstream. Kong verifies the bearer JWT, then
// forwards the request with X-MCP-Subject / X-MCP-Scope set from the token's
// claims (see the plugin's main.go). This server trusts those headers — Kong
// is the front door — and hands them back through a single `whoami` tool so a
// demo can answer "is the token's identity actually reaching my backend?" with
// one tools/call.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// healthPath is the liveness endpoint. Single source of truth so the handler
// that serves it and the -health probe that GETs it can't drift.
const healthPath = "/healthz"

// Output is what `whoami` returns. The SDK infers the output schema from this
// struct and fills both the structured and unstructured tool result from it.
//
// Subject and Scope come from the headers Kong's plugin always sets; the rest
// are best-effort: the plugin forwards them only when the verified token
// carried the matching claim, so each is omitempty and may be absent. Server is
// the one field this process knows on its own (not from Kong) — it answers
// "which MCP route handled this call" when one binary backs several.
type Output struct {
	Subject  string   `json:"subject" jsonschema:"the X-MCP-Subject the gateway forwarded (token sub)"`
	Scope    string   `json:"scope" jsonschema:"the raw X-MCP-Scope the gateway forwarded (space-delimited token scope)"`
	Scopes   []string `json:"scopes" jsonschema:"the scope split into individual grants"`
	Server   string   `json:"server" jsonschema:"which logical MCP server answered (MCP_SERVER_NAME)"`
	Host     string   `json:"host,omitempty" jsonschema:"the gateway host the client reached (X-Forwarded-Host)"`
	Issuer   string   `json:"issuer,omitempty" jsonschema:"the token issuer the gateway forwarded (token iss)"`
	Audience string   `json:"audience,omitempty" jsonschema:"the audience the token was bound to (token aud)"`
	Client   string   `json:"client,omitempty" jsonschema:"the OAuth client the token was issued to (client_id/azp)"`
	TokenID  string   `json:"token_id,omitempty" jsonschema:"the token's unique id (token jti)"`
	Expires  string   `json:"expires,omitempty" jsonschema:"when the access token expires, RFC 3339 (token exp)"`
	// TokenForwarded is deliberately not omitempty: false is the interesting
	// answer — it proves the gateway withheld the client's bearer token
	// (upstream_auth_mode strip/static), which is what validation row 6a checks.
	// Only presence is reported, never the credential itself, so a demo output
	// can't leak a live token into logs or screenshots.
	TokenForwarded bool `json:"token_forwarded" jsonschema:"whether an Authorization header reached this backend; false means the gateway stripped or replaced the client token"`
}

// whoami reads the trusted identity headers off the inbound HTTP request that
// carried the tools/call and returns their values, plus this process's own
// server name. Kong re-sends the headers on every proxied request, so each call
// sees the caller's identity.
//
// req.Extra is nil on transports that don't carry an HTTP request (e.g. stdio),
// so guard it before reaching for .Header. http.Header.Get is nil-safe, so an
// absent header simply yields "" — no panic, the server stays up.
func whoami(_ context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, Output, error) {
	var h http.Header
	if req != nil && req.Extra != nil {
		h = req.Extra.Header
	}
	scope := h.Get("X-MCP-Scope")
	// Host comes from X-Forwarded-Host (Kong's default), not the Host header:
	// Go's HTTP server moves Host out of the header map into req.Host, which the
	// SDK doesn't expose here, so Get("Host") would always be empty.
	return nil, Output{
		Subject:        h.Get("X-MCP-Subject"),
		Scope:          scope,
		Scopes:         strings.Fields(scope),
		Server:         serverName(),
		Host:           h.Get("X-Forwarded-Host"),
		Issuer:         h.Get("X-MCP-Issuer"),
		Audience:       h.Get("X-MCP-Audience"),
		Client:         h.Get("X-MCP-Client"),
		TokenID:        h.Get("X-MCP-Token-Id"),
		Expires:        h.Get("X-MCP-Expires"),
		TokenForwarded: h.Get("Authorization") != "",
	}, nil
}

// newHandler builds the MCP server with its single tool and returns an HTTP
// handler. MCP traffic is served at "/" because Kong's route uses
// strip_path: true (kong.yml) — a request to $GW/mcp/server arrives here as "/".
// A plain "/healthz" returning 200 is mounted alongside so the container's
// HEALTHCHECK (and any external probe) can confirm liveness without speaking
// MCP. Factored out so tests can drive it through httptest.
func newHandler() http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: serverName(), Version: "v0.1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "whoami",
		Description: "Return the caller identity the gateway forwarded (subject, scope, issuer, audience, client, token id, expiry) and which MCP server answered",
	}, whoami)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)

	mux := http.NewServeMux()
	mux.HandleFunc(healthPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/", mcpHandler)
	return mux
}

func main() {
	// -health turns this same binary into a liveness probe: it GETs its own
	// /healthz and exits 0/1. The distroless image has no shell or curl, so the
	// HEALTHCHECK can't shell out — re-invoking the binary is the only probe
	// available. flag.Parse stays cheap for the normal server path.
	healthCheck := flag.Bool("health", false, "probe the local /healthz endpoint and exit (for container HEALTHCHECK)")
	flag.Parse()
	if *healthCheck {
		os.Exit(runHealthCheck("http://127.0.0.1:" + port() + healthPath))
	}

	addr := ":" + port()

	slog.Info("mcp-server listening", "addr", addr)
	if err := http.ListenAndServe(addr, newHandler()); err != nil {
		slog.Error("server exited", "error", err)
		os.Exit(1)
	}
}

// runHealthCheck GETs url and returns a process exit code: 0 when it answers
// 200, 1 otherwise. The URL is a parameter (main passes the local /healthz)
// so tests can point it at an httptest server — the same code path the
// container HEALTHCHECK exercises, minus os.Exit.
func runHealthCheck(url string) int {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		slog.Error("health check failed", "error", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		slog.Error("health check unhealthy", "status", resp.StatusCode)
		return 1
	}
	return 0
}

// port returns PORT if set, else 3000 to match kong.yml's upstream and the
// stub it replaces.
func port() string {
	if p := os.Getenv("PORT"); p != "" {
		return p
	}
	return "3000"
}

// serverName returns MCP_SERVER_NAME if set, else "mcp-server". The same binary
// backs multiple Kong routes (mcp-server, mcp-sentry); each sets this so its
// initialize/serverInfo advertises the right identity. The per-call subject and
// scope still come from Kong's per-route headers, not from this name.
func serverName() string {
	if n := os.Getenv("MCP_SERVER_NAME"); n != "" {
		return n
	}
	return "mcp-server"
}
