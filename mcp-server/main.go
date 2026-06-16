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
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// healthPath is the liveness endpoint. Single source of truth so the handler
// that serves it and the -health probe that GETs it can't drift.
const healthPath = "/healthz"

// Output is what `whoami` returns. The SDK infers the output schema from this
// struct and fills both the structured and unstructured tool result from it.
type Output struct {
	Subject string `json:"subject" jsonschema:"the X-MCP-Subject the gateway forwarded (token sub)"`
	Scope   string `json:"scope" jsonschema:"the X-MCP-Scope the gateway forwarded (token scope)"`
}

// whoami reads the two trusted identity headers off the inbound HTTP request
// that carried the tools/call and returns their values. Headers are re-sent by
// Kong on every proxied request, so each call sees the caller's identity.
//
// req.Extra is nil on transports that don't carry an HTTP request (e.g. stdio),
// so guard it before reaching for .Header. http.Header.Get is nil-safe, so an
// absent header simply yields "" — no panic, the server stays up.
func whoami(_ context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, Output, error) {
	var h http.Header
	if req != nil && req.Extra != nil {
		h = req.Extra.Header
	}
	return nil, Output{
		Subject: h.Get("X-MCP-Subject"),
		Scope:   h.Get("X-MCP-Scope"),
	}, nil
}

// newHandler builds the MCP server with its single tool and returns an HTTP
// handler. MCP traffic is served at "/" because Kong's route uses
// strip_path: true (kong.yml) — a request to $GW/mcp/gitea arrives here as "/".
// A plain "/healthz" returning 200 is mounted alongside so the container's
// HEALTHCHECK (and any external probe) can confirm liveness without speaking
// MCP. Factored out so tests can drive it through httptest.
func newHandler() http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: serverName(), Version: "v0.1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "whoami",
		Description: "Return the X-MCP-Subject and X-MCP-Scope the gateway forwarded",
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
// backs multiple Kong routes (mcp-gitea, mcp-sentry); each sets this so its
// initialize/serverInfo advertises the right identity. The per-call subject and
// scope still come from Kong's per-route headers, not from this name.
func serverName() string {
	if n := os.Getenv("MCP_SERVER_NAME"); n != "" {
		return n
	}
	return "mcp-server"
}
