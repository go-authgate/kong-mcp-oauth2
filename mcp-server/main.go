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
	"log/slog"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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

// newHandler builds the MCP server with its single tool and returns the
// Streamable HTTP handler. It mounts at "/" because Kong's route uses
// strip_path: true (kong.yml) — a request to $GW/mcp/gitea arrives here as "/".
// Factored out so tests can drive it through httptest.
func newHandler() http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "mcp-gitea", Version: "v0.1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "whoami",
		Description: "Return the X-MCP-Subject and X-MCP-Scope the gateway forwarded",
	}, whoami)
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
}

func main() {
	addr := ":" + port()

	slog.Info("mcp-server listening", "addr", addr)
	if err := http.ListenAndServe(addr, newHandler()); err != nil {
		slog.Error("server exited", "error", err)
		os.Exit(1)
	}
}

// port returns PORT if set, else 3000 to match kong.yml's upstream and the
// stub it replaces.
func port() string {
	if p := os.Getenv("PORT"); p != "" {
		return p
	}
	return "3000"
}
