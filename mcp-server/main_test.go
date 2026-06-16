package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// unmarshalStructured decodes a tool result's structured output into v by
// round-tripping it through JSON.
func unmarshalStructured(res *mcp.CallToolResult, v any) error {
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// headerRoundTripper injects fixed headers on every outbound request, standing
// in for Kong re-sending the trusted X-MCP-* headers on each proxied call.
type headerRoundTripper struct {
	base    http.RoundTripper
	headers map[string]string
}

func (h headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	return h.base.RoundTrip(req)
}

// callWhoami connects an MCP client to ts (injecting headers on every request)
// and returns the whoami tool's structured Subject/Scope output.
func callWhoami(t *testing.T, ts *httptest.Server, headers map[string]string) Output {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	transport := &mcp.StreamableClientTransport{
		Endpoint:   ts.URL,
		HTTPClient: &http.Client{Transport: headerRoundTripper{base: http.DefaultTransport, headers: headers}},
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.0"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "whoami"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool reported error: %v", res.Content)
	}

	var out Output
	if err := unmarshalStructured(res, &out); err != nil {
		t.Fatalf("decode structured output: %v", err)
	}
	return out
}

// Test 1: happy path — headers present are echoed back.
func TestWhoami_HappyPath(t *testing.T) {
	ts := httptest.NewServer(newHandler())
	defer ts.Close()

	out := callWhoami(t, ts, map[string]string{
		"X-MCP-Subject": "alice",
		"X-MCP-Scope":   "mcp:gitea",
	})
	if out.Subject != "alice" {
		t.Errorf("subject = %q, want %q", out.Subject, "alice")
	}
	if out.Scope != "mcp:gitea" {
		t.Errorf("scope = %q, want %q", out.Scope, "mcp:gitea")
	}
}

// Test 2: edge — headers absent yield empty strings, no panic, server stays up.
func TestWhoami_HeadersAbsent(t *testing.T) {
	ts := httptest.NewServer(newHandler())
	defer ts.Close()

	out := callWhoami(t, ts, nil)
	if out.Subject != "" {
		t.Errorf("subject = %q, want empty", out.Subject)
	}
	if out.Scope != "" {
		t.Errorf("scope = %q, want empty", out.Scope)
	}

	// Server still serves a subsequent valid call.
	out = callWhoami(t, ts, map[string]string{"X-MCP-Subject": "bob"})
	if out.Subject != "bob" {
		t.Errorf("after empty call, subject = %q, want %q", out.Subject, "bob")
	}
}

// Test 3: bad input — a plain GET and malformed body don't crash the server;
// it keeps serving valid MCP traffic afterward.
func TestWhoami_NonMCPRequestDoesNotCrash(t *testing.T) {
	ts := httptest.NewServer(newHandler())
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("plain GET returned 200, expected an MCP/HTTP error status")
	}

	resp, err = http.Post(ts.URL, "application/json", strings.NewReader("{ not json"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("malformed POST returned 200, expected an MCP/HTTP error status")
	}

	// Server survived: a valid MCP call still works.
	out := callWhoami(t, ts, map[string]string{"X-MCP-Subject": "carol", "X-MCP-Scope": "mcp:gitea"})
	if out.Subject != "carol" || out.Scope != "mcp:gitea" {
		t.Errorf("after bad input, got %+v, want subject=carol scope=mcp:gitea", out)
	}
}
