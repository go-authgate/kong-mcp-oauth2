package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
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

// Test: /healthz answers 200 OK so the container HEALTHCHECK has something to
// probe, and MCP traffic on "/" still works alongside it.
func TestHealthz(t *testing.T) {
	ts := httptest.NewServer(newHandler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + healthPath)
	if err != nil {
		t.Fatalf("GET %s: %v", healthPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("%s status = %d, want %d", healthPath, resp.StatusCode, http.StatusOK)
	}

	// The health endpoint didn't displace MCP traffic on "/".
	out := callWhoami(t, ts, map[string]string{"X-MCP-Subject": "dave", "X-MCP-Scope": "mcp:gitea"})
	if out.Subject != "dave" || out.Scope != "mcp:gitea" {
		t.Errorf("after %s, got %+v, want subject=dave scope=mcp:gitea", healthPath, out)
	}
}

// Test: runHealthCheck — the code path the container HEALTHCHECK runs — maps a
// 200 to exit 0, a non-200 to exit 1, and an unreachable server to exit 1.
func TestRunHealthCheck(t *testing.T) {
	// Healthy: real handler serving /healthz answers 200 → exit 0.
	ts := httptest.NewServer(newHandler())
	defer ts.Close()
	if code := runHealthCheck(ts.URL + healthPath); code != 0 {
		t.Errorf("runHealthCheck(healthy) = %d, want 0", code)
	}

	// Unhealthy: a 503 → exit 1.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()
	if code := runHealthCheck(bad.URL); code != 1 {
		t.Errorf("runHealthCheck(503) = %d, want 1", code)
	}

	// Unreachable: probe a server we've already closed → connection error → exit 1.
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()
	if code := runHealthCheck(downURL); code != 1 {
		t.Errorf("runHealthCheck(unreachable) = %d, want 1", code)
	}
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

// Test 1b: the full set of forwarded claim headers is echoed, scope is split
// into scopes, and server reports this process's identity.
func TestWhoami_FullIdentity(t *testing.T) {
	ts := httptest.NewServer(newHandler())
	defer ts.Close()

	out := callWhoami(t, ts, map[string]string{
		"X-MCP-Subject":    "alice",
		"X-MCP-Scope":      "mcp:gitea mcp:sentry",
		"X-MCP-Issuer":     "https://auth.example.com",
		"X-MCP-Audience":   "https://gw.example.com/mcp/server",
		"X-MCP-Client":     "cli-app",
		"X-MCP-Token-Id":   "tok-123",
		"X-MCP-Expires":    "2026-01-01T00:00:00Z",
		"X-Forwarded-Host": "gw.example.com",
	})

	want := Output{
		Subject:  "alice",
		Scope:    "mcp:gitea mcp:sentry",
		Scopes:   []string{"mcp:gitea", "mcp:sentry"},
		Server:   "mcp-server", // MCP_SERVER_NAME unset in tests -> default
		Host:     "gw.example.com",
		Issuer:   "https://auth.example.com",
		Audience: "https://gw.example.com/mcp/server",
		Client:   "cli-app",
		TokenID:  "tok-123",
		Expires:  "2026-01-01T00:00:00Z",
	}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("whoami output\n got %+v\nwant %+v", out, want)
	}
}

// Test 1c: token_forwarded reports whether an Authorization header reached the
// backend — the signal validation row 6a reads to prove the gateway's
// strip/static mode actually withheld the client token. Only presence is
// echoed, never the value.
func TestWhoami_TokenForwarded(t *testing.T) {
	ts := httptest.NewServer(newHandler())
	defer ts.Close()

	// gateway in passthrough mode: the bearer token reaches the backend
	out := callWhoami(t, ts, map[string]string{
		"X-MCP-Subject": "alice",
		"Authorization": "Bearer live-token",
	})
	if !out.TokenForwarded {
		t.Error("token_forwarded = false with Authorization present, want true")
	}

	// gateway in strip/static mode: no Authorization header arrives
	out = callWhoami(t, ts, map[string]string{"X-MCP-Subject": "alice"})
	if out.TokenForwarded {
		t.Error("token_forwarded = true without Authorization, want false")
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

	assertNotOK := func(label string, do func() (*http.Response, error)) {
		t.Helper()
		resp, err := do()
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("%s returned 200, expected an MCP/HTTP error status", label)
		}
	}

	assertNotOK("plain GET", func() (*http.Response, error) { return http.Get(ts.URL) })
	assertNotOK("malformed POST", func() (*http.Response, error) {
		return http.Post(ts.URL, "application/json", strings.NewReader("{ not json"))
	})

	// Server survived: a valid MCP call still works.
	out := callWhoami(t, ts, map[string]string{"X-MCP-Subject": "carol", "X-MCP-Scope": "mcp:gitea"})
	if out.Subject != "carol" || out.Scope != "mcp:gitea" {
		t.Errorf("after bad input, got %+v, want subject=carol scope=mcp:gitea", out)
	}
}
