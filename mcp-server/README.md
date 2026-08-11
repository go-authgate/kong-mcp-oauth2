# mcp-server

A minimal [Model Context Protocol](https://modelcontextprotocol.io) server that
echoes the trusted identity headers Kong's `mcp-oauth2` plugin injects upstream.
It answers one question for the demo gateway: **is the token's identity actually
reaching my backend?**

Kong verifies the bearer JWT, then forwards each request with a set of trusted
headers derived from the token's claims (see the plugin's `main.go`). Under the
plugin's default `upstream_auth_mode: strip`, the client's `Authorization`
header is removed before the request reaches this server, so identity travels
only in these headers:

- `X-MCP-Subject` — the token `sub`
- `X-MCP-Scope` — the token `scope`
- `X-MCP-Issuer` — the token `iss`
- `X-MCP-Audience` — the token `aud`
- `X-MCP-Client` — the token `client_id` (or `azp`)
- `X-MCP-Token-Id` — the token `jti`
- `X-MCP-Expires` — the token `exp`, rendered as RFC 3339

Only `X-MCP-Subject` and `X-MCP-Scope` are always present; the rest are set only
when the verified token carried the matching claim.

This server trusts those headers (Kong is the front door; it does no auth of its
own) and exposes a single MCP tool over Streamable HTTP:

- **`whoami`** — returns the forwarded identity read from the inbound request's
  `X-MCP-*` headers, plus this process's own `server` name. Absent headers yield
  empty strings (omitted from the JSON for the optional fields). `token_forwarded`
  is always present (never omitted): it reports whether an `Authorization` header
  reached this backend, so `false` is the proof that the gateway withheld the
  client's token under the default `strip` mode:

  ```json
  {
    "subject": "alice",
    "scope": "mcp:gitea mcp:sentry",
    "scopes": ["mcp:gitea", "mcp:sentry"],
    "server": "mcp-server",
    "host": "localhost:8000",
    "issuer": "http://localhost:8080",
    "audience": "http://localhost:8000/mcp/server",
    "client": "inspector",
    "token_id": "0b5e...",
    "expires": "2026-06-17T12:34:56Z",
    "token_forwarded": false
  }
  ```

  `scopes` is `scope` split on whitespace; `server` comes from `MCP_SERVER_NAME`
  (it identifies the route, not the caller); `host` is read from Kong's
  `X-Forwarded-Host`.

It mounts the handler at `/` because Kong's route uses `strip_path: true`
(`kong.yml`), so `$GW/mcp/server` arrives here as `/`. It listens on `:3000`
(override with `PORT`) to match `kong.yml`'s `url: http://mcp-server:3000`.

The same binary backs multiple Kong routes (`mcp-server`, `mcp-sentry`). Each
sets `MCP_SERVER_NAME` (default `mcp-server`) so its `initialize` response — and
`whoami`'s `server` field — advertises the right name; the per-call identity
still comes from Kong's per-route headers, so the two routes return
route-specific identity from one image.

## Run

```sh
# Standalone (no gateway):
go run .                 # listens on :3000
PORT=8080 go run .       # or pick a port

# Through the demo stack:
docker compose up --build   # from the repo root; Kong proxies to this server
```

## Try it

Through the gateway with the [MCP Inspector](https://github.com/modelcontextprotocol/inspector):

```sh
npx @modelcontextprotocol/inspector
# connect to http://localhost:8000/mcp/server with a valid bearer token,
# then call `whoami` — it echoes the token's real sub / scope / issuer /
# audience / client / jti / expiry, plus which server answered.
```

## Test

```sh
go test ./...
```

Covers the happy path (headers echoed), the empty-header edge (graceful, no
panic), and non-MCP traffic (a plain `GET` doesn't crash the server).
