# mcp-server

A minimal [Model Context Protocol](https://modelcontextprotocol.io) server that
echoes the trusted identity headers Kong's `mcp-oauth2` plugin injects upstream.
It answers one question for the demo gateway: **is the token's identity actually
reaching my backend?**

Kong verifies the bearer JWT, then forwards each request with two headers set
from the token's claims (see the plugin's `main.go`):

- `X-MCP-Subject` — the token `sub`
- `X-MCP-Scope` — the token `scope`

This server trusts those headers (Kong is the front door; it does no auth of its
own) and exposes a single MCP tool over Streamable HTTP:

- **`whoami`** — returns `{ "subject": "...", "scope": "..." }` read from the
  inbound request's `X-MCP-*` headers. Absent headers yield empty strings.

It mounts the handler at `/` because Kong's route uses `strip_path: true`
(`kong.yml`), so `$GW/mcp/gitea` arrives here as `/`. It listens on `:3000`
(override with `PORT`) to match `kong.yml`'s `url: http://mcp-gitea:3000`.

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
# connect to http://localhost:8000/mcp/gitea with a valid bearer token,
# then call `whoami` — it echoes the token's real sub / scope.
```

## Test

```sh
go test ./...
```

Covers the happy path (headers echoed), the empty-header edge (graceful, no
panic), and non-MCP traffic (a plain `GET` doesn't crash the server).
