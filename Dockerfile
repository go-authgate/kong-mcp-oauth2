# Build the Go plugin as a standalone pluginserver binary, then bake it into the
# Kong image. go-pdk plugins are ordinary executables that speak the Kong
# pluginserver RPC protocol over stdio — no cgo, no .so loading.
#
# Pin the binary to the FINAL image's architecture. Under BuildKit, TARGETOS /
# TARGETARCH are populated (e.g. by `docker build --platform`) and the binary
# cross-compiles to that target, matching the kong image it lands in. Under the
# classic builder they are empty, and an empty GOOS/GOARCH means "use the native
# default" — which is also the daemon's arch, so both stages still agree. Either
# way the binary's arch matches the kong container. A mismatch would make the
# pluginserver fail with `exec format error` and emit *nothing* on stdout, and
# Kong would die at init with `failed decoding plugin info: Expected value but
# found T_END at character 1` (an empty `-dump`).
FROM golang:1.26 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -trimpath -ldflags="-s -w" -o /mcp-authgate .

FROM kong:3.9
COPY --from=build /mcp-authgate /usr/local/bin/mcp-authgate
USER kong
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD kong health
