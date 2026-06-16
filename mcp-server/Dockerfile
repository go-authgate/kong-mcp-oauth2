# Build the MCP server as a static binary, then ship it in a distroless image.
# Standalone service — no Kong base image here. Mirrors the root Dockerfile's
# build style (CGO off, trimmed/stripped, honors TARGETOS/TARGETARCH so a
# `--platform` build cross-compiles to the final image's arch).
FROM golang:1.26 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -trimpath -ldflags="-s -w" -o /mcp-server .

# distroless/static: smallest base, no shell — clean Trivy scan. The server
# trusts Kong's injected headers and needs no shell or extra runtime.
FROM gcr.io/distroless/static:nonroot
COPY --from=build /mcp-server /usr/local/bin/mcp-server
EXPOSE 3000
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/mcp-server"]
