# syntax=docker/dockerfile:1
#
# The panel image. It carries three things:
#
#   * the panel binary, with the admin interface embedded;
#   * the Linux agent and core builds for amd64 and arm64, which the installer
#     hands to a node - that is why a node only ever has to reach the panel;
#   * nothing else. No shell tooling beyond CA certificates, because the panel
#     holds the master key and is the one host that can reach every node.

# ---------------------------------------------------------------- interface --
FROM node:22-alpine AS web
WORKDIR /src/web
# The manifest is copied on its own so a source-only change does not reinstall
# the dependency tree.
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
# Vite writes to ../internal/panel/webui/dist, which is where go:embed looks.
RUN npm run build

# -------------------------------------------------------------------- build --
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The freshly built interface replaces whatever the repository had, so an image
# can never ship a stale panel next to a current binary.
COPY --from=web /src/internal/panel/webui/dist ./internal/panel/webui/dist

# No cgo: the agent and the core have to run on a node whose libc is unknown,
# and a static binary is one fewer thing that can differ between the two.
ENV CGO_ENABLED=0 GOOS=linux

# Which architectures the installer can serve. Both by default; narrow it to
# one on a host that has to build the image itself, since each extra
# architecture is a full second compile and a build cache to go with it:
#
#   docker compose build --build-arg DIST_ARCHES=amd64
ARG DIST_ARCHES="amd64 arm64"

RUN go build -trimpath -ldflags="-s -w" -o /out/wn-main ./cmd/wn-main
RUN set -eu; for arch in $DIST_ARCHES; do \
      GOARCH="$arch" go build -trimpath -ldflags="-s -w" \
        -o "/out/dist/wn-agent-linux-$arch" ./cmd/wn-agent; \
      GOARCH="$arch" go build -trimpath -ldflags="-s -w" \
        -o "/out/dist/whitenet-linux-$arch" ./cmd/whitenet; \
    done

# --------------------------------------------------------------------- run ---
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 whitenet \
 && adduser -S -u 10001 -G whitenet whitenet
COPY --from=build /out/wn-main /usr/local/bin/wn-main
COPY --from=build /out/dist/ /opt/whitenet/dist/
# The panel keeps no state on disk - the database holds all of it - so it runs
# unprivileged with nothing writable.
USER whitenet:whitenet
# An empty WN_CONFIG means "no file, read the environment", which is how the
# image avoids needing a mounted config just to find its database.
ENV WN_CONFIG="" \
    WN_DIST_DIR=/opt/whitenet/dist \
    WN_HTTP_LISTEN=0.0.0.0:8080 \
    WN_GRPC_LISTEN=0.0.0.0:8443
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/wn-main"]
CMD ["serve"]
