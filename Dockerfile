# syntax=docker/dockerfile:1.7

FROM golang:1.24-alpine AS build

ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /src

# Keep dependency download cacheable. The root module replaces the API module
# with ./api, so both module manifests must exist before go mod download.
COPY go.mod go.sum ./
COPY api/go.mod api/go.sum ./api/
RUN go mod download

COPY api ./api
COPY cmd ./cmd
COPY internal ./internal

# Auth Center has no CGO dependency. A CGO-disabled build is fully static and
# therefore has no runtime dependency on glibc or musl.
RUN if [ -n "$TARGETARCH" ]; then export GOARCH="$TARGETARCH"; fi; \
    CGO_ENABLED=0 GOOS="$TARGETOS" \
    go build -buildvcs=false -trimpath -tags="netgo,osusergo" \
    -ldflags="-s -w -buildid=" \
    -o /out/auth-center ./cmd/auth-center

FROM alpine:3.22 AS runtime

RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 auth-center \
    && adduser -S -D -H -u 10001 -G auth-center auth-center \
    && install -d -o auth-center -g auth-center /app /var/lib/iwut-auth-center

WORKDIR /app
COPY --from=build --chown=auth-center:auth-center /out/auth-center ./auth-center

USER auth-center:auth-center

EXPOSE 8000 9000
STOPSIGNAL SIGTERM

ENTRYPOINT ["/app/auth-center"]
