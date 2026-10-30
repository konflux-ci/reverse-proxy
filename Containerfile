FROM registry.access.redhat.com/hi/go@sha256:661c9318bad795f5b9e5a851ae045dab81519e9c5b2e96b7879c074faf0882c8 AS builder
ARG TARGETOS
ARG TARGETARCH

ENV GOTOOLCHAIN=auto
WORKDIR /build

COPY --chmod=644 go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -a -o /opt/app-root/caddy ./cmd/caddy && \
    go test ./...

# Minimal runtime for statically compiled binaries (Go/Rust/C/C++).
# Includes only CA certs, timezone data, and a non-root user.
# No shell, package manager, or C library is included.
FROM registry.access.redhat.com/hi/static@sha256:c51e17de4a96e3bd68361830ec54f3c43ffcf398b82765a1ce250bd4a0d99d1f
WORKDIR /
COPY --from=builder /opt/app-root/caddy /usr/bin/caddy
COPY LICENSE /licenses/

LABEL name="Konflux Reverse Proxy"
LABEL vendor="Red Hat, Inc."
LABEL version="0.1.0"
LABEL release="1"
LABEL summary="Custom Caddy reverse proxy for Konflux"
LABEL description="Custom Caddy reverse proxy for Konflux"
LABEL maintainer="Konflux CI"
LABEL io.k8s.description="Custom Caddy reverse proxy for Konflux"
LABEL io.k8s.display-name="konflux-reverse-proxy"
LABEL distribution-scope="public"
LABEL url="https://github.com/konflux-ci/reverse-proxy"
LABEL com.redhat.component="konflux-reverse-proxy"

USER 1001
ENTRYPOINT ["caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile"]
