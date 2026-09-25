FROM registry.access.redhat.com/hi/go@sha256:666e77358fcda912f3251bc1651dc1908ea1d6e49c0eab43b0aacef272d187dc AS builder
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
FROM registry.access.redhat.com/hi/static@sha256:08d039e8b4f70c0b22118acfff9ada93fc7f9d349e5c5ac991fbdf6b876eea91
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
