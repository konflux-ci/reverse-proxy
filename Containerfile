FROM registry.access.redhat.com/hi/go@sha256:f40252e3921a07ee4c7ef4dc04fbb6fc89f4fb4f821495e0ac0446f019e2dc20 AS builder
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
FROM registry.access.redhat.com/hi/static@sha256:e03890505b412c81de20ba8719dbe6eda47096f88d3451b2b42b3f7535ecccf7
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
