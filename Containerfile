FROM registry.access.redhat.com/hi/go@sha256:46591373211cdf0c5689f5a15bebec3f1bb5602552257882b4aa9a320a8d29e1 AS builder
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

FROM registry.access.redhat.com/ubi10/ubi-minimal@sha256:5a1acbfad56de537f978184e662a02ba8141d82a3ce0d2aca183bfad812b0ea7
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
