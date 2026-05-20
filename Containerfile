FROM registry.access.redhat.com/hi/go@sha256:1d46eceb4c8055a316083d83644a06e8e3c877432f9f97bb138923ef61f9bbdb AS builder
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

FROM scratch
WORKDIR /
COPY --from=builder /opt/app-root/caddy /usr/bin/caddy

LABEL name="Konflux Reverse Proxy"
LABEL description="Custom Caddy reverse proxy with Konflux impersonation plugin"
LABEL summary="Custom Caddy reverse proxy with Konflux impersonation plugin"
LABEL io.k8s.description="Custom Caddy reverse proxy with Konflux impersonation plugin"
LABEL io.k8s.display-name="konflux-reverse-proxy"
LABEL vendor="Red Hat, Inc."
LABEL distribution-scope="public"
LABEL url="https://github.com/konflux-ci/reverse-proxy"
LABEL maintainer="Konflux CI"
LABEL com.redhat.component="konflux-reverse-proxy"

USER 1001
ENTRYPOINT ["caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile"]
