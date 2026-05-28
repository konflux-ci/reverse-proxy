# Konflux Reverse Proxy

Custom [Caddy](https://caddyserver.com/) build with plugins for the
[Konflux](https://github.com/konflux-ci/konflux-ci) UI proxy.

## Why a custom build?

The Konflux UI proxy sits between the browser and the Kubernetes API server.
After `oauth2-proxy` authenticates a user, the proxy must translate the
authentication response into Kubernetes
[impersonation headers](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation)
(`Impersonate-User`, `Impersonate-Group`).

The challenge is that `oauth2-proxy` returns all groups in a **single
comma-separated** `X-Auth-Request-Groups` header, but the Kubernetes API
requires each group as a **separate** `Impersonate-Group` header.

Stock Caddy cannot split one header value into multiple headers. This repo
provides the `impersonate` handler plugin that does exactly that, with no
arbitrary group limit and no empty-header side effects.

## Architecture: Dynamic File Rotation Without a Sidecar

The Konflux UI proxy needs to handle three types of dynamic file content that
rotates at different frequencies. Rather than using a sidecar to poll files and
reload Caddy via the Admin API, this build uses a combination of custom plugins
to handle each type optimally:

| What changes | Frequency | Mechanism | Plugin | Reload? |
|---|---|---|---|---|
| Bearer tokens | Every 600s | atomic cache + `inject_cached_vars` | `filewatcher` | No |
| Serving TLS cert | Every 60–90 days | `get_certificate` module | `certwatcher` | No |
| CA trust bundles | Rare (months/years) | fsnotify + SIGUSR1 | `filewatcher` | Yes (seamless) |

### Why not Caddy's `{file.*}` placeholder?

Caddy's built-in `{file.*}` placeholder reads a file from disk on every
request. Even after upstream fixed the 1 MB buffer allocation (now using
`io.ReadAll`), it still performs a filesystem `open` + `read` + `close` syscall
per request. Under memory-constrained containers (256 MB limit) and high
concurrency, this causes significant performance degradation:

| Metric | Baseline | `{file.*}` | Plugin |
|--------|----------|------------|--------|
| Throughput (c=10) | 204 req/s | 148 req/s | **205 req/s** |
| p50 latency | 22.5 ms | 88.4 ms | **21.0 ms** |
| Throughput at 12x c=200 | ~1,085 req/s | ~142 req/s | **~1,108 req/s** |
| Behavior at memory limit | OOM (serving traffic) | GC thrashing (1/7th throughput) | **OOM (serving traffic)** |

Our `filewatcher` plugin solves this by caching file content in
`atomic.Pointer[string]` values — reads are a single pointer load with **zero
allocations and zero syscalls per request**. Files are updated instantly via
fsnotify with a periodic poll fallback for Kubernetes symlink rotations.

### How it works

```
┌─────────────────────────────────────────────────────────────┐
│                    Caddy Process                              │
│                                                              │
│  ┌──────────────────┐   ┌───────────────────────────────┐   │
│  │  certwatcher      │   │  filewatcher                  │   │
│  │  (tls.get_cert)   │   │  (caddy.apps.file_watcher)    │   │
│  │                   │   │                               │   │
│  │  Watches serving  │   │  Watches CA directories +     │   │
│  │  cert via fsnotify│   │  caches token files           │   │
│  │  Serves from      │   │  Sends SIGUSR1 for CAs       │   │
│  │  atomic.Pointer   │   │  atomic.Pointer for tokens    │   │
│  └──────────────────┘   └───────────────────────────────┘   │
│                                                              │
│  TLS handshake:                                              │
│    → certwatcher.GetCertificate() returns latest cert        │
│                                                              │
│  Upstream request:                                           │
│    → inject_cached_vars sets {http.vars.*} from cache         │
│    → header_up uses {http.vars.kube_token}                   │
│    → transport uses tls_trust_pool (re-read on SIGUSR1)      │
└─────────────────────────────────────────────────────────────┘
```

**Why SIGUSR1 is safe here**: The `get_certificate` module and cached token
injection eliminate all runtime Admin API usage, keeping SIGUSR1 active for
the pod's entire lifetime.

## Plugins

### `impersonate`

HTTP handler middleware that reads user/group headers from an auth proxy and
sets them as individual impersonation headers on the request.

**What it does:**

1. Reads `X-Auth-Request-Email` and sets it as `Impersonate-User`
2. Reads `X-Auth-Request-Groups` (comma-separated), splits it, and adds each
   value as a separate `Impersonate-Group` header
3. Always appends `system:authenticated` (configurable)

#### Caddyfile syntax

```caddyfile
impersonate [<options>]
```

With defaults (Kubernetes API impersonation):

```caddyfile
route {
    forward_auth 127.0.0.1:6000 {
        uri /oauth2/auth
        copy_headers X-Auth-Request-Email X-Auth-Request-Groups
    }
    impersonate
    reverse_proxy https://kubernetes.default.svc { ... }
}
```

With custom target headers (e.g. for namespace-lister):

```caddyfile
route {
    forward_auth 127.0.0.1:6000 {
        uri /oauth2/auth
        copy_headers X-Auth-Request-Email X-Auth-Request-Groups
    }
    impersonate {
        target_user  X-User
        target_group X-Group
    }
    reverse_proxy https://namespace-lister.svc { ... }
}
```

#### Options

| Option | Default | Description |
|--------|---------|-------------|
| `source_user` | `X-Auth-Request-Email` | Header containing the user identity |
| `source_groups` | `X-Auth-Request-Groups` | Header containing comma-separated groups |
| `target_user` | `Impersonate-User` | Header name to set for the user |
| `target_group` | `Impersonate-Group` | Header name to add for each group |
| `always_include` | `system:authenticated` | Groups always appended (space-separated list) |
| `separator` | `,` | Delimiter for splitting the source groups header |

### `certwatcher`

TLS certificate manager module (`tls.get_certificate.file`) that watches a
certificate and key file on disk and serves the latest version during TLS
handshakes — without requiring a Caddy reload.

Designed for Kubernetes environments where cert-manager rotates serving
certificates by atomically replacing symlinks in projected volumes.

#### Caddyfile syntax

```caddyfile
:9443 {
    tls {
        get_certificate file {
            cert /mnt/serving-cert/tls.crt
            key  /mnt/serving-cert/tls.key
            debounce 5s
            poll 5m
        }
    }
    reverse_proxy ...
}
```

#### Options

| Option | Default | Description |
|--------|---------|-------------|
| `cert` | *(required)* | Path to the PEM-encoded certificate file |
| `key` | *(required)* | Path to the PEM-encoded private key file |
| `debounce` | `5s` | Wait time after last fs event before reloading |
| `poll` | `5m` | Fallback poll interval for re-reading cert files (catches missed fsnotify events; `0` to disable) |

---

### `filewatcher`

Caddy app module (`file_watcher`) with two behaviors:

1. **Watch directories** — sends SIGUSR1 on changes to trigger a config reload.
   Designed for CA bundle rotation where Go's immutable `x509.CertPool` requires
   a full re-provision to pick up new CAs.

2. **Cache file content** — reads files into `atomic.Pointer[string]` values,
   updated instantly via fsnotify with a 10s poll fallback. Zero allocations per
   request. Use with `inject_cached_vars` middleware for token injection.

#### Caddyfile syntax

```caddyfile
{
    file_watcher {
        watch /var/run/secrets/kubernetes.io/serviceaccount
        watch /mnt/trusted-ca

        cache kube_token /var/run/secrets/konflux-ci.dev/serviceaccount/token
        cache backend_token /var/run/secrets/konflux-ci.dev/backend/token

        debounce 5s
        poll 10s
    }
}

route {
    inject_cached_vars
    reverse_proxy https://kubernetes.default.svc {
        header_up Authorization "Bearer {http.vars.kube_token}"
    }
}
```

#### Options

| Option | Default | Description |
|--------|---------|-------------|
| `watch` | *(repeatable)* | Directory path to watch; changes trigger SIGUSR1 |
| `cache` | *(repeatable)* | `<name> <path>` — cache file content as `{http.vars.<name>}` |
| `debounce` | `5s` | Wait time after last fs event before sending SIGUSR1 |
| `poll` | `10s` | Fallback poll interval for cached files (catches missed fsnotify events) |

---

## Building

No `xcaddy` required. The build follows the
[standard Caddy plugin workflow](https://github.com/caddyserver/caddy/blob/master/cmd/caddy/main.go):

```bash
go build -o caddy ./cmd/caddy
./caddy list-modules | grep -E 'impersonate|certwatcher|file_watcher'
# http.handlers.impersonate
# tls.get_certificate.file
# caddy.apps.file_watcher
```

### Container image

```bash
podman build -t konflux-reverse-proxy .
```

For multi-arch:

```bash
podman build --platform linux/amd64,linux/arm64 -t konflux-reverse-proxy .
```

## Testing

```bash
go test ./...
```

## License

Apache License 2.0
