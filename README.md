# Konflux Reverse Proxy

Custom [Caddy](https://caddyserver.com/) build with plugins for the
[Konflux](https://github.com/konflux-ci/konflux-ci) UI proxy.

## Why a custom build?

The Konflux UI proxy sits between the browser and the Kubernetes API server.
After `oauth2-proxy` authenticates a user, the proxy must translate the
authentication response into Kubernetes
[impersonation headers](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation)
(`Impersonate-User`, `Impersonate-Group`).

The Kubernetes API requires each group as a **separate** `Impersonate-Group`
header. `oauth2-proxy` can put those names in one comma-separated header, but
that encoding is ambiguous: a group whose name contains a comma is the same
bytes as two groups. Dex already stores the names in the ID token as a JSON
array. This repo's `impersonate` handler reads that array and writes one
header per group. It also drops reserved and platform-admin groups such as
`system:masters`.

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

HTTP handler middleware that reads the authenticated user and the ID token's
`groups` array, then sets individual impersonation headers on the request.

**What it does:**

1. Reads `X-Auth-Request-Email` and sets it as `Impersonate-User`
2. Reads `Authorization: Bearer <id_token>` (or a compact JWT with no
   prefix), decodes the payload, and adds each string in the `groups` claim
   as a separate `Impersonate-Group` header. The signature is not checked;
   oauth2-proxy already verified the token. The header is removed afterward
   so the JWT is not proxied.
3. Drops groups prefixed with `system:` except the exact group
   `system:authenticated`, and drops `kubeadm:cluster-admins`,
   `cluster-admins`, and `dedicated-admins`. A dropped group does not fail
   the request. `System:masters` is kept, because Kubernetes treats it as a
   different group from `system:masters`.
4. Appends `system:authenticated` (configurable via `always_include`). A
   group that is already present is not added again. An `always_include`
   entry the denylist would drop is rejected when Caddy loads the config.
5. Returns 401 when the token header is missing, the value is not a compact
   JWT, the payload is not a JSON object, or the group claim is present but
   is not an array of non-empty strings. A missing claim or JSON `null`
   means no groups from the token.

`token_groups off` skips the ID token. The handler still copies the user,
deletes any client-supplied group headers, and sends only `always_include`.
It does not read `Authorization`. `source_id_token` and `groups_claim` cannot
be set in that mode. `source_groups` and `separator` are rejected at load
time.

#### Caddyfile syntax

```caddyfile
impersonate [<options>]
```

With defaults (Kubernetes API impersonation):

```caddyfile
route {
    forward_auth 127.0.0.1:6000 {
        uri /oauth2/auth
        copy_headers X-Auth-Request-Email Authorization
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
        copy_headers X-Auth-Request-Email Authorization
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
| `source_id_token` | `Authorization` | Header containing the ID token. Ignored when `token_groups` is `off` |
| `groups_claim` | `groups` | JWT claim holding a JSON array of group names. Ignored when `token_groups` is `off` |
| `target_user` | `Impersonate-User` | Header name to set for the user |
| `target_group` | `Impersonate-Group` | Header name to add for each group |
| `always_include` | `system:authenticated` | Groups always appended (space-separated list) |
| `token_groups` | `on` | `off` skips the ID token and sends only `always_include` |

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

        # Optional file — use empty default when file doesn't exist
        cache watson_auth /mnt/watson-config/BASIC_AUTH {
            default ""
        }

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

#### Cache entry options

Each `cache` entry can optionally include a sub-block:

```caddyfile
cache <name> <path> {
    default <value>    # use <value> when file doesn't exist
    required           # fail startup if file is missing (default behavior)
}
```

| Option | Description |
|--------|-------------|
| `default` | Value to use when the file doesn't exist. If the file later appears, it is picked up automatically. If the file disappears again, the default is restored. |
| `required` | Fail Caddy startup if the file is missing. This is the default behavior when no sub-block is specified. |

This is useful for optional Kubernetes Secrets mounted with `optional: true`.
When the Secret doesn't exist, the mount point is an empty directory and the
cached file is absent — using `default` prevents Caddy from crashing on startup.

---

## Installation

Published image for Konflux UI: `quay.io/konflux-ci/reverse-proxy:latest` (Makefile `IMG` default).
Build from this repo: [Building](#building).

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
