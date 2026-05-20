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

## Building

No `xcaddy` required. The build follows the
[standard Caddy plugin workflow](https://github.com/caddyserver/caddy/blob/master/cmd/caddy/main.go):

```bash
go build -o caddy ./cmd/caddy
./caddy list-modules | grep impersonate
# http.handlers.impersonate
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
