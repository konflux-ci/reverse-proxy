# AGENTS.md — Konflux Reverse Proxy

## What This Repo Is

A custom [Caddy](https://caddyserver.com/) build with three plugins for the
[Konflux](https://github.com/konflux-ci/konflux-ci) UI proxy. It sits between
the browser and the Kubernetes API server, translating OAuth2 authentication
headers into Kubernetes impersonation headers.

The core problem: `oauth2-proxy` returns groups in a single comma-separated
`X-Auth-Request-Groups` header, but Kubernetes requires each group as a
**separate** `Impersonate-Group` header. Stock Caddy cannot do this.

## Repository Layout

```
cmd/caddy/          Entry point — registers plugins, calls caddycmd.Main()
impersonate/        Plugin: splits auth headers → K8s impersonation headers
certwatcher/        Plugin: watches TLS certs on disk, rotates without reload
filewatcher/        Plugin: watches dirs (SIGUSR1 reload) + caches file content
scripts/            Helper scripts for Kind cluster testing
.tekton/            Tekton CI/CD pipelines (Konflux build system)
.github/workflows/  GitHub Actions (lint, test, fullsend)
Containerfile       Multi-stage OCI image build
Makefile            Build, test, lint targets
```

## Architecture

Three plugins handle dynamic file content that rotates at different frequencies:

| What changes     | Frequency       | Plugin        | Mechanism                        |
|------------------|-----------------|---------------|----------------------------------|
| Bearer tokens    | Every 600s      | `filewatcher` | atomic cache + `inject_cached_vars` |
| Serving TLS cert | Every 60–90 days| `certwatcher` | `get_certificate` module         |
| CA trust bundles | Rare (months)   | `filewatcher` | fsnotify + SIGUSR1               |

All plugins use `atomic.Pointer` for zero-allocation, zero-syscall per-request
reads. Files are updated via fsnotify with periodic poll fallbacks for
Kubernetes symlink rotations.

## Plugin Details

### impersonate (`http.handlers.impersonate`)

- Source: `impersonate/impersonate.go` (~240 lines)
- Reads `X-Auth-Request-Email` → sets `Impersonate-User`
- Reads `X-Auth-Request-Groups` (comma-separated) → splits into separate
  `Impersonate-Group` headers
- Always appends `system:authenticated` (configurable)
- Supports custom source/target headers and separators
- Caddy interfaces: `caddy.Provisioner`, `caddyhttp.MiddlewareHandler`,
  `caddyfile.Unmarshaler`

### certwatcher (`tls.get_certificate.file`)

- Source: `certwatcher/certwatcher.go` (~380 lines)
- Watches cert+key files via fsnotify, reloads on change with debounce
- Serves latest cert during TLS handshake from `atomic.Pointer`
- Poll fallback for missed fsnotify events
- Caddy interfaces: `caddy.Provisioner`, `caddy.CleanerUpper`

### filewatcher (`file_watcher`)

- Source: `filewatcher/filewatcher.go` (~485 lines)
- Two behaviors:
  1. **Watch directories**: sends SIGUSR1 on changes → config reload
  2. **Cache files**: reads into `atomic.Pointer[string]`, updated via fsnotify
- Companion middleware `inject_cached_vars` sets `{http.vars.*}` from cache
- Caddy interfaces: `caddy.App` (Start/Stop), `caddy.Provisioner`

## Skills

Repo-specific skills live in `skills/` and are symlinked into `.claude/skills/`
for Claude Code discovery.

| Skill | Path | When to use |
|-------|------|-------------|
| testing-with-kind | `skills/testing-with-kind/SKILL.md` | Testing local changes in a Kind cluster, iterating on plugin changes end-to-end |

## Build & Run

```bash
# Build (runs fmt + vet first)
make build              # output: bin/caddy

# Build container image
make docker-build       # uses Containerfile

# Multi-arch container build
make docker-buildx      # linux/arm64, linux/amd64

# Verify plugins registered
./bin/caddy list-modules | grep -E 'impersonate|certwatcher|file_watcher'
```

The build is a standard Go build — no `xcaddy` required. `cmd/caddy/main.go`
imports plugins via blank imports; each plugin self-registers in `init()`.

Container: multi-stage build using Red Hat UBI Go builder → UBI static runtime
(no shell, no package manager). Runs as non-root user 1001.

## Testing

```bash
# Run all tests with coverage (excludes cmd/)
make test

# Run tests directly
go test ./...

# Run a specific package's tests
go test ./impersonate/...
go test ./certwatcher/...
go test ./filewatcher/...
```

### Test framework

- **Ginkgo v2** (BDD) + **Gomega** (assertions)
- Unit tests: `*_test.go` in each package
- Functional tests: `functional_test.go` — end-to-end with real Caddy servers
- Integration tests: `filewatcher/integration_test.go`
- Kind cluster tests: `scripts/test-in-kind.sh`

### Test patterns used in this repo

- `gomega.NewWithT(t)` for scoped assertions (not global `Expect`)
- Helper functions like `provision(t, h)` and `serve(t, h, r)` to reduce boilerplate
- `httptest.NewRequest` + `httptest.NewRecorder` for HTTP handler tests
- `captureNext` pattern: a fake `caddyhttp.Handler` that captures request state
  after middleware runs, used to verify header modifications

### When writing new tests

- Use the same `gomega.NewWithT(t)` pattern, not raw `if` checks
- Test both the happy path and edge cases (empty values, whitespace, pre-existing headers)
- For middleware, use the `captureNext` pattern to inspect the request after processing
- Functional tests should start a real Caddy instance using `caddytest`

## Linting

```bash
make lint               # runs golangci-lint
make lint-fix           # runs golangci-lint with --fix
```

- golangci-lint v2 — version pinned in `.golangci-lint-version`
- Config: `.golangci.yml`
- Key enabled linters: `errcheck`, `staticcheck`, `govet`, `revive`,
  `gocyclo`, `dupl`, `lll`, `misspell`, `unused`, `unparam`
- Formatters: `gofmt`, `goimports`

## CI Pipelines

### GitHub Actions

| Workflow     | Trigger                        | What it does                  |
|--------------|-------------------------------|-------------------------------|
| `lint.yaml`  | PRs, merge_group              | golangci-lint                 |
| `test.yaml`  | Push to main, PRs, merge_group| `make test` + CodeCov upload  |

### Tekton (Konflux)

- `reverse-proxy-push.yaml` — triggered on push to main, builds multi-arch
  image, runs security scans (Clair, Snyk, ClamAV, shell-check)
- `reverse-proxy-pull-request.yaml` — triggered on PRs, same pipeline with
  5-day image expiry

## Code Conventions

### Go style

- Go 1.25+ (check `go.mod` for exact version)
- `CGO_ENABLED=0` — static binaries, no C dependencies
- All plugins follow the Caddy module pattern:
  1. Define a struct with JSON tags
  2. `init()` → `caddy.RegisterModule()` + directive registration
  3. `CaddyModule()` returns `caddy.ModuleInfo`
  4. `Provision()` sets defaults
  5. `UnmarshalCaddyfile()` parses Caddyfile syntax
  6. Interface compliance vars at bottom: `var _ Interface = (*Type)(nil)`
- Use `go.uber.org/zap` for logging (via `caddy.Context.Logger()`)
- Use `atomic.Pointer` for concurrent state shared between goroutines
- Use `github.com/fsnotify/fsnotify` for file system watching

### What NOT to do

- Do not add `xcaddy` — this repo uses direct Go builds
- Do not import plugins outside of `cmd/caddy/main.go`
- Do not use `sync.Mutex` where `atomic.Pointer` suffices — the existing
  plugins are optimized for zero-allocation per-request hot paths
- Do not add indirect Go dependency updates (controlled by renovate.json)
- Do not modify `.tekton/` pipelines without understanding Konflux conventions

### Dependency management

- Direct deps managed via `go.mod`
- Automated updates via Renovate (config: `renovate.json`)
- Indirect deps are NOT auto-updated
- Run `go mod tidy -diff` to verify go.sum (CI checks this)

## Adding a New Plugin

1. Create a new package directory at the repo root (e.g., `myplugin/`)
2. Implement the Caddy module interfaces (see existing plugins for patterns)
3. Add a blank import in `cmd/caddy/main.go`:
   ```go
   _ "github.com/konflux-ci/reverse-proxy/myplugin"
   ```
4. Write tests using Ginkgo/Gomega following existing test patterns
5. Run `make build && make test && make lint`

## Common Tasks

### Fix a bug in a plugin

| Plugin        | Source file              | Key entry points                                            |
|---------------|--------------------------|-------------------------------------------------------------|
| impersonate   | `impersonate/impersonate.go` | `ServeHTTP` (hot path)                                  |
| filewatcher   | `filewatcher/filewatcher.go` | `Start()`, `poll()`, `handleEvent()`                    |
| certwatcher   | `certwatcher/certwatcher.go` | `loadCertificate()`, `GetCertificate()` (atomic.Pointer)|

1. Read the source file — focus on the entry points listed above
2. Write a failing test in the package's `*_test.go` (use `integration_test.go`
   for real filesystem tests in filewatcher)
3. Fix the bug
4. Run `make test && make lint`

### Update a dependency

```bash
go get <package>@<version>
go mod tidy
make test
```

## Troubleshooting

### Tests fail with "no required module provides package"

Run `go mod tidy` — the `go.sum` may be out of sync.

### Lint fails on line length

The `lll` linter enforces line length limits. Break long lines or restructure.

### Container build fails

Check that the base image digests in `Containerfile` are reachable. The builder
and runtime images are pinned by digest and updated by Renovate/MintMaker.
