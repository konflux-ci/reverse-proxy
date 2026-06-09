---
name: testing-with-kind
description: Use when testing local changes to the reverse-proxy in a Kind cluster, iterating on plugin changes end-to-end, or when asked how to run e2e or integration tests against a real cluster.
---

# Testing with Kind

## Prerequisites

Two things must exist before any script will work:

1. **A running Kind cluster** named `konflux` — created by `konflux-ci`'s `deploy-local.sh`.
   > Cluster name source: `Makefile:61` — `KIND_CLUSTER ?= konflux`

2. **A checkout of `github.com/konflux-ci/konflux-ci`** as a sibling directory to this repo:
   ```
   parent/
     reverse-proxy/    ← this repo
     konflux-ci/       ← must exist here
   ```
   Or set `KONFLUX_CI_DIR=/path/to/konflux-ci` to override.
   > Source: `scripts/test-in-kind.sh:25` — `KONFLUX_CI_DIR="${KONFLUX_CI_DIR:-${REPO_ROOT}/../konflux-ci}"`

## Two-script workflow

There are two scripts with different purposes. Use the wrong one and you waste time.

| Script | When to run | What it does |
|---|---|---|
| `scripts/test-in-kind.sh` | **First time only** (or after operator changes) | Builds image, loads into Kind, applies operator overrides so the cluster uses your local image instead of `quay.io/konflux-ci/reverse-proxy` |
| `scripts/reload-in-kind.sh` | **Every subsequent iteration** | Rebuilds and reloads the image, then restarts the deployment — no operator changes |

> Source: `scripts/reload-in-kind.sh:6-8` — "This is the fast inner-loop companion to test-in-kind.sh. Run test-in-kind.sh first to apply operator overrides, then use this script for subsequent iterations."

## First-time setup

```bash
./scripts/test-in-kind.sh
```

The script:
1. Runs `make kind-load IMG=... KIND_CLUSTER=...` — builds the container image and loads it into the `konflux` cluster.
   > Source: `scripts/test-in-kind.sh:43`, `Makefile:64-68`
2. Applies operator overrides — patches the operator so `quay.io/konflux-ci/reverse-proxy` → `localhost/konflux-ci/reverse-proxy:local`.
   > Source: `scripts/test-in-kind.sh:45-61`
3. **Does NOT restart the operator.** After the script finishes, you must do this yourself:
   ```bash
   cd <konflux-ci>/operator && make run
   ```
   > Source: `scripts/test-in-kind.sh:63-64` — script prints this as the final log lines

## Fast iteration (after first-time setup)

```bash
./scripts/reload-in-kind.sh
```

This rebuilds the image, reloads it, then runs:
```bash
kubectl rollout restart deployment/proxy -n konflux-ui
kubectl rollout status deployment/proxy -n konflux-ui --timeout=120s
```
> Source: `scripts/reload-in-kind.sh:31-32` — namespace `konflux-ui` (`:20`), deployment `proxy` (`:21`)

## Overridable environment variables

| Variable | Default | Source |
|---|---|---|
| `IMG` | `localhost/konflux-ci/reverse-proxy:local` | `scripts/reload-in-kind.sh:18` |
| `KIND_CLUSTER` | `konflux` | `scripts/reload-in-kind.sh:19` |
| `NAMESPACE` | `konflux-ui` | `scripts/reload-in-kind.sh:20` |
| `DEPLOYMENT` | `proxy` | `scripts/reload-in-kind.sh:21` |
| `KONFLUX_CI_DIR` | `${REPO_ROOT}/../konflux-ci` | `scripts/test-in-kind.sh:25` |

## Common mistakes

- **Running `reload-in-kind.sh` before `test-in-kind.sh`** — the deployment restarts but still uses the upstream image, not your local build. Run `test-in-kind.sh` first.
- **Forgetting `make run` in the operator** — the script ends with a reminder but does not do it. The proxy won't pick up the override until the operator runs.
- **Wrong cluster name** — if your Kind cluster isn't named `konflux`, set `KIND_CLUSTER=<your-name>` before running either script.
