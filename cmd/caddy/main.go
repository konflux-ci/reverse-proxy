// Custom Caddy build with Konflux plugins.
//
// Build instructions (no xcaddy needed):
//  1. From the repo root: go build -o caddy ./cmd/caddy
//  2. ./caddy list-modules | grep -E 'impersonate|certwatcher|file_watcher'
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/konflux-ci/reverse-proxy/certwatcher"
	_ "github.com/konflux-ci/reverse-proxy/filewatcher"
	_ "github.com/konflux-ci/reverse-proxy/impersonate"
)

func main() {
	caddycmd.Main()
}
