IMG ?= quay.io/konflux-ci/reverse-proxy:latest

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
CONTAINER_TOOL ?= $(shell (command -v docker >/dev/null 2>&1 && echo docker) || (command -v podman >/dev/null 2>&1 && echo podman) || echo docker)

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: fmt vet ## Run tests.
	go test $$(go list ./... | grep -v /cmd/) -coverprofile cover.out

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter.
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes.
	$(GOLANGCI_LINT) run --fix

##@ Build

.PHONY: build
build: fmt vet ## Build caddy binary.
	CGO_ENABLED=0 go build -o bin/caddy ./cmd/caddy

.PHONY: docker-build
docker-build: ## Build container image.
	$(CONTAINER_TOOL) build -f Containerfile -t $(IMG) .

.PHONY: docker-push
docker-push: ## Push container image.
	$(CONTAINER_TOOL) push $(IMG)

KIND_CLUSTER ?= konflux

.PHONY: kind-load
kind-load: docker-build ## Build and load image into a Kind cluster.
	dir=$$(mktemp -d) && \
	$(CONTAINER_TOOL) save $(IMG) -o $${dir}/reverse-proxy.tar && \
	kind load image-archive $${dir}/reverse-proxy.tar --name $(KIND_CLUSTER) && \
	rm -r $${dir}

PLATFORMS ?= linux/arm64,linux/amd64
.PHONY: docker-buildx
docker-buildx: ## Build and push multi-arch container image.
	$(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag $(IMG) -f Containerfile .

##@ Dependencies

PROJECT_ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
LOCALBIN ?= $(PROJECT_ROOT)bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

GOLANGCI_LINT_VERSION_FILE := $(PROJECT_ROOT).golangci-lint-version
ifeq ($(wildcard $(GOLANGCI_LINT_VERSION_FILE)),)
$(error Missing $(GOLANGCI_LINT_VERSION_FILE). It must live next to the Makefile.)
endif
GOLANGCI_LINT_VERSION ?= $(shell tr -d ' \r\n' < $(GOLANGCI_LINT_VERSION_FILE))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN) $(PROJECT_ROOT).golangci-lint-version
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef
