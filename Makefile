# ╭──────────────────────────────────────────────────────────────────╮
# │  ┌●───●───●───●───●───●───●───●───●───●───●───●───●───●───●───┐  │
# │  │                                                            │  │
# │  ●   ██╗  ██╗    ██╗    ██╗                                   ●  │
# │  │   ██║  ██║    ██║    ██║           herbiewalker            │  │
# │  │   ███████║    ██║ █╗ ██║──●──●──●──┐                       │  │
# │  │   ██╔══██║    ██║███╗██║           │                       │  │
# │  ●   ██║  ██║    ╚███╔███╔╝           ●───⏣  code · tools     ●  │
# │  │   ╚═╝  ╚═╝     ╚══╝╚══╝                    homelab         │  │
# │  │                                                            │  │
# │  └●───●───●───●───●───●───●───●───●───●───●───●───●───●───●───┘  │
# ╰──────────────────────────────────────────────────────────────────╯
# Sanctum — dev tasks. `make check` runs everything CI runs that needs no Docker.
#
# Note: there is no `make` in Git Bash on Windows by default. This file is for
# CI and Linux; on the Windows dev box use `.\bootstrap.ps1`, which runs the
# same steps. See SETUP.md.

SHELL := /bin/bash
BIN   := bin/sanctum
PKG   := ./...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
IMAGE ?= sanctum:$(VERSION)

.DEFAULT_GOAL := check

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# --- build & test ------------------------------------------------------------

.PHONY: build
build: ## Compile to ./bin/
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/sanctum

.PHONY: test
test: ## Run the test suite
	go test -race $(PKG)

.PHONY: lint
lint: ## go vet + gofmt check
	go vet $(PKG)
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	@echo "lint OK"

.PHONY: tidy
tidy: ## Sync go.mod/go.sum
	go mod tidy

# --- constraint guards (CLAUDE.md hard constraints; principle 1) -------------
# Delegated to scripts/guards.sh so the Makefile, bootstrap.ps1 and CI all run
# the SAME check (principle 4). Do not reimplement a guard here — three copies
# of a guard is three chances to drift, and a drifted guard still shows green.

.PHONY: guards
guards: ## Run all constraint guards
	bash scripts/guards.sh all

.PHONY: guard-digest-pin
guard-digest-pin: ## Hard constraint 6 / N4: every FROM pinned by digest
	bash scripts/guards.sh digest-pin

.PHONY: guard-no-secrets
guard-no-secrets: ## Hard constraints 3+4: no key material or real backups tracked
	bash scripts/guards.sh no-secrets

.PHONY: guard-no-plaintext
guard-no-plaintext: ## Hard constraint 2 / N1: no plaintext outside tmpfs (real at M3)
	bash scripts/guards.sh no-plaintext

# --- container ---------------------------------------------------------------

.PHONY: image
image: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

.PHONY: image-checks
image-checks: image ## Assert the shipped image runs non-root
	@u=$$(docker inspect --format '{{.Config.User}}' $(IMAGE)); \
	if [ -z "$$u" ] || [ "$$u" = "root" ] || [ "$$u" = "0" ]; then \
	  echo "::error::image runs as root (hard constraint 6, N3)"; exit 1; \
	fi; \
	echo "image runs as $$u -- OK"

.PHONY: compose-check
compose-check: ## Validate compose interpolation, ports and limits
	docker compose config -q && echo "compose config OK"

# --- aggregate ---------------------------------------------------------------

.PHONY: check
check: lint test guards ## Everything CI runs that does not need Docker

.PHONY: clean
clean:
	rm -rf bin/

# ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
