SHELL := /bin/bash
BIN   := bin/concord

# Local dev defaults — override on the command line:  make dev DATABASE_URL=...
DATABASE_URL ?= postgres://concord:concord-dev@localhost:5432/concord?sslmode=disable
CONCORD_OPERATOR_TOKEN ?= dev-admin-token
LISTEN_ADDR ?= :8080

# Analyzer binaries — installed into $(go env GOPATH)/bin by `make tools`.
GOPATH_BIN := $(shell go env GOPATH)/bin

.PHONY: tidy build test test-integration test-race lint vet staticcheck deadcode vuln tools check clean run help

help:
	@echo "Common targets:"
	@echo "  make build              — build the concord CLI"
	@echo "  make test               — unit tests only (no backends needed)"
	@echo "  make test-integration   — unit + integration (spawn plugins, hit ghcr)"
	@echo "  make test-race          — full sweep with the race detector"
	@echo "  make lint               — vet + staticcheck + deadcode"
	@echo "  make vuln               — govulncheck for stdlib + dep CVEs"
	@echo "  make tools              — install staticcheck/deadcode/govulncheck"
	@echo ""
	@echo "Server + worker have moved to concord-dev/concord-platform."

tidy:
	go mod tidy

build:
	@mkdir -p bin
	go build -buildvcs=false -o $(BIN) ./cmd/concord
	go build -buildvcs=false -o bin/concord-admin ./cmd/concord-admin

test:
	go test -buildvcs=false ./... -count=1

test-integration:
	go test -buildvcs=false -tags integration ./... -count=1

test-race:
	go test -buildvcs=false -race -tags integration ./... -count=1

# ── Analyzers ───────────────────────────────────────────────────────
#
# `lint` is the umbrella every PR must pass. govulncheck is split into
# its own `vuln` target because it depends on the online vuln database
# and shouldn't block offline dev. Both run in CI.

vet:
	go vet ./...

staticcheck:
	$(GOPATH_BIN)/staticcheck ./...

deadcode:
	$(GOPATH_BIN)/deadcode -test ./...

lint: vet staticcheck deadcode
	@echo "✓ lint clean"

vuln:
	$(GOPATH_BIN)/govulncheck ./...

# Install the analyzer binaries. Versioned so a fresh clone gets a
# known-good set. Bumping these is a deliberate PR.
tools:
	go install honnef.co/go/tools/cmd/staticcheck@v0.7.0
	go install golang.org/x/tools/cmd/deadcode@v0.45.0
	go install golang.org/x/vuln/cmd/govulncheck@v1.3.0
	@echo "✓ analyzers installed into $(GOPATH_BIN)"

check: build
	./$(BIN) check --fixtures --controls testdata/smoke-pack

clean:
	rm -rf bin tmp coverage.out build-errors.log

run: build
	./$(BIN) $(ARGS)
