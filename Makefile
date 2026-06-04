SHELL := /bin/bash
BIN   := bin/concord

# Local dev defaults — override on the command line:  make dev DATABASE_URL=...
DATABASE_URL ?= postgres://concord:concord-dev@localhost:5432/concord?sslmode=disable
CONCORD_OPERATOR_TOKEN ?= dev-admin-token
LISTEN_ADDR ?= :8080

# Analyzer binaries — installed into $(go env GOPATH)/bin by `make tools`.
GOPATH_BIN := $(shell go env GOPATH)/bin

.PHONY: tidy build server test test-race lint vet staticcheck deadcode vuln tools check clean run dev pg pg-down pg-logs psql air-install help

help:
	@echo "Common targets:"
	@echo "  make pg          — start Postgres in docker-compose"
	@echo "  make pg-down     — stop Postgres"
	@echo "  make dev         — live-reload concord-server (needs air + pg)"
	@echo "  make build       — build the concord CLI"
	@echo "  make server      — build cmd/server (concord-server)"
	@echo "  make test        — full test sweep"
	@echo "  make test-race   — full test sweep with the race detector"
	@echo "  make lint        — vet + staticcheck + deadcode (all must pass)"
	@echo "  make vuln        — govulncheck for stdlib + dependency CVEs"
	@echo "  make tools       — install staticcheck/deadcode/govulncheck"
	@echo "  make psql        — open psql against the dev DB"

tidy:
	go mod tidy

build:
	@mkdir -p bin
	go build -buildvcs=false -o $(BIN) ./cmd/concord

server:
	@mkdir -p bin
	go build -buildvcs=false -o bin/concord-server ./cmd/server

test:
	go test -buildvcs=false ./... -count=1

test-race:
	go test -buildvcs=false -race ./... -count=1

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
	./$(BIN) check --controls ./controls

clean:
	rm -rf bin tmp coverage.out build-errors.log

run: build
	./$(BIN) $(ARGS)

# ── Dev workflow ────────────────────────────────────────────────────

pg:
	docker compose up -d postgres
	@echo "Postgres up on localhost:5432 (db=concord user=concord)"

pg-down:
	docker compose down

pg-logs:
	docker compose logs -f postgres

psql:
	docker compose exec postgres psql -U concord -d concord

# Live-reload concord-server. Picks up changes to *.go / *.yaml / *.sql / *.rego.
# Press Ctrl-C to stop. Tail logs/<file>.log for the live-build errors.
dev: air-install
	@DATABASE_URL=$(DATABASE_URL) \
	 CONCORD_OPERATOR_TOKEN=$(CONCORD_OPERATOR_TOKEN) \
	 LISTEN_ADDR=$(LISTEN_ADDR) \
	 air -c .air.toml

# Idempotent: only installs air when the binary isn't already on PATH.
air-install:
	@command -v air >/dev/null 2>&1 || { \
		echo "Installing air@latest into $$(go env GOPATH)/bin …"; \
		go install github.com/air-verse/air@latest; \
	}
