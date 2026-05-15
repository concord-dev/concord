SHELL := /bin/bash
BIN   := bin/concord

# Local dev defaults — override on the command line:  make dev DATABASE_URL=...
DATABASE_URL ?= postgres://concord:concord-dev@localhost:5432/concord?sslmode=disable
CONCORD_OPERATOR_TOKEN ?= dev-admin-token
LISTEN_ADDR ?= :8080

.PHONY: tidy build server test lint check clean run dev pg pg-down pg-logs psql air-install help

help:
	@echo "Common targets:"
	@echo "  make pg          — start Postgres in docker-compose"
	@echo "  make pg-down     — stop Postgres"
	@echo "  make dev         — live-reload concord-server (needs air + pg)"
	@echo "  make build       — build the concord CLI"
	@echo "  make server      — build cmd/server (concord-server)"
	@echo "  make test        — full test sweep"
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

lint:
	go vet ./...

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
