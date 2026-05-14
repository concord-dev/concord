SHELL := /bin/bash
BIN   := bin/concord

.PHONY: tidy build test lint check clean run

tidy:
	go mod tidy

build:
	@mkdir -p bin
	go build -buildvcs=false -o $(BIN) ./cmd/concord

test:
	go test -buildvcs=false ./... -count=1

lint:
	go vet ./...

check: build
	./$(BIN) check --controls ./controls

clean:
	rm -rf bin coverage.out

run: build
	./$(BIN) $(ARGS)
