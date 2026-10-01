# NetHole-Tester Makefile
# Pure-Go, static, cross-compiled single binary. No external runtime required.

BINARY   := nethole
PKG      := ./cmd/nethole
DIST     := dist
BIN      := bin

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
GCFLAGS  := -trimpath

.PHONY: all build test test-net vet fmt tidy clean run quick report dist release help

all: build

## build: native binary for the current platform
build:
	@mkdir -p $(BIN)
	CGO_ENABLED=0 go build $(GCFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN)/$(BINARY) $(PKG)
	@echo "built $(BIN)/$(BINARY) ($(VERSION))"

## test: fast unit tests (no network)
test:
	go test ./...

## test-net: include live network tests (hits 1.1.1.1 etc.)
test-net:
	go test -v ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

tidy:
	go mod tidy

run: build
	./$(BIN)/$(BINARY) run --preset=dorm --duration=30s

quick: build
	./$(BIN)/$(BINARY)

report: build
	./$(BIN)/$(BINARY) report --in=./nethole-out --complaint

## dist: cross-compile static binaries for every supported target
dist: clean
	@mkdir -p $(DIST)
	@set -e; for t in \
		linux/amd64 linux/arm64 linux/arm/7 \
		darwin/amd64 darwin/arm64 \
		windows/amd64 ; do \
		os=$${t%%/*}; rest=$${t#*/}; arch=$${rest%%/*}; arm=""; \
		if [ "$$rest" != "$$arch" ]; then arm="$${rest#*/}"; fi; \
		out=$(DIST)/$(BINARY)-$$os-$$arch$${arm:+-v$$arm}; \
		[ "$$os" = "windows" ] && out=$$out.exe; \
		echo "  -> $$out"; \
		env CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOARM=$$arm \
			go build $(GCFLAGS) -ldflags "$(LDFLAGS)" -o $$out $(PKG); \
	done
	@echo "creating checksums..."
	@cd $(DIST) && (command -v sha256sum >/dev/null 2>&1 && sha256sum * > SHA256SUMS || shasum -a 256 * > SHA256SUMS)
	@echo "done -> $(DIST)/"

## release: dist + git tag reminder
release: dist
	@echo "Artifacts in $(DIST)/. Tag with: git tag -a v$(VERSION) -m 'v$(VERSION)' && git push --tags"

clean:
	rm -rf $(BIN) $(DIST)

help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
