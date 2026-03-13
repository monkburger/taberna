# ---------------------------------------------------------------------------
# Taberna — Makefile
# ---------------------------------------------------------------------------

# ---- Project ---------------------------------------------------------------
MODULE      := github.com/monkburger/taberna
BINARY      := taberna
CMD         := ./cmd/taberna
BUILD_DIR   := dist

# ---- Go toolchain ----------------------------------------------------------
GO          := go
GOFLAGS     ?=
GOOS        ?= $(shell $(GO) env GOOS)
GOARCH      ?= $(shell $(GO) env GOARCH)

# ---- Version / build stamp -------------------------------------------------
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
               -X main.version=$(VERSION) \
               -X main.buildTime=$(BUILD_DATE)

# ---- Tool versions ---------------------------------------------------------
GOLANGCI_VERSION    := v2.11.3
STATICCHECK_VERSION := latest
GOVULNCHECK_VERSION := latest

# ---- Local tool cache ------------------------------------------------------
TOOLS_DIR   := $(CURDIR)/.tools
TOOLS_BIN   := $(TOOLS_DIR)/bin
export PATH := $(TOOLS_BIN):$(PATH)

# ---------------------------------------------------------------------------
# Default target
# ---------------------------------------------------------------------------
.DEFAULT_GOAL := build

# ---------------------------------------------------------------------------
# Phony declarations
# ---------------------------------------------------------------------------
.PHONY: all build static release build-all clean test test-v test-race test-cover cover bench \
        fmt fmt-check vet lint staticcheck vulncheck \
	tidy verify check mod-verify \
        install uninstall setcap \
        help tools

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

## build: Compile the binary for the host OS/arch.
build:
	@echo "» Building $(BINARY) $(VERSION)"
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) \
		-ldflags "$(LDFLAGS)" \
		-trimpath \
		-o $(BINARY) \
		$(CMD)
	@cp $(BINARY) $(BUILD_DIR)/$(BINARY)
	@echo "  output: $(BINARY)"
	@echo "  copy:   $(BUILD_DIR)/$(BINARY)"

## static: Compile a fully static, CGO-disabled binary (production/embedded).
static:
	@echo "» Building $(BINARY) $(VERSION) [static]"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) \
		-ldflags "$(LDFLAGS)" \
		-trimpath \
		-o $(BINARY) \
		$(CMD)
	@cp $(BINARY) $(BUILD_DIR)/$(BINARY)
	@echo "  output: $(BINARY)"
	@echo "  copy:   $(BUILD_DIR)/$(BINARY)"

## release: Build a static binary named with version and host OS/arch.
release:
	@mkdir -p $(BUILD_DIR)
	@out=$(BUILD_DIR)/$(BINARY)-$(VERSION)-$(GOOS)-$(GOARCH); \
		echo "» Building $$out"; \
		CGO_ENABLED=0 $(GO) build $(GOFLAGS) \
			-ldflags "$(LDFLAGS)" \
			-trimpath \
			-o $$out \
			$(CMD); \
		echo "  output: $$out"

## build-all: Cross-compile common release targets.
build-all:
	@for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 freebsd/amd64 freebsd/arm64 openbsd/amd64; do \
		os=$$(echo $$target | cut -d/ -f1); \
		arch=$$(echo $$target | cut -d/ -f2); \
		out=$(BUILD_DIR)/$(BINARY)-$$os-$$arch; \
		echo "» Building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build $(GOFLAGS) \
			-ldflags "$(LDFLAGS)" \
			-trimpath \
			-o $$out \
			$(CMD); \
	done

## install: Install binary to GOPATH/bin (or $$GOBIN).
install:
	$(GO) install -ldflags "$(LDFLAGS)" -trimpath $(CMD)

## uninstall: Remove binary from GOPATH/bin.
uninstall:
	@rm -f $$($(GO) env GOPATH)/bin/$(BINARY)

## setcap: Grant the binary permission to bind ports <1024 without root.
setcap:
	sudo setcap cap_net_bind_service=+ep $(BINARY)

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------

## test: Run all tests.
test:
	$(GO) test $(GOFLAGS) ./...

## test-v: Run all tests with verbose output.
test-v:
	$(GO) test -v $(GOFLAGS) ./...

## test-race: Run tests with the race detector.
test-race:
	$(GO) test -race $(GOFLAGS) ./...

## test-cover: Run tests and produce an HTML coverage report (dist/cover.html).
test-cover:
	@mkdir -p $(BUILD_DIR)
	$(GO) test -race -coverprofile=$(BUILD_DIR)/cover.out -covermode=atomic ./...
	$(GO) tool cover -html=$(BUILD_DIR)/cover.out -o $(BUILD_DIR)/cover.html
	@echo "  coverage report: $(BUILD_DIR)/cover.html"

## cover: Alias for test-cover.
cover: test-cover

## bench: Run benchmarks.
bench:
	$(GO) test -run='^$$' -bench=. -benchmem ./...

# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

## fmt: Format all Go source files with gofmt.
fmt:
	@echo "» gofmt"
	@gofmt -l -w $$(find . -name '*.go' -not -path './vendor/*')

## fmt-check: Fail if any file is not gofmt-formatted (CI use).
fmt-check:
	@echo "» gofmt (check)"
	@unformatted=$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*')); \
	if [ -n "$$unformatted" ]; then \
		echo "ERROR: the following files need gofmt:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo "  all files are formatted"

# ---------------------------------------------------------------------------
# Static analysis
# ---------------------------------------------------------------------------

## vet: Run go vet on all packages.
vet:
	@echo "» go vet"
	$(GO) vet ./...

## lint: Run golangci-lint (installs it on first use).
lint: $(TOOLS_BIN)/golangci-lint
	@echo "» golangci-lint"
	$(TOOLS_BIN)/golangci-lint run ./...

## staticcheck: Run staticcheck (installs it on first use).
staticcheck: $(TOOLS_BIN)/staticcheck
	@echo "» staticcheck"
	$(TOOLS_BIN)/staticcheck ./...

## vulncheck: Check for known vulnerabilities in dependencies.
vulncheck: $(TOOLS_BIN)/govulncheck
	@echo "» govulncheck"
	$(TOOLS_BIN)/govulncheck ./...

# ---------------------------------------------------------------------------
# Module hygiene
# ---------------------------------------------------------------------------

## tidy: Tidy go.mod and go.sum.
tidy:
	@echo "» go mod tidy"
	$(GO) mod tidy

## mod-verify: Verify dependency checksums match go.sum.
mod-verify:
	@echo "» go mod verify"
	$(GO) mod verify

## verify: Run fmt-check, vet, lint, staticcheck, test-race, mod-verify.
##         Full CI gate — all checks must pass.
verify: fmt-check vet lint staticcheck test-race mod-verify
	@echo ""
	@echo "✓ All checks passed"

## check: Alias for verify.
check: verify

# ---------------------------------------------------------------------------
# Tool installation (into .tools/bin — never pollutes the module)
# ---------------------------------------------------------------------------
tools: $(TOOLS_BIN)/golangci-lint $(TOOLS_BIN)/staticcheck $(TOOLS_BIN)/govulncheck

$(TOOLS_DIR):
	@mkdir -p $(TOOLS_BIN)

$(TOOLS_BIN)/golangci-lint: $(TOOLS_DIR)
	@echo "» Installing golangci-lint $(GOLANGCI_VERSION)"
	curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b $(TOOLS_BIN) $(GOLANGCI_VERSION)

$(TOOLS_BIN)/staticcheck: $(TOOLS_DIR)
	@echo "» Installing staticcheck $(STATICCHECK_VERSION)"
	GOBIN=$(TOOLS_BIN) $(GO) install \
		honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)

$(TOOLS_BIN)/govulncheck: $(TOOLS_DIR)
	@echo "» Installing govulncheck $(GOVULNCHECK_VERSION)"
	GOBIN=$(TOOLS_BIN) $(GO) install \
		golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

## clean: Remove build output and tool cache.
clean:
	@echo "» Cleaning"
	@rm -rf $(BUILD_DIR) $(TOOLS_DIR) $(BINARY)

# ---------------------------------------------------------------------------
# Help — auto-generated from ## comments
# ---------------------------------------------------------------------------

## help: Print this help message.
help:
	@echo "Usage: make [target]"
	@echo ""
	@grep -E '^## [a-zA-Z_-]+:' $(MAKEFILE_LIST) \
		| sed 's/^## //' \
		| awk -F': ' '{ printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }'
