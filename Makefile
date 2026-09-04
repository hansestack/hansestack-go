# ==============================================================================
# hansestack-go — official Go client library for the Hansestack API
# ==============================================================================

# ==============================================================================
# Phony declarations
# ==============================================================================
.PHONY: help test test-cover lint lint-fix vuln tidy verify clean

# ==============================================================================
# Default
# ==============================================================================
default: help

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-28s\033[0m %s\n", $$1, $$2}'

# ==============================================================================
# Test & Lint
# ==============================================================================
test: ## Run tests with race detector
	go test -v -race ./...

test-cover: ## Run tests and report coverage
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint: ## Run golangci-lint
	golangci-lint run ./...

lint-fix: ## Run golangci-lint with auto-fix
	golangci-lint run --fix ./...

vuln: ## Scan dependencies and stdlib for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

tidy: ## Tidy and verify module dependencies
	go mod tidy
	go mod verify

verify: tidy lint test ## Run the full local verification suite

# ==============================================================================
# Clean
# ==============================================================================
clean: ## Remove test and coverage artifacts
	rm -f coverage.out
	go clean -testcache
