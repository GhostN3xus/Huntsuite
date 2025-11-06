# HuntSuite Makefile
.DEFAULT_GOAL := help

# Variables
BINARY_NAME=huntsuite
BUILD_DIR=./build
INSTALL_PATH=/usr/local/bin
GO_FILES=$(shell find . -name '*.go' -type f -not -path "./third_party/*")
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -s -w"

.PHONY: help
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/huntsuite
	@echo "✓ Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

.PHONY: install
install: build ## Install to system (requires sudo)
	@echo "Installing $(BINARY_NAME) to $(INSTALL_PATH)..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_PATH)/
	@sudo chmod +x $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "✓ Installed to $(INSTALL_PATH)/$(BINARY_NAME)"
	@echo "You can now run: $(BINARY_NAME)"

.PHONY: uninstall
uninstall: ## Uninstall from system (requires sudo)
	@echo "Uninstalling $(BINARY_NAME)..."
	@sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "✓ Uninstalled"

.PHONY: test
test: ## Run all tests
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.out ./...
	@echo "✓ Tests complete"

.PHONY: test-coverage
test-coverage: test ## Run tests with coverage report
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report generated: coverage.html"

.PHONY: lint
lint: ## Run linters
	@echo "Running linters..."
	@go fmt ./...
	@go vet ./...
	@echo "✓ Linting complete"

.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html
	@echo "✓ Clean complete"

.PHONY: dev
dev: clean build ## Build for development
	@echo "✓ Development build ready"
	@$(BUILD_DIR)/$(BINARY_NAME) --help

.PHONY: deps
deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy
	@echo "✓ Dependencies downloaded"

.PHONY: run
run: build ## Build and run with example
	@echo "Running $(BINARY_NAME)..."
	@$(BUILD_DIR)/$(BINARY_NAME)

.PHONY: all
all: clean deps lint test build ## Run all checks and build
