MISE := ./scripts/mise-exec.sh
GO := $(MISE) go
GOFUMPT := $(MISE) gofumpt
GOLANGCI_LINT := $(MISE) golangci-lint
PRE_COMMIT := $(MISE) pre-commit

.PHONY: help
help: ## Displays this help menu
	@awk 'BEGIN {FS = ":.##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[0-9a-zA-Z_-]+:.?##/ \
  { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: setup
setup: ## Sets up your local development environment
	@echo "Setting up pre-commit hooks..."
	@$(PRE_COMMIT) install # install pre-commit hooks
	@$(PRE_COMMIT) install --hook-type commit-msg # needed to enforce conventional commits
	@echo "Setup complete!"

.PHONY: tidy
tidy: ## Adds missing and removes unused modules
	@echo "Cleaning up your go.mod and go.sum files..."
	@$(GO) mod tidy
	@$(GO) mod vendor

.PHONY: fmt
fmt: ## Formats your code
	@echo "Formatting your code..."
	@find . -name '*.go' -exec $(GOFUMPT) -l -w {} \;

.PHONY: lint
lint: ## Lints your code
	@echo "Linting your code..."
	@$(GOLANGCI_LINT) run -v ./...

.PHONY: test
test: ## Runs your unit tests and generates HTML coverage report
	@echo "Running your unit tests..."
	@$(GO) test -v ./... -coverprofile=coverage.out
	@echo "Generating test coverage report..."
	@$(GO) tool cover -html=coverage.out -o coverage.html

.PHONY: build
build: ## Builds your application binaries
	@echo "Building your application binaries..."
	@$(GO) build -o bin/policy-scout

.PHONY: validate
validate: setup tidy fmt lint test build clean ## Validates your application

.PHONY: clean
clean: ## Cleans your local development environment
	@echo "Cleaning your local development environment..."
	@rm bin/policy-scout
