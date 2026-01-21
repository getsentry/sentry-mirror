
test: ## Run tests
	cargo test
.PHONY: test

# Builds

build: ## Build all features without debug symbols
	cargo build --all-features
.PHONY: build

release: ## Build a release profile with all features
	cargo build --all-features --release
.PHONY: release

# Formatting and linting

style: ## Run style checking tools (cargo-fmt)
	@rustup component add rustfmt 2> /dev/null
	cargo fmt --all --check
.PHONY: style

lint: ## Run linting tools (cargo-clippy)
	@rustup component add clippy 2> /dev/null
	cargo clippy --workspace --all-targets --all-features --no-deps -- -D warnings
.PHONY: lint

format: ## Run autofix mode for formatting and lint
	@rustup component add clippy 2> /dev/null
	@rustup component add rustfmt 2> /dev/null
	cargo fmt --all
	cargo clippy --workspace --all-targets --all-features --no-deps --fix --allow-dirty --allow-staged -- -D warnings
.PHONY: format

# Python / Integration Tests

.venv: ## Create a Python virtual environment using uv
	uv venv .venv
.PHONY: .venv

install-python: .venv ## Install Python dependencies using uv
	uv pip install -e .
.PHONY: install-python

test-integration: ## Run integration tests
	. .venv/bin/activate && pytest tests/test_integration.py -v
.PHONY: test-integration

test-all: test test-integration ## Run all tests (unit and integration)
.PHONY: test-all

clean-python: ## Clean Python artifacts and logs
	rm -rf .venv tests/logs/*.log
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
.PHONY: clean-python

# Help

help: ## this help
	@ awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m\t%s\n", $$1, $$2 }' $(MAKEFILE_LIST) | column -s$$'\t' -t
.PHONY: help
