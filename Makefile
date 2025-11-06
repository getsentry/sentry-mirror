
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

# Help

help: ## this help
	@ awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m\t%s\n", $$1, $$2 }' $(MAKEFILE_LIST) | column -s$$'\t' -t
.PHONY: help
