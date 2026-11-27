SHELL := /bin/bash
.DEFAULT_GOAL := help
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: help test lint docs-check hooks

help: ## List the documented targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: ## Run the project test suite
	"$(PYTHON)" -m pytest

lint: ## Check Python and Bash syntax without importing the application
	"$(PYTHON)" scripts/lint.py

docs-check: ## Check local Markdown links and image paths outside docs/archive/
	"$(PYTHON)" scripts/check_docs.py

hooks: ## Enable pre-commit lint and Markdown link checks
	git config --local core.hooksPath .githooks
	@echo "Enabled .githooks: 'git commit' runs scripts/checks.sh."
