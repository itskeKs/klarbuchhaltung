SHELL := /bin/bash
.DEFAULT_GOAL := help
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: help test test-agent-rules lint docs-check hooks

help: ## List the documented targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: test-agent-rules ## Agent-rule contracts followed by the project test suite
	"$(PYTHON)" -m pytest

test-agent-rules: ## Paired rules, CLAUDE.md symlink and Codex hook contracts
	"$(PYTHON)" -B scripts/test_agent_rules.py

lint: ## Check Python and Bash syntax without importing the application
	"$(PYTHON)" scripts/lint.py

docs-check: ## Check local Markdown links and image paths outside docs/archive/
	"$(PYTHON)" scripts/check_docs.py

hooks: ## Enable pre-commit lint and Markdown link checks
	git config --local core.hooksPath .githooks
	@echo "Enabled .githooks: 'git commit' runs scripts/checks.sh."
