PYTHON ?= python3

.PHONY: help install-dev lint type test conformance security package-check check

help:
	@echo "install-dev    Install the project and bounded development toolchain"
	@echo "lint           Run Ruff lint and format checks"
	@echo "type           Run strict mypy checks"
	@echo "test           Run tests with branch coverage"
	@echo "conformance    Verify all contract fixtures and the AtlasBridge chain"
	@echo "security       Run source and dependency security checks"
	@echo "package-check  Build and validate wheel and source distribution"
	@echo "check          Run every local quality and packaging gate"

install-dev:
	$(PYTHON) -m pip install 'pip>=26.1.2,<27'
	$(PYTHON) -m pip install 'setuptools>=83,<84' 'wheel>=0.45,<1'
	$(PYTHON) -m pip install -e '.[dev]'

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

type:
	$(PYTHON) -m mypy src

test:
	$(PYTHON) -m pytest

conformance:
	$(PYTHON) -m transformation_portfolio_contracts.cli verify-conformance --json
	$(PYTHON) -m transformation_portfolio_contracts.cli verify-example --json

security:
	$(PYTHON) -m bandit -q -r src setup.py
	$(PYTHON) -m pip_audit --local --skip-editable --cache-dir .pip-audit-cache

package-check:
	$(PYTHON) -m build
	$(PYTHON) -m twine check dist/*

check: lint type test conformance security package-check
