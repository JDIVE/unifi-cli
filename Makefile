PYTHON ?= python3
VERSION ?= $(shell $(PYTHON) -c "import pathlib, tomllib; print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['version'])")

.PHONY: install-dev format lint typecheck test check build install-local release-binaries clean

install-dev:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"

format:
	$(PYTHON) -m ruff format src tests

lint:
	$(PYTHON) -m ruff format --check src tests
	$(PYTHON) -m ruff check src tests

typecheck:
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest

check: lint typecheck test

build:
	$(PYTHON) -m build

install-local:
	@if command -v uv >/dev/null 2>&1; then \
		uv tool install --force --editable .; \
	else \
		$(PYTHON) -m pip install --user --upgrade .; \
	fi

release-binaries:
	./scripts/build-release-binaries.sh "v$(VERSION)" release

clean:
	rm -rf build dist release pyinstaller-build .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +
