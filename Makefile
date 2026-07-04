PYTHON ?= python3
VERSION ?= $(shell $(PYTHON) -c "import pathlib, re; print(re.search(r'__version__\s*=\s*\"([^\"]+)\"', pathlib.Path('src/unifi_cli/__init__.py').read_text()).group(1))")

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
