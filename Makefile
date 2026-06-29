.PHONY: install install-hooks lint typecheck test check build clean man

lint:
	ruff check src/
	ruff format --check src/

typecheck:
	mypy src/

install:
	uv sync --dev

install-hooks: install
	uv run pre-commit install

test:
	uv run pytest

check: lint typecheck test

build:
	uv build

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage

man:
	@command -v pandoc >/dev/null 2>&1 || { echo "Error: pandoc is not installed."; echo "Install with: brew install pandoc (macOS) or apt-get install pandoc (Linux)"; exit 1; }
	pandoc --standalone --to=man docs/man/pkgd.1.md -o docs/man/pkgd.1
	mandoc -Tlint docs/man/pkgd.1
	@echo "OK: docs/man/pkgd.1 regenerated and lint-clean"
