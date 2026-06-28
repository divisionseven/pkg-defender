#!/bin/zsh
# Pre-commit checklist — all must pass before commit/push

set -e

echo "=== 1. Lint ==="
ruff check src/ tests/

echo "=== 2. Format check ==="
ruff format --check src/ tests/

echo "=== 3. Type check ==="
mypy src/

echo "=== 4. Tests ==="
pytest tests/ -v

echo "=== 5. Build verification ==="
python -m build
twine check dist/*

echo "=== ALL CHECKS PASSED ==="
