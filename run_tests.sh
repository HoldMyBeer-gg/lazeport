#!/usr/bin/env sh
# Run tests with coverage. Use this to see coverage % before or after spin-up.
set -e
[ -f .venv/bin/activate ] && . .venv/bin/activate
python -m pytest tests/ --ignore=tests/e2e -n auto --cov=app --cov-report=term-missing --cov-report=html --cov-fail-under=40 -v
echo ""
echo "HTML report: htmlcov/index.html"
echo ""
echo "UI tests (headless): behave"