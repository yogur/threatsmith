.PHONY: build-skills test lint format

build-skills:
	uv run python scripts/build_skills.py

test:
	uv run pytest

lint:
	uv run ruff check --fix

format:
	uv run ruff format
