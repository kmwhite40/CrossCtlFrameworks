# CrossCtlFrameworks — Copyright © 2026 Colleen Townsend
.PHONY: help install dev up down logs migrate ingest serve cli test lint typecheck fmt sbom scan clean

PY      ?= python3
COMPOSE ?= docker compose
WORKBOOK ?= ./data/NIST Cross Mappings Rev. 1.1.xlsx

help:
	@awk 'BEGIN{FS=":.*##"; printf "Targets:\n"} /^[a-zA-Z_-]+:.*?##/{printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Create .venv and install the package (editable) with dev extras
	$(PY) -m venv .venv
	. .venv/bin/activate && pip install -U pip && pip install -e ".[dev]"

dev: install migrate ingest serve ## Full local bootstrap

up: ## Bring up db + migrator + api
	$(COMPOSE) up -d db migrator api

down: ## Tear down stack (keeps volumes)
	$(COMPOSE) down

logs: ## Tail compose logs
	$(COMPOSE) logs -f --tail=200

migrate: ## Apply Alembic migrations (host python, local DB)
	alembic upgrade head

ingest: ## Ingest the workbook into Postgres
	ccf ingest --xlsx "$(WORKBOOK)"

serve: ## Run the FastAPI app locally
	ccf serve --reload

cli: ## Open a ccf CLI prompt (through compose)
	$(COMPOSE) --profile cli run --rm cli --help

test: ## Run the test suite
	pytest -q

lint: ## Ruff lint
	ruff check .

typecheck: ## Mypy strict
	mypy src

fmt: ## Ruff format
	ruff format .

sbom: ## Generate CycloneDX SBOM
	cyclonedx-py environment -o sbom.json || true

scan: ## Trivy filesystem scan
	trivy fs --severity HIGH,CRITICAL --exit-code 1 .

reader-build: ## Build Concord Reader .exe via PyInstaller
	pip install -e ".[reader]"
	pyinstaller concord_reader.spec --clean --noconfirm
	@echo "Artifact: dist/ConcordReader$(if $(findstring Windows,$(OS)),.exe,)"

reader-run: ## Run the Reader from source (no packaging)
	CCF_READONLY=true CCF_DATABASE_URL=sqlite+aiosqlite:///$$HOME/.concord/concord.db \
	CCF_DATABASE_URL_SYNC=sqlite:///$$HOME/.concord/concord.db \
	python -m ccf.reader.launcher

clean:
	rm -rf .venv .pytest_cache .ruff_cache .mypy_cache dist build *.egg-info sbom.json
