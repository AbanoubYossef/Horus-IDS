# ── HORUS SOC — Makefile ──────────────────────────────────────────────────────

.DEFAULT_GOAL := help
PYTHON := .venv/bin/python
PIP    := .venv/bin/pip

# ── Help ───────────────────────────────────────────────────────────────────────
.PHONY: help
help:
	@echo ""
	@echo "  HORUS SOC"
	@echo ""
	@echo "  Development"
	@echo "    make venv          create .venv and install dependencies"
	@echo "    make dev           start API with hot-reload on localhost:8000"
	@echo "    make dev-frontend  start Vite dev server on localhost:3000"
	@echo "    make test          run full pytest suite (no model needed)"
	@echo "    make test-v        run tests with verbose output"
	@echo "    make test-cov      run tests with coverage report"
	@echo ""
	@echo "  Docker"
	@echo "    make build         build horus-soc and horus-capture images"
	@echo "    make up            start API container (detached)"
	@echo "    make up-capture    start API + capture service"
	@echo "    make down          stop and remove containers"
	@echo "    make logs          tail API container logs"
	@echo "    make shell         open shell in running API container"
	@echo ""
	@echo "  Maintenance"
	@echo "    make clean         remove __pycache__ and .pytest_cache"
	@echo ""

# ── Virtual environment ────────────────────────────────────────────────────────
.PHONY: venv
venv:
	python3 -m venv .venv
	$(PIP) install --upgrade pip -q
	$(PIP) install -r requirements.txt -q
	@echo "  ✓ .venv ready. Activate with: source .venv/bin/activate"

# ── Development ────────────────────────────────────────────────────────────────
.PHONY: dev
dev:
	$(PYTHON) -m uvicorn api.app:app --reload --host 127.0.0.1 --port 8000

.PHONY: dev-frontend
dev-frontend:
	cd horus-frontend && npm run dev

# ── Testing ────────────────────────────────────────────────────────────────────
.PHONY: test
test:
	$(PYTHON) -m pytest tests/ --tb=short -q

.PHONY: test-v
test-v:
	$(PYTHON) -m pytest tests/ -v --tb=short

.PHONY: test-cov
test-cov:
	$(PYTHON) -m pytest tests/ --cov=. --cov-report=term-missing --cov-report=html \
	    --cov-omit=".venv/*,tests/*,sdfg/*,*train_*.py,evaluate_unseen.py,sample_ddos2019.py"
	@echo "  HTML report: htmlcov/index.html"

# ── Docker ─────────────────────────────────────────────────────────────────────
.PHONY: build
build:
	docker compose build

.PHONY: up
up:
	docker compose up -d horus-api
	@echo "  API: http://localhost:$${HORUS_PORT:-8000}/health"

.PHONY: up-capture
up-capture:
	docker compose --profile capture up -d
	@echo "  API + capture service running"

.PHONY: down
down:
	docker compose --profile capture down

.PHONY: logs
logs:
	docker compose logs -f horus-api

.PHONY: shell
shell:
	docker compose exec horus-api /bin/bash

# ── Maintenance ────────────────────────────────────────────────────────────────
.PHONY: clean
clean:
	find . -type d -name "__pycache__" -not -path "./.venv/*" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache htmlcov .coverage
	@echo "  ✓ Cleaned"
