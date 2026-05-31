# ── Build frontend ───────────────────────────────────────────────────────────
FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY horus-frontend/package*.json ./
RUN npm ci --silent
COPY horus-frontend/ ./
ARG VITE_API_URL=""
ENV VITE_API_URL=${VITE_API_URL}
RUN npm run build

# ── API ──────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS api

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY domain/        ./domain/
COPY infrastructure/ ./infrastructure/
COPY application/   ./application/
COPY api/           ./api/
COPY data_utils/    ./data_utils/

COPY api.py ./
COPY --from=frontend-build /app/frontend/dist ./static/
RUN mkdir -p models data

EXPOSE 8000

ENV HORUS_HOST=0.0.0.0 \
    HORUS_PORT=8000 \
    HORUS_API_KEY="" \
    HORUS_CORS_ORIGINS="*" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

CMD ["sh", "-c", "uvicorn api:app --host $HORUS_HOST --port $HORUS_PORT --workers 1"]
