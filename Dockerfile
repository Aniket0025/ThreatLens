# ── Build stage ──────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Install dependencies into a prefix so we can copy them cleanly
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ─────────────────────────────────────────────────
FROM python:3.12-slim

# Non-root user for security
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY backend/ ./backend/

# Copy dataset (needed at startup for median computation if using old model)
COPY dataset/ ./dataset/

COPY frontend/ ./frontend/

# Set working directory to backend so relative paths resolve
WORKDIR /app/backend

# Runtime environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_DEBUG=false \
    PORT=8000 \
    MODEL_PATH=url_model.pkl \
    DATASET_PATH=../dataset/phishing_urls.csv \
    LOG_LEVEL=INFO

USER appuser

EXPOSE 8000

# Production server: gunicorn with 2 workers
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "60", "app:app"]
