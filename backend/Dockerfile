# Build the existing FastAPI backend in a Linux image. The Windows .venv is
# excluded by backend/.dockerignore and must never be copied into this image.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app

# Dependencies change less often than source, so this layer can be cached.
COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && useradd --uid 10001 --create-home appuser

COPY app ./app
USER appuser
EXPOSE 8000

# Exactly one Uvicorn process: this app starts its feed workers in lifespan.
# Multiple processes would create duplicate background worker loops.
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
