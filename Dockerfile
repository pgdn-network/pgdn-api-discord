# Ultra-minimal Dockerfile for lite validation API
FROM python:3.12-alpine

# Essential Python optimizations only
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-deps -r requirements.txt

# Copy organized app structure
COPY main.py .
COPY app/ ./app/

# Non-root user for security
RUN adduser -D -s /bin/sh appuser
USER appuser

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
