FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY service/ ./service/
COPY extractor/ ./extractor/
COPY capture/ ./capture/
COPY kafka_components/ ./kafka_components/
COPY alerting/ ./alerting/
COPY dashboard/ ./dashboard/

# Create directory for models
RUN mkdir -p /app/models /app/logs

# Copy model files from models/ directory
# Mount as volume in production: -v /path/to/models:/app/models
COPY --chmod=644 models/*.joblib /app/models/
COPY --chmod=644 models/*.pkl /app/models/

# Environment variables
ENV MODEL_DIR=/app/models
ENV SERVICE_PORT=8000
ENV SERVICE_HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1

# Expose service port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Run detection service
CMD ["uvicorn", "service.detector_service:app", "--host", "0.0.0.0", "--port", "8000"]
