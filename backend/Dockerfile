FROM python:3.11-slim

WORKDIR /app

# System deps for GUDHI, scipy, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ cmake libboost-all-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY . .

# Create db directory
RUN mkdir -p /app/db

EXPOSE 5000

# Health check
HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

CMD ["python", "server.py"]
