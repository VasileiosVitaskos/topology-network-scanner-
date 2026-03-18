FROM python:3.11-slim

WORKDIR /app

# System deps for GUDHI (C++ library), scipy, dtaidistance
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ cmake libboost-all-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY . .

# Create directories for runtime data
RUN mkdir -p /app/db /app/data

EXPOSE 5000

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Use gunicorn in production, fallback to flask dev server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "120", "server:app"]