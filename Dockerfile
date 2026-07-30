FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt update && apt install -y \
    git \
    bash \
    ca-certificates \
    iputils-ping \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir psycopg2-binary

# Copy application files
COPY ingest.py .
COPY update.py .
COPY init.sh .
COPY crontab /etc/cron.d/nvd-cron

RUN chmod +x init.sh
RUN chmod 0644 /etc/cron.d/nvd-cron

# Create log file for cron
RUN touch /var/log/cron.log

# Default command: initial bulk import (used by the ingest-tool service)
CMD ["bash", "-lc", "./init.sh && python ingest.py"]