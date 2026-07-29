FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt update && apt install -y \
    git \
    bash \
    ca-certificates \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir psycopg2-binary

COPY ingest.py .
COPY init.sh .

RUN chmod +x init.sh

CMD ["bash", "-lc", "./init.sh && python ingest.py"]