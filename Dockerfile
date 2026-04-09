# Stage 1: Builder
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy dependency files
COPY requirements.txt .
COPY setup.py .
COPY README.md .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY kosty/ ./kosty/

# Install kosty CLI
RUN pip install --no-cache-dir .

# Stage 2: Runner (Distroless)
FROM gcr.io/distroless/python3-debian12:nonroot

# Copy virtual environment from builder
COPY --from=builder --chown=nonroot:nonroot /opt/venv /opt/venv

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/opt/venv/lib/python3.11/site-packages" \
    PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /home/nonroot

# Run as nonroot user (already default in distroless:nonroot)
USER nonroot

# Entrypoint
ENTRYPOINT ["/opt/venv/bin/python", "/opt/venv/bin/kosty"]
