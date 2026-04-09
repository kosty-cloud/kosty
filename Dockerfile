# Stage 1: Builder
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
COPY setup.py .
COPY README.md .

RUN pip install --no-cache-dir -r requirements.txt

COPY kosty/ ./kosty/

RUN pip install --no-cache-dir .

# Stage 2: Runner (Distroless)
FROM gcr.io/distroless/python3-debian12:nonroot


COPY --from=builder --chown=nonroot:nonroot /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/opt/venv/lib/python3.11/site-packages" \
    PYTHONUNBUFFERED=1

WORKDIR /home/nonroot

USER nonroot

ENTRYPOINT ["python3", "-m", "kosty.cli"]
