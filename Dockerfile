FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TENANT_ANALYZER_DATA_DIR=/data

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==23.0.0

COPY . .

# Run unprivileged; the synced SQLite cache lives on the /data volume.
RUN useradd --system --uid 10001 --no-create-home analyzer \
    && mkdir -p /data && chown analyzer /data
USER analyzer
VOLUME ["/data"]

EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8888/static/css/style.css', timeout=4)"]

# Exactly one worker: signed-in sessions and sync progress live in this
# process's memory, so a second worker wouldn't see them. Threads give the
# concurrency instead (page loads while a sync is running).
CMD ["gunicorn", "--bind", "0.0.0.0:8888", "--workers", "1", "--threads", "8", "--timeout", "120", "app:app"]
