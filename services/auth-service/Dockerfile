# SEEDED FLAW #8: stale base image.
# Expected detector: Trivy image scan. python:3.12.0-slim was published Oct 2023;
# its Debian layer carries dozens of since-patched OS package CVEs.
FROM python:3.12.0-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# SEEDED FLAW #9: container runs as root.
# Expected detector: Checkov CKV_DOCKER_3 (no USER instruction).
# The adduser/USER lines that dropped privileges have been removed.

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
