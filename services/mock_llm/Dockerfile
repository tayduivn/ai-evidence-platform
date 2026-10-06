# ==============================================================================
# Single-Stage Lightweight Python Image
# ==============================================================================
FROM python:3.11-slim

WORKDIR /app

RUN groupadd -r appgroup && useradd -r -g appgroup appuser

COPY services/mock_llm/server.py /app/server.py

USER appuser
EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=5 --start-period=3s \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

ENTRYPOINT ["python3", "/app/server.py", "--host", "0.0.0.0", "--port", "8080"]
