FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi uvicorn \
    RestrictedPython \
    requests urllib3

COPY sandbox_worker.py /app/sandbox_worker.py

RUN useradd -r -s /bin/false sandboxuser

EXPOSE 9090

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9090/health')" || exit 1

USER sandboxuser

CMD ["uvicorn", "sandbox_worker:app", "--host", "0.0.0.0", "--port", "9090"]
