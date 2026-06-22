FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir mitmproxy redis

COPY addon.py /app/addon.py

EXPOSE 8080 8081

CMD ["mitmdump", "--listen-host", "0.0.0.0", "--listen-port", "8080", \
     "--set", "ssl_insecure=true", \
     "-s", "/app/addon.py"]
