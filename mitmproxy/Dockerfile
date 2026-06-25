FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir mitmproxy redis

COPY addon.py /app/addon.py

# 创建非 root 用户运行（安全加固）
RUN useradd -r -s /bin/false -u 1001 proxyuser && \
    mkdir -p /home/proxyuser/.mitmproxy && \
    chown -R proxyuser:proxyuser /app /home/proxyuser

EXPOSE 8080 8081

USER proxyuser

CMD ["mitmdump", "--listen-host", "0.0.0.0", "--listen-port", "8080", \
     "--set", "ssl_insecure=true", \
     "-s", "/app/addon.py"]
