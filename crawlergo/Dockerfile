FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git
WORKDIR /build
RUN git clone --depth 1 https://github.com/Qianlitp/crawlergo.git . && \
    go build -o /crawlergo ./cmd/crawlergo

FROM alpine:3.19

RUN apk add --no-cache chromium curl python3 py3-pip && \
    pip3 install --no-cache-dir --break-system-packages flask

COPY --from=builder /crawlergo /usr/local/bin/crawlergo
COPY api_wrapper.py /app/api_wrapper.py

WORKDIR /app

# 创建非 root 用户运行（安全加固）
RUN adduser -D -u 1002 crawluser && \
    chown -R crawluser:crawluser /app

EXPOSE 7777

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:7777/health || exit 1

USER crawluser

CMD ["python3", "/app/api_wrapper.py"]
