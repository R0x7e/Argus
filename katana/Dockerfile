FROM projectdiscovery/katana:latest

# 安装 Python + Flask
RUN apk add --no-cache python3 py3-pip curl && \
    pip3 install --break-system-packages flask

COPY api_wrapper.py /app/api_wrapper.py
WORKDIR /app

EXPOSE 7778

ENTRYPOINT []
CMD ["python3", "api_wrapper.py"]

HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:7778/health || exit 1
