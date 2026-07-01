# Argus 后端 Dockerfile
# 多阶段构建：builder 安装依赖，runtime 仅保留运行时所需

# ---- Builder ----
FROM python:3.12-slim AS builder

WORKDIR /build

# 安装构建依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./

# 创建最小包结构让 pip 能解析依赖并安装
RUN mkdir -p app && touch app/__init__.py

# 安装 Python 依赖到 /app/venv（路径需与 runtime 一致）
RUN python -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /app/venv/bin/pip install --no-cache-dir .

# ---- Runtime ----
FROM python:3.12-slim AS runtime

WORKDIR /app

# 安装运行时系统依赖（nmap 供 port_scanner 工具使用，Chromium 依赖供 Playwright 使用）
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 nmap curl \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 libgbm1 \
    libpango-1.0-0 libcairo2 libasound2 libxshmfence1 \
    fonts-liberation libappindicator3-1 \
    && rm -rf /var/lib/apt/lists/*

# 从 builder 复制虚拟环境（路径已对齐 /app/venv）
COPY --from=builder /app/venv /app/venv

# 安装 Playwright Chromium 浏览器
RUN /app/venv/bin/python -m playwright install chromium --with-deps

# 复制应用代码
COPY app/ /app/app/
COPY alembic/ /app/alembic/
COPY alembic.ini /app/alembic.ini
COPY tests/ /app/tests/

# 安装测试依赖
RUN /app/venv/bin/pip install --no-cache-dir pytest pytest-asyncio

# 创建非 root 用户, 复制 Playwright Chromium 到 appuser 目录
RUN useradd -r -s /bin/false -u 1000 appuser && \
    mkdir -p /home/appuser/.cache && \
    cp -r /root/.cache/ms-playwright /home/appuser/.cache/ms-playwright && \
    chown -R appuser:appuser /app /home/appuser/.cache

# 设置环境变量
ENV PATH="/app/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/system/health || exit 1

USER appuser

# 启动命令：使用 uvicorn 运行 FastAPI
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
