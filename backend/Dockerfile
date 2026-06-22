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

# 安装运行时系统依赖（nmap 供 port_scanner 工具使用）
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 nmap curl && \
    rm -rf /var/lib/apt/lists/*

# 从 builder 复制虚拟环境（路径已对齐 /app/venv）
COPY --from=builder /app/venv /app/venv

# 复制应用代码
COPY app/ /app/app/
COPY alembic/ /app/alembic/
COPY alembic.ini /app/alembic.ini

# 设置环境变量
ENV PATH="/app/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/system/health || exit 1

# 启动命令：使用 uvicorn 运行 FastAPI
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
