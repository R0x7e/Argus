# Argus - AI SRC 漏洞挖掘系统 Makefile
# 常用开发命令集合

.PHONY: dev migrate test build up down lint format

# 启动开发服务器（热重载）
dev:
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 执行数据库迁移
migrate:
	cd backend && alembic upgrade head

# 运行测试套件
test:
	cd backend && pytest -v --cov=app --cov-report=term-missing

# 构建 Docker 镜像
build:
	docker-compose build

# 启动所有基础服务（后台模式）
up:
	docker-compose up -d

# 停止所有基础服务
down:
	docker-compose down

# 代码质量检查
lint:
	cd backend && ruff check app/

# 代码格式化
format:
	cd backend && ruff format app/
