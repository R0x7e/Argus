"""
Alembic 异步迁移环境配置

支持异步 SQLAlchemy 引擎，自动检测模型变更并生成迁移脚本。
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.config import get_settings

# 导入所有模型以确保 Alembic 能检测到表结构
from app.models import Base  # noqa: F401

# Alembic 配置对象
config = context.config

# 配置日志
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# 设置目标元数据（用于自动迁移检测）
target_metadata = Base.metadata

# 从应用配置获取数据库 URL
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)


def run_migrations_offline() -> None:
    """
    离线模式运行迁移

    仅生成 SQL 脚本，不连接数据库。
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    """在给定连接上执行迁移"""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """
    异步模式运行迁移

    创建异步引擎并在连接上执行迁移。
    """
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """
    在线模式运行迁移

    使用异步引擎连接数据库并执行迁移。
    """
    asyncio.run(run_async_migrations())


# 根据运行模式选择迁移方式
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
