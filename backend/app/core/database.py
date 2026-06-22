"""
数据库连接模块

提供异步 SQLAlchemy 引擎和会话工厂，支持 async/await 操作。
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings

# 获取配置
settings = get_settings()

# 创建异步数据库引擎
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,  # 调试模式下输出 SQL 语句
    pool_size=20,  # 连接池大小
    max_overflow=10,  # 最大溢出连接数
    pool_pre_ping=True,  # 连接前检测是否有效
)

# 创建异步会话工厂
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,  # 提交后不自动过期对象
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    获取数据库会话的异步生成器

    用法:
        async with async_session_factory() as session:
            ...
    或作为 FastAPI 依赖注入使用。
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
