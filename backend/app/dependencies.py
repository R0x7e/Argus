"""
FastAPI 依赖注入模块

提供数据库会话、Redis 客户端、NATS 客户端的依赖注入函数。
"""

from collections.abc import AsyncGenerator

import redis.asyncio as aioredis
from nats.aio.client import Client as NATSClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session_factory
from app.core.redis import get_redis_client
from app.core.nats_client import get_nats_client


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    获取数据库会话（FastAPI 依赖注入）

    在请求生命周期内提供异步数据库会话，
    请求结束后自动提交或回滚并关闭会话。
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


async def get_redis() -> aioredis.Redis:
    """
    获取 Redis 客户端（FastAPI 依赖注入）

    返回全局 Redis 客户端实例。
    """
    return get_redis_client()


async def get_nats() -> NATSClient:
    """
    获取 NATS 客户端（FastAPI 依赖注入）

    返回全局 NATS 客户端实例。
    """
    return get_nats_client()
