"""
Redis 连接模块

提供 Redis 异步客户端的初始化、关闭和获取功能。
"""

import redis.asyncio as aioredis

from app.config import get_settings

# 全局 Redis 客户端实例
_redis_client: aioredis.Redis | None = None


async def init_redis() -> aioredis.Redis:
    """
    初始化 Redis 连接

    在应用启动时调用，创建全局 Redis 客户端。
    """
    global _redis_client
    settings = get_settings()
    _redis_client = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,  # 自动解码响应为字符串
    )
    # 测试连接是否正常
    await _redis_client.ping()
    return _redis_client


async def close_redis() -> None:
    """关闭 Redis 连接，在应用关闭时调用"""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.close()
        _redis_client = None


def get_redis_client() -> aioredis.Redis:
    """
    获取全局 Redis 客户端实例

    必须在 init_redis() 之后调用，否则抛出异常。
    """
    if _redis_client is None:
        raise RuntimeError("Redis 客户端未初始化，请先调用 init_redis()")
    return _redis_client
