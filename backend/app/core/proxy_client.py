"""
mitmproxy 流量消费客户端

通过 Redis Pub/Sub 订阅 mitmproxy 拦截的 HTTP 流量，
供 proxy_flows 工具查询分析。
"""

import asyncio
import json
import logging
from collections import deque

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

_proxy_consumer: "ProxyFlowConsumer | None" = None


class ProxyFlowConsumer:
    def __init__(self, redis_client: aioredis.Redis, channel: str = "proxy:flows"):
        self._redis = redis_client
        self._channel = channel
        self._flows: deque[dict] = deque(maxlen=5000)
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._subscribe_loop())
        logger.info("ProxyFlowConsumer 已启动, channel=%s", self._channel)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("ProxyFlowConsumer 已停止")

    async def _subscribe_loop(self) -> None:
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(self._channel)
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        data = message["data"]
                        if isinstance(data, bytes):
                            data = data.decode("utf-8")
                        flow = json.loads(data)
                        self._flows.append(flow)
                    except (json.JSONDecodeError, TypeError):
                        pass
        except asyncio.CancelledError:
            await pubsub.unsubscribe(self._channel)
            raise

    def get_flows(self, task_id: str | None = None, limit: int = 100) -> list[dict]:
        flows = list(self._flows)
        if task_id:
            flows = [f for f in flows if f.get("task_id") == task_id]
        return flows[-limit:]

    def clear_flows(self) -> None:
        self._flows.clear()


async def start_consumer() -> None:
    global _proxy_consumer
    from app.config import get_settings
    from app.core.redis import get_redis_client

    settings = get_settings()
    redis_client = get_redis_client()
    _proxy_consumer = ProxyFlowConsumer(redis_client, channel=settings.PROXY_FLOWS_CHANNEL)
    await _proxy_consumer.start()


async def stop_consumer() -> None:
    global _proxy_consumer
    if _proxy_consumer:
        await _proxy_consumer.stop()
        _proxy_consumer = None
