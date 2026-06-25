"""
事件总线 - 统一管理事件的持久化和实时分发

将 Agent 事件同时写入 PostgreSQL、发布到 NATS 消息总线，
并广播给已连接的 WebSocket 客户端。
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import Event

logger = structlog.get_logger()


class EventBus:
    """
    事件总线：将 Agent 事件同时写入数据库和发布到 NATS，
    并广播给已连接的 WebSocket 客户端。
    """

    def __init__(self) -> None:
        # task_id -> 回调函数列表，用于向 WebSocket 客户端推送事件
        self._ws_clients: dict[str, list[Callable]] = {}
        # NATS 客户端（在 lifespan 中注入）
        self._nats_client = None

    def set_nats(self, nats_client) -> None:
        """注入 NATS 客户端实例（在应用启动时调用）"""
        self._nats_client = nats_client

    async def publish(
        self,
        db: AsyncSession,
        task_id: str,
        agent: str,
        event_type: str,
        data: dict,
        tags: Optional[list[str]] = None,
        confidence: Optional[float] = None,
        cost: Optional[dict] = None,
    ) -> str:
        """
        发布事件：
        1. 写入 PostgreSQL（持久化）
        2. 发布到 NATS（供其他服务消费）
        3. 广播到该任务的所有 WebSocket 客户端（实时推送）

        Args:
            db: 异步数据库会话
            task_id: 关联任务 ID
            agent: 产生事件的 Agent 名称
            event_type: 事件类型（如 log, error, vuln_found 等）
            data: 事件数据（JSON 格式）
            tags: 事件标签列表
            confidence: 置信度（0.0 ~ 1.0）
            cost: 成本信息（token 用量、API 费用等）

        Returns:
            新创建的事件 ID
        """
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        # 1. 持久化到数据库
        event = Event(
            id=event_id,
            task_id=task_id,
            agent=agent,
            type=event_type,
            timestamp=now,
            data=data,
            tags=tags or [],
            confidence=confidence,
            cost=cost,
        )
        db.add(event)
        await db.flush()

        # 2. 构造事件载荷（用于 NATS 发布和 WebSocket 广播）
        event_payload = {
            "id": event_id,
            "task_id": task_id,
            "agent": agent,
            "type": event_type,
            "timestamp": now.isoformat(),
            "data": data,
            "tags": tags or [],
        }

        # 发布到 NATS JetStream
        if self._nats_client:
            try:
                js = self._nats_client.jetstream()
                await js.publish(
                    f"events.{task_id}",
                    json.dumps(event_payload).encode(),
                )
            except Exception as e:
                # NATS 发布失败不阻塞主流程，仅记录警告
                logger.warning("nats_publish_failed", error=str(e), task_id=task_id)

        # 3. 广播到 WebSocket 客户端
        await self._broadcast_ws(task_id, event_payload)

        return event_id

    def subscribe_ws(self, task_id: str, callback: Callable) -> None:
        """
        注册 WebSocket 回调

        当指定任务产生新事件时，通过回调通知客户端。

        Args:
            task_id: 要订阅的任务 ID
            callback: 异步回调函数，接收事件字典
        """
        if task_id not in self._ws_clients:
            self._ws_clients[task_id] = []
        self._ws_clients[task_id].append(callback)
        logger.debug("ws_client_subscribed", task_id=task_id,
                     client_count=len(self._ws_clients[task_id]))

    def unsubscribe_ws(self, task_id: str, callback: Callable) -> None:
        """
        注销 WebSocket 回调

        客户端断开连接时清除对应回调。

        Args:
            task_id: 要取消订阅的任务 ID
            callback: 之前注册的回调函数
        """
        if task_id in self._ws_clients:
            self._ws_clients[task_id] = [
                cb for cb in self._ws_clients[task_id] if cb != callback
            ]
            # 如果没有订阅者了，清理空列表
            if not self._ws_clients[task_id]:
                del self._ws_clients[task_id]

    async def _broadcast_ws(self, task_id: str, event: dict) -> None:
        """
        向所有订阅该任务的 WebSocket 客户端广播事件

        单个客户端发送失败不影响其他客户端。
        """
        callbacks = self._ws_clients.get(task_id, [])
        for cb in callbacks:
            try:
                await cb(event)
            except Exception as e:
                logger.warning("ws_broadcast_failed", error=str(e), task_id=task_id)


# 全局单例（整个应用共享一个事件总线实例）
event_bus = EventBus()
