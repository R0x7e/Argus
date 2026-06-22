"""
WebSocket 端点 - 实时事件流推送

提供按任务 ID 订阅事件流的 WebSocket 接口，
客户端连接后自动接收该任务的所有实时事件。
支持通过 query param 传递 JWT Token 进行认证。
"""

import json
from typing import Optional

import structlog
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.core.event_bus import event_bus
from app.core.security import decode_access_token

logger = structlog.get_logger()

router = APIRouter()


@router.websocket("/ws/tasks/{task_id}/stream")
async def task_event_stream(
    websocket: WebSocket,
    task_id: str,
    token: Optional[str] = Query(default=None),
) -> None:
    """
    WebSocket 端点：实时推送任务事件流。

    认证方式：
    - 通过 query param ?token=<jwt> 传递 JWT Token
    - Token 无效时关闭连接（code=4001）
    - Token 缺失时允许连接（方便开发调试，生产环境应强制认证）

    连接流程：
    1. 客户端连接 ws://<host>/api/v1/ws/tasks/{task_id}/stream?token=xxx
    2. 验证 Token（如有）
    3. 服务端接受连接并注册事件回调
    4. 任务产生新事件时自动推送 {"type": "event", "data": {...}}
    5. 客户端可发送 {"action": "ping"} 进行心跳检测
    """
    # Token 验证（如有）
    if token:
        payload = decode_access_token(token)
        if payload is None:
            await websocket.close(code=4001, reason="Token 无效或已过期")
            return

    await websocket.accept()
    logger.info("ws_client_connected", task_id=task_id)

    async def send_event(event: dict) -> None:
        """回调函数：收到事件总线推送的事件时转发给 WebSocket 客户端"""
        try:
            await websocket.send_json({
                "type": "event",
                "data": event,
            })
        except Exception:
            pass

    # 注册事件回调
    event_bus.subscribe_ws(task_id, send_event)

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "ping":
                    await websocket.send_json({"type": "pong"})
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        logger.info("ws_client_disconnected", task_id=task_id)
    finally:
        event_bus.unsubscribe_ws(task_id, send_event)
