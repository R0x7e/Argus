"""
WebSocket 端点 - 实时事件流推送 + 用户干预下行

v2: 双向通信 — 客户端可发送用户干预指令控制搜索过程。
"""

import json
from typing import Optional

import structlog
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.core.event_bus import event_bus
from app.core.security import decode_access_token
from app.core.user_action_handler import UserActionHandler

logger = structlog.get_logger()

router = APIRouter()
_user_action_handler = UserActionHandler()


def _get_active_state(task_id: str) -> dict | None:
    """获取当前运行中任务的 LATSState"""
    from app.services import agent_runner as agent_runner_module
    runner = agent_runner_module.agent_runner
    if runner is None:
        return None
    # 通过 agent_runner 获取当前运行状态
    if hasattr(runner, '_active_states'):
        return runner._active_states.get(task_id)
    return None


@router.websocket("/ws/tasks/{task_id}/stream")
async def task_event_stream(
    websocket: WebSocket,
    task_id: str,
    token: Optional[str] = Query(default=None),
) -> None:
    """
    WebSocket 端点 (v2 双向): 实时推送任务事件流 + 接收用户干预指令。

    上行 (Client → Server):
      {"type": "user_action", "action": "create_branch"|"mark_false_positive"|...,
       "params": {...}}

      {"type": "ping"}

    下行 (Server → Client):
      {"type": "event", "data": {...}}

      {"type": "pong"}

      {"type": "user_action_ack", "action": "...", "status": "applied"|"rejected",
       "reason": "...", "data": {...}}
    """
    # Token 验证 — WebSocket 连接必须提供有效 token
    if not token:
        await websocket.close(code=4001, reason="缺少认证 Token")
        return

    payload = decode_access_token(token)
    if payload is None:
        await websocket.close(code=4001, reason="Token 无效或已过期")
        return

    await websocket.accept()
    logger.info("ws_client_connected", task_id=task_id)

    async def send_event(event: dict) -> None:
        """回调：收到事件总线推送时转发给 WebSocket 客户端"""
        try:
            await websocket.send_json({"type": "event", "data": event})
        except Exception:
            pass

    # 注册事件回调
    event_bus.subscribe_ws(task_id, send_event)

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "user_action_ack",
                    "status": "rejected",
                    "reason": "无效的 JSON",
                })
                continue

            msg_type = msg.get("type", "")

            if msg_type == "ping":
                await websocket.send_json({"type": "pong"})

            elif msg_type == "user_action":
                action = msg.get("action", "")
                params = msg.get("params", {})

                # 查找当前任务状态
                state = _get_active_state(task_id)
                if state is None:
                    await websocket.send_json({
                        "type": "user_action_ack",
                        "action": action,
                        "status": "rejected",
                        "reason": "任务状态不可用（任务可能未在运行）",
                    })
                    continue

                result = await _user_action_handler.handle(action, params, state)
                await websocket.send_json({
                    "type": "user_action_ack",
                    "action": action,
                    "status": result.get("status", "rejected"),
                    "reason": result.get("reason", ""),
                    "data": result.get("data", {}),
                })

            else:
                await websocket.send_json({
                    "type": "user_action_ack",
                    "status": "rejected",
                    "reason": f"未知消息类型: {msg_type}",
                })

    except WebSocketDisconnect:
        logger.info("ws_client_disconnected", task_id=task_id)
    finally:
        event_bus.unsubscribe_ws(task_id, send_event)
