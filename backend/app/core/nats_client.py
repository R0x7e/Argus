"""
NATS 消息总线客户端模块

提供 NATS 连接和 JetStream 支持，用于 Agent 间事件通信。
"""

import nats
from nats.aio.client import Client as NATSClient
from nats.js.client import JetStreamContext

from app.config import get_settings

# 全局 NATS 客户端和 JetStream 上下文
_nats_client: NATSClient | None = None
_jetstream: JetStreamContext | None = None


async def init_nats() -> NATSClient:
    """
    初始化 NATS 连接并配置 JetStream

    在应用启动时调用，创建全局 NATS 客户端，
    并创建名为 "EVENTS" 的 JetStream 流用于事件存储。
    """
    global _nats_client, _jetstream
    settings = get_settings()

    # 建立 NATS 连接
    _nats_client = await nats.connect(settings.NATS_URL)

    # 获取 JetStream 上下文
    _jetstream = _nats_client.jetstream()

    # 创建 EVENTS 流（用于存储所有 Agent 事件）
    # 如果流已存在则更新配置
    await _jetstream.add_stream(
        name="EVENTS",
        subjects=["events.>"],  # 匹配所有 events.* 主题
        retention="limits",  # 基于限制的保留策略
        max_msgs=1_000_000,  # 最大消息数
        max_age=7 * 24 * 3600 * 1_000_000_000,  # 保留 7 天（纳秒）
    )

    return _nats_client


async def close_nats() -> None:
    """关闭 NATS 连接，在应用关闭时调用"""
    global _nats_client, _jetstream
    if _nats_client is not None:
        await _nats_client.drain()  # 优雅排空消息后关闭
        _nats_client = None
        _jetstream = None


def get_nats_client() -> NATSClient:
    """
    获取全局 NATS 客户端实例

    必须在 init_nats() 之后调用。
    """
    if _nats_client is None:
        raise RuntimeError("NATS 客户端未初始化，请先调用 init_nats()")
    return _nats_client


def get_jetstream() -> JetStreamContext:
    """
    获取 JetStream 上下文

    用于发布和订阅持久化事件消息。
    """
    if _jetstream is None:
        raise RuntimeError("JetStream 未初始化，请先调用 init_nats()")
    return _jetstream
