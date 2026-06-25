"""
节点内实时事件发射器

提供 emit() 函数供 LangGraph 节点在执行过程中实时发布事件。
每次调用使用独立的 DB session，事件立即通过 WebSocket 推送给前端。
对于 finding 类关键事件，异常会向上传播以确保数据一致性；
其他类型的事件发布失败不会中断扫描流程。
"""

import logging

logger = logging.getLogger(__name__)

# 关键事件类型：发布失败时应向上传播异常，确保数据一致性
_CRITICAL_EVENT_TYPES = frozenset({
    "finding_confirmed",
    "task_completed",
    "task_failed",
})


async def emit(
    task_id: str,
    agent: str,
    event_type: str,
    data: dict,
    tags: list[str] | None = None,
) -> None:
    """从 Agent 节点内部实时发布事件

    对于 finding_confirmed 等关键事件，异常会向上传播；
    其他类型的事件发布失败仅记录警告。
    """
    try:
        from app.core.database import async_session_factory
        from app.core.event_bus import event_bus

        async with async_session_factory() as db:
            await event_bus.publish(
                db=db,
                task_id=task_id,
                agent=agent,
                event_type=event_type,
                data=data,
                tags=tags,
            )
            await db.commit()
    except Exception as e:
        if event_type in _CRITICAL_EVENT_TYPES:
            # 关键事件发布失败，向上传播以确保数据一致性
            logger.error("关键事件发射失败 [%s/%s]: %s", agent, event_type, e)
            raise
        logger.warning("事件发射失败 [%s/%s]: %s", agent, event_type, e)
