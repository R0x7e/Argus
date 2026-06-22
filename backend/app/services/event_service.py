"""
事件服务层

封装事件的创建和查询逻辑，用于记录 Agent 执行过程中产生的事件流。
"""

import uuid
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import Event
from app.schemas.event import EventFilter


class EventService:
    """
    事件服务类

    提供事件的创建、分页查询和计数功能。
    通过构造函数注入异步数据库会话。
    """

    def __init__(self, db: AsyncSession) -> None:
        """初始化事件服务，注入数据库会话"""
        self.db = db

    async def create_event(
        self,
        task_id: uuid.UUID,
        agent: str,
        type: str,
        data: dict,
        tags: Optional[list[str]] = None,
        confidence: Optional[float] = None,
        cost: Optional[dict] = None,
    ) -> Event:
        """
        创建新事件

        记录一条 Agent 执行事件，关联到指定任务。
        """
        event = Event(
            task_id=task_id,
            agent=agent,
            type=type,
            data=data,
            tags=tags,
            confidence=confidence,
            cost=cost,
        )
        self.db.add(event)
        await self.db.flush()
        await self.db.refresh(event)
        return event

    async def get_events(
        self,
        task_id: uuid.UUID,
        page: int = 1,
        page_size: int = 50,
        filters: Optional[EventFilter] = None,
    ) -> tuple[list[Event], int]:
        """
        分页查询事件列表

        支持按 Agent、类型、时间范围筛选，按时间戳降序排列。
        """
        # 构建基础查询
        stmt = select(Event).where(Event.task_id == task_id)
        count_stmt = select(func.count()).select_from(Event).where(Event.task_id == task_id)

        # 应用过滤条件
        if filters:
            if filters.agent is not None:
                stmt = stmt.where(Event.agent == filters.agent)
                count_stmt = count_stmt.where(Event.agent == filters.agent)
            if filters.type is not None:
                stmt = stmt.where(Event.type == filters.type)
                count_stmt = count_stmt.where(Event.type == filters.type)
            if filters.after is not None:
                stmt = stmt.where(Event.timestamp > filters.after)
                count_stmt = count_stmt.where(Event.timestamp > filters.after)
            if filters.before is not None:
                stmt = stmt.where(Event.timestamp < filters.before)
                count_stmt = count_stmt.where(Event.timestamp < filters.before)

        # 查询总数
        total_result = await self.db.execute(count_stmt)
        total = total_result.scalar() or 0

        # 分页查询（按时间戳降序）
        offset = (page - 1) * page_size
        stmt = stmt.order_by(Event.timestamp.desc()).offset(offset).limit(page_size)
        result = await self.db.execute(stmt)
        events = list(result.scalars().all())

        return events, total

    async def get_event_count(self, task_id: uuid.UUID) -> int:
        """
        获取指定任务的事件总数

        用于统计和状态展示。
        """
        stmt = select(func.count()).select_from(Event).where(Event.task_id == task_id)
        result = await self.db.execute(stmt)
        return result.scalar() or 0
