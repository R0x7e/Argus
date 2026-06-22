"""
事件模型

记录 Agent 执行过程中产生的所有事件，用于追踪和审计。
"""

import uuid
from datetime import datetime

from sqlalchemy import Float, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDMixin


class Event(UUIDMixin, Base):
    """
    事件表

    存储 Agent 执行过程中的事件流，包含事件类型、数据、标签等。
    用于完整的执行追踪和任务回溯。
    """

    __tablename__ = "events"

    # 关联任务 ID
    task_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        comment="关联任务 ID",
    )

    # 父事件 ID（用于构建事件层级树）
    parent_event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="父事件 ID",
    )

    # 产生事件的 Agent 名称
    agent: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Agent 名称",
    )

    # 事件类型（如 recon_started, vuln_found, tool_called 等）
    type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="事件类型",
    )

    # 事件时间戳
    timestamp: Mapped[datetime] = mapped_column(
        server_default=func.now(),
        nullable=False,
        comment="事件时间戳",
    )

    # 事件数据（JSON 格式的详细内容）
    data: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="事件数据",
    )

    # 事件标签（用于过滤和分类）
    tags: Mapped[list[str] | None] = mapped_column(
        ARRAY(String),
        nullable=True,
        comment="事件标签",
    )

    # 置信度（0.0 ~ 1.0）
    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="置信度",
    )

    # 成本信息（token 用量、API 费用等）
    cost: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="成本信息",
    )

    # 索引定义
    __table_args__ = (
        Index("ix_events_task_id_timestamp", "task_id", "timestamp"),
        Index("ix_events_task_id_agent", "task_id", "agent"),
        {"comment": "Agent 事件流表"},
    )

    def __repr__(self) -> str:
        return f"<Event(id={self.id}, agent='{self.agent}', type='{self.type}')>"
