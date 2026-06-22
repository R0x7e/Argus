"""
Agent 执行记录模型

记录每次 Agent 的执行信息，包含状态、耗时、成本等。
"""

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDMixin


class AgentExecution(UUIDMixin, Base):
    """
    Agent 执行记录表

    追踪每个 Agent 的执行生命周期，包括开始/结束时间、成本和执行摘要。
    """

    __tablename__ = "agent_executions"

    # 关联任务 ID
    task_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        comment="关联任务 ID",
    )

    # Agent 名称
    agent: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Agent 名称",
    )

    # 执行状态: running, completed, failed, cancelled
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="执行状态",
    )

    # 开始时间
    started_at: Mapped[datetime] = mapped_column(
        nullable=False,
        comment="开始时间",
    )

    # 完成时间
    completed_at: Mapped[datetime | None] = mapped_column(
        nullable=True,
        comment="完成时间",
    )

    # 成本信息（token 用量、API 费用等）
    cost: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="成本信息",
    )

    # 执行摘要
    summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="执行摘要",
    )

    def __repr__(self) -> str:
        return f"<AgentExecution(id={self.id}, agent='{self.agent}', status='{self.status}')>"
