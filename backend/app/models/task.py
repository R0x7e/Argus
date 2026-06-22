"""
任务模型

定义漏洞挖掘任务的数据库表结构，包含目标配置、策略、状态等字段。
"""

import uuid
from datetime import datetime

from sqlalchemy import Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDMixin


class Task(UUIDMixin, Base):
    """
    任务表

    存储漏洞挖掘任务的核心信息，包括目标、策略、执行状态等。
    """

    __tablename__ = "tasks"

    # 任务名称
    name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        comment="任务名称",
    )

    # 目标类型（如 web_app, api, mobile 等）
    target_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="目标类型",
    )

    # 目标配置（JSON 格式存储 URL、范围等信息）
    target_config: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment="目标配置（JSONB）",
    )

    # 测试策略
    strategy: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="测试策略",
    )

    # 任务状态: created, running, paused, completed, failed, cancelled
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="created",
        server_default="created",
        comment="任务状态",
    )

    # 任务进度（JSON 格式存储各阶段进度）
    progress: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="任务进度",
    )

    # 任务配置（预算、并发数等）
    config: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="任务配置",
    )

    # 创建者用户 ID
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="创建者用户 ID",
    )

    # 任务开始时间
    started_at: Mapped[datetime | None] = mapped_column(
        nullable=True,
        comment="任务开始时间",
    )

    # 任务完成时间
    completed_at: Mapped[datetime | None] = mapped_column(
        nullable=True,
        comment="任务完成时间",
    )

    # 错误信息（JSON 格式存储错误详情）
    error_info: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="错误信息",
    )

    # 索引定义
    __table_args__ = (
        Index("ix_tasks_status", "status"),
        Index("ix_tasks_created_at", "created_at"),
        {"comment": "漏洞挖掘任务表"},
    )

    def __repr__(self) -> str:
        return f"<Task(id={self.id}, name='{self.name}', status='{self.status}')>"
