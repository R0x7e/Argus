"""
SQLAlchemy 模型基类

提供声明式基类和通用 UUID 混入，所有模型继承此基类。
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """SQLAlchemy 声明式基类"""
    pass


class UUIDMixin:
    """
    UUID 主键混入

    为模型提供:
    - id: UUID 主键（数据库端自动生成）
    - created_at: 创建时间（数据库端自动设置）
    - updated_at: 更新时间（每次更新自动刷新）
    """

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        comment="主键 UUID",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        comment="创建时间",
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        onupdate=func.now(),
        server_default=func.now(),
        comment="更新时间",
    )
