"""
用户模型

存储系统用户信息，支持认证和角色管理。
"""

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDMixin


class User(UUIDMixin, Base):
    """
    用户表

    存储系统用户的基本信息，包括认证凭据和角色。
    """

    __tablename__ = "users"

    # 用户名（唯一）
    username: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        comment="用户名",
    )

    # 邮箱地址
    email: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        comment="邮箱地址",
    )

    # 密码哈希值
    password_hash: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        comment="密码哈希值",
    )

    # 用户角色: admin, operator, viewer
    role: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="operator",
        server_default="operator",
        comment="用户角色",
    )

    # 最后登录时间
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="最后登录时间",
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"
