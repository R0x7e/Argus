"""
报告模型

存储漏洞报告的内容、格式和版本信息。
支持两种报告类型：
- 单发现报告（finding_id 非空）
- 任务汇总报告（task_id 非空，finding_id 为空）
"""

import uuid

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDMixin


class Report(UUIDMixin, Base):
    """
    漏洞报告表

    存储根据漏洞发现生成的正式报告，支持多格式和版本管理。
    """

    __tablename__ = "reports"

    # 关联任务 ID（任务汇总报告）
    task_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=True,
        comment="关联任务 ID（汇总报告）",
    )

    # 关联漏洞发现 ID（单发现报告）
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=True,
        comment="关联漏洞发现 ID",
    )

    # 报告格式: markdown, html, pdf, json
    format: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="报告格式",
    )

    # 报告内容
    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="报告内容",
    )

    # 报告版本号
    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
        comment="报告版本号",
    )

    # 创建者用户 ID
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="创建者用户 ID",
    )

    # 提交信息（JSON 格式，记录提交到哪些平台）
    submitted_to: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="提交信息",
    )

    # 报告元数据（严重级别分布等）
    report_metadata: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="报告元数据",
    )

    def __repr__(self) -> str:
        return f"<Report(id={self.id}, format='{self.format}', version={self.version})>"
