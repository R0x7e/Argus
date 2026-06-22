"""
漏洞发现模型

记录在扫描过程中发现的漏洞信息，包含类型、严重级别、证据、修复建议等。
"""

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDMixin


class Finding(UUIDMixin, Base):
    """
    漏洞发现表

    存储 Agent 发现的漏洞详细信息，包括触发路径、载荷、复现步骤等。
    """

    __tablename__ = "findings"

    # 关联任务 ID
    task_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        comment="关联任务 ID",
    )

    # 关联假设 ID（来自 Agent 推理过程）
    hypothesis_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="关联假设 ID",
    )

    # 漏洞类型（如 XSS, SQLi, SSRF, IDOR 等）
    type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="漏洞类型",
    )

    # 严重级别: critical, high, medium, low, info
    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="严重级别",
    )

    # 漏洞标题
    title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        comment="漏洞标题",
    )

    # 漏洞描述
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="漏洞描述",
    )

    # 触发路径（JSON 格式的请求链）
    trigger_path: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="触发路径",
    )

    # 攻击载荷
    payload: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="攻击载荷",
    )

    # 复现步骤（JSON 数组）
    reproduction_steps: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="复现步骤",
    )

    # 证据（截图、响应片段等）
    evidence: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="证据",
    )

    # 影响评估
    impact_assessment: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="影响评估",
    )

    # 修复建议
    fix_suggestion: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="修复建议",
    )

    # 发现状态: draft, confirmed, false_positive, reported, resolved
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="draft",
        server_default="draft",
        comment="发现状态",
    )

    # 关联报告 ID
    report_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="关联报告 ID",
    )

    # 验证时间
    verified_at: Mapped[datetime | None] = mapped_column(
        nullable=True,
        comment="验证时间",
    )

    # 索引定义
    __table_args__ = (
        Index("ix_findings_task_id", "task_id"),
        Index("ix_findings_type_severity", "type", "severity"),
        Index("ix_findings_status", "status"),
        {"comment": "漏洞发现表"},
    )

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, type='{self.type}', severity='{self.severity}')>"
