"""
LLM 供应商配置模型

存储 AI 供应商的连接信息，支持多供应商动态切换。
"""

import uuid

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDMixin


class LLMProvider(UUIDMixin, Base):
    __tablename__ = "llm_providers"

    provider_type: Mapped[str] = mapped_column(
        String(30), nullable=False, comment="供应商类型: anthropic|openai|deepseek|zhipu|qwen|custom"
    )

    display_name: Mapped[str] = mapped_column(
        String(100), nullable=False, comment="显示名称"
    )

    api_key_encrypted: Mapped[str] = mapped_column(
        Text, nullable=False, comment="加密后的 API Key"
    )

    base_url: Mapped[str | None] = mapped_column(
        String(500), nullable=True, comment="自定义 API 端点 URL"
    )

    default_model: Mapped[str] = mapped_column(
        String(100), nullable=False, comment="默认模型 ID"
    )

    models_available: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True, comment="可用模型列表"
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true", comment="是否启用"
    )

    priority: Mapped[int] = mapped_column(
        Integer, nullable=False, default=10, server_default="10", comment="优先级（越小越高）"
    )

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment="创建者"
    )

    def __repr__(self) -> str:
        return f"<LLMProvider(id={self.id}, type='{self.provider_type}', name='{self.display_name}')>"
