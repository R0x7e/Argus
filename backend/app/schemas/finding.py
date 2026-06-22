"""
漏洞发现 Schema 模块

定义漏洞发现相关的请求/响应模型和枚举类型。
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class FindingSeverity(str, Enum):
    """漏洞严重级别枚举"""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingStatus(str, Enum):
    """漏洞发现状态枚举"""
    draft = "draft"
    pending_verification = "pending_verification"
    verified = "verified"
    reported = "reported"
    fixed = "fixed"
    rejected = "rejected"


class FindingResponse(BaseModel):
    """
    漏洞发现响应模型

    返回漏洞发现的完整信息，支持从 ORM 对象自动转换。
    """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID = Field(description="漏洞发现 ID")
    task_id: uuid.UUID = Field(description="关联任务 ID")
    hypothesis_id: uuid.UUID | None = Field(default=None, description="关联假设 ID")
    type: str = Field(description="漏洞类型")
    severity: str = Field(description="严重级别")
    title: str = Field(description="漏洞标题")
    description: str = Field(description="漏洞描述")
    trigger_path: Any | None = Field(default=None, description="触发路径")
    payload: str | None = Field(default=None, description="攻击载荷")
    reproduction_steps: Any | None = Field(default=None, description="复现步骤")
    evidence: Any | None = Field(default=None, description="证据")
    impact_assessment: str | None = Field(default=None, description="影响评估")
    fix_suggestion: str | None = Field(default=None, description="修复建议")
    status: str = Field(description="发现状态")
    report_id: uuid.UUID | None = Field(default=None, description="关联报告 ID")
    verified_at: datetime | None = Field(default=None, description="验证时间")
    created_at: datetime = Field(description="创建时间")
    updated_at: datetime | None = Field(default=None, description="更新时间")


class FindingUpdate(BaseModel):
    """
    更新漏洞发现请求模型

    所有字段可选，仅更新传入的字段。
    """
    status: Optional[str] = Field(default=None, description="发现状态")
    severity: Optional[str] = Field(default=None, description="严重级别")
    title: Optional[str] = Field(default=None, description="漏洞标题")
    fix_suggestion: Optional[str] = Field(default=None, description="修复建议")
