"""
事件 Schema 模块

定义事件相关的响应和过滤数据模型。
"""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class EventResponse(BaseModel):
    """
    事件响应模型

    返回事件的完整信息，支持从 ORM 对象自动转换。
    """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID = Field(description="事件 ID")
    task_id: uuid.UUID = Field(description="关联任务 ID")
    parent_event_id: uuid.UUID | None = Field(default=None, description="父事件 ID")
    agent: str = Field(description="Agent 名称")
    type: str = Field(description="事件类型")
    timestamp: datetime = Field(description="事件时间戳")
    data: dict = Field(description="事件数据")
    tags: list[str] = Field(default_factory=list, description="事件标签")
    confidence: float | None = Field(default=None, description="置信度")
    cost: dict | None = Field(default=None, description="成本信息")


class EventFilter(BaseModel):
    """
    事件过滤条件

    支持按 Agent、类型、时间范围筛选事件。
    """
    agent: Optional[str] = Field(default=None, description="按 Agent 名称筛选")
    type: Optional[str] = Field(default=None, description="按事件类型筛选")
    after: Optional[datetime] = Field(default=None, description="起始时间（不含）")
    before: Optional[datetime] = Field(default=None, description="截止时间（不含）")
