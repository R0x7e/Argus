"""
Agent Schema 模块

定义 Agent 状态和黑板快照相关的响应模型。
"""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class AgentStatusResponse(BaseModel):
    """
    Agent 状态响应模型

    返回单个 Agent 的运行状态信息。
    """
    agent: str = Field(description="Agent 名称")
    status: str = Field(description="运行状态（idle/running/paused/error）")
    started_at: datetime | None = Field(default=None, description="启动时间")
    events_count: int = Field(default=0, description="事件数量")


class BlackboardSnapshot(BaseModel):
    """
    黑板快照模型

    返回任务共享黑板的当前状态摘要，供各 Agent 协调使用。
    """
    task_id: uuid.UUID = Field(description="关联任务 ID")
    version: int = Field(description="黑板版本号")
    target_profile: dict | None = Field(default=None, description="目标画像")
    attack_surface: dict | None = Field(default=None, description="攻击面信息")
    hypotheses_count: int = Field(default=0, description="假设数量")
    findings_count: int = Field(default=0, description="漏洞发现数量")
    current_phase: str = Field(default="idle", description="当前阶段")
    slot_status: dict = Field(default_factory=dict, description="槽位状态")
