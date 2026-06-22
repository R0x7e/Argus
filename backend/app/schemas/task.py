"""
任务 Schema 模块

定义任务相关的请求/响应数据模型，用于 API 接口的数据校验和序列化。
"""

import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, computed_field


class TaskCreate(BaseModel):
    """
    创建任务请求模型

    包含新建漏洞挖掘任务所需的全部参数。
    """
    name: str = Field(description="任务名称")
    target_type: Literal["web", "api", "mobile", "binary", "llm_app"] = Field(
        description="目标类型"
    )
    target_config: dict = Field(description="目标配置（URL、范围等）")
    strategy: Literal[
        "web_broad", "web_deep", "api_focused",
        "mobile_re", "binary_fuzz", "llm_specific"
    ] = Field(description="测试策略")
    config: dict = Field(default_factory=dict, description="任务配置（预算、并发等）")
    max_iterations: int = Field(default=5, ge=1, description="最大迭代次数")


class TaskResponse(BaseModel):
    """
    任务响应模型

    返回任务的完整信息，支持从 ORM 对象自动转换。
    """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID = Field(description="任务 ID")
    name: str = Field(description="任务名称")
    target_type: str = Field(description="目标类型")
    strategy: str = Field(description="测试策略")
    status: str = Field(description="任务状态")
    progress: dict | None = Field(default=None, description="任务进度")
    config: dict | None = Field(default=None, description="任务配置")
    target_config: dict = Field(default_factory=dict, description="目标配置")
    created_at: datetime = Field(description="创建时间")
    started_at: datetime | None = Field(default=None, description="开始时间")
    completed_at: datetime | None = Field(default=None, description="完成时间")
    findings_count: int = Field(default=0, description="漏洞发现数量")
    error_info: dict | None = Field(default=None, description="错误信息")

    @computed_field
    @property
    def target_url(self) -> str:
        return self.target_config.get("target_url", "")

    def model_post_init(self, __context) -> None:
        if self.findings_count == 0 and self.progress:
            fc = self.progress.get("findings_count", 0)
            if fc:
                object.__setattr__(self, "findings_count", fc)


class TaskUpdate(BaseModel):
    """
    更新任务请求模型

    所有字段可选，仅更新传入的字段。
    """
    name: Optional[str] = Field(default=None, description="任务名称")
    config: Optional[dict] = Field(default=None, description="任务配置")
    max_iterations: Optional[int] = Field(default=None, ge=1, description="最大迭代次数")


class TaskListFilter(BaseModel):
    """
    任务列表过滤条件

    支持按状态和目标类型筛选任务。
    """
    status: Optional[str] = Field(default=None, description="按状态筛选")
    target_type: Optional[str] = Field(default=None, description="按目标类型筛选")
