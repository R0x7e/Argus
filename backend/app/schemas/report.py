"""
报告 Schema 模块

定义漏洞报告相关的响应和导出请求模型。
"""

import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class ReportResponse(BaseModel):
    """报告响应模型"""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID = Field(description="报告 ID")
    task_id: Optional[uuid.UUID] = Field(default=None, description="关联任务 ID")
    finding_id: Optional[uuid.UUID] = Field(default=None, description="关联漏洞发现 ID")
    format: str = Field(description="报告格式")
    content: str = Field(description="报告内容")
    version: int = Field(description="报告版本号")
    created_by: Optional[uuid.UUID] = Field(default=None, description="创建者用户 ID")
    submitted_to: Optional[dict] = Field(default=None, description="提交信息")
    report_metadata: Optional[dict] = Field(default=None, description="报告元数据")
    created_at: datetime = Field(description="创建时间")
    updated_at: Optional[datetime] = Field(default=None, description="更新时间")


class ReportExportRequest(BaseModel):
    """报告导出请求模型"""
    format: Literal["md", "html", "json"] = Field(description="导出格式")
