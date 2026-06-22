"""
Argus Schema 模块

导出所有 Pydantic 数据模型，供 API 路由和业务逻辑使用。
"""

from app.schemas.agent import AgentStatusResponse, BlackboardSnapshot
from app.schemas.common import ApiResponse, PaginatedResponse, SortOrder
from app.schemas.event import EventFilter, EventResponse
from app.schemas.finding import (
    FindingResponse,
    FindingSeverity,
    FindingStatus,
    FindingUpdate,
)
from app.schemas.report import ReportExportRequest, ReportResponse
from app.schemas.task import TaskCreate, TaskListFilter, TaskResponse, TaskUpdate

__all__ = [
    # 通用
    "ApiResponse",
    "PaginatedResponse",
    "SortOrder",
    # 任务
    "TaskCreate",
    "TaskResponse",
    "TaskUpdate",
    "TaskListFilter",
    # 事件
    "EventResponse",
    "EventFilter",
    # 漏洞发现
    "FindingResponse",
    "FindingUpdate",
    "FindingSeverity",
    "FindingStatus",
    # 报告
    "ReportResponse",
    "ReportExportRequest",
    # Agent
    "AgentStatusResponse",
    "BlackboardSnapshot",
]
