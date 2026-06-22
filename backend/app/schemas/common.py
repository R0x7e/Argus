"""
通用 Schema 模块

提供分页响应、排序枚举、统一 API 响应包装器等通用数据模型。
"""

from enum import Enum
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

# 泛型类型变量，用于分页响应中的数据类型
T = TypeVar("T")


class SortOrder(str, Enum):
    """排序方向枚举"""
    asc = "asc"
    desc = "desc"


class PaginatedResponse(BaseModel, Generic[T]):
    """
    分页响应模型（泛型）

    用于所有列表接口的统一分页返回格式。
    """
    items: list[T] = Field(description="数据列表")
    total: int = Field(description="总记录数")
    page: int = Field(description="当前页码")
    page_size: int = Field(description="每页大小")


class ApiResponse(BaseModel, Generic[T]):
    """
    统一 API 响应包装器

    所有接口返回统一格式: code + message + data，
    方便前端统一处理。
    """
    code: int = Field(default=200, description="业务状态码")
    message: str = Field(default="success", description="响应消息")
    data: T | None = Field(default=None, description="响应数据")
