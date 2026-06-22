"""
Pydantic Schema 单元测试

验证请求/响应 schema 的序列化、校验和默认值行为。
"""

import pytest
from pydantic import ValidationError

from app.schemas.task import TaskCreate, TaskResponse
from app.schemas.finding import FindingSeverity, FindingStatus
from app.schemas.common import PaginatedResponse


class TestTaskCreate:
    """TaskCreate schema 测试"""

    def test_valid_task(self):
        task = TaskCreate(
            name="测试任务",
            target_url="https://example.com",
            task_type="web_scan",
        )
        assert task.name == "测试任务"
        assert task.target_url == "https://example.com"

    def test_missing_required_field(self):
        with pytest.raises(ValidationError):
            TaskCreate(name="test")

    def test_default_config(self):
        task = TaskCreate(
            name="test",
            target_url="https://example.com",
            task_type="web_scan",
        )
        assert task.config == {} or task.config is not None


class TestFindingEnums:
    """Finding 枚举值测试"""

    def test_severity_values(self):
        assert FindingSeverity.CRITICAL == "critical"
        assert FindingSeverity.HIGH == "high"
        assert FindingSeverity.MEDIUM == "medium"
        assert FindingSeverity.LOW == "low"

    def test_status_values(self):
        assert FindingStatus.UNCONFIRMED == "unconfirmed"
        assert FindingStatus.CONFIRMED == "confirmed"
        assert FindingStatus.FALSE_POSITIVE == "false_positive"


class TestPaginatedResponse:
    """分页响应测试"""

    def test_paginated_response(self):
        resp = PaginatedResponse[dict](
            items=[{"id": "1"}, {"id": "2"}],
            total=10,
            page=1,
            page_size=2,
            total_pages=5,
        )
        assert len(resp.items) == 2
        assert resp.total == 10
        assert resp.total_pages == 5
