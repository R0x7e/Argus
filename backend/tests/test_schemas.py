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
            target_type="web",
            target_config={"target_url": "https://example.com"},
            strategy="web_broad",
        )
        assert task.name == "测试任务"
        assert task.target_type == "web"
        assert task.target_config["target_url"] == "https://example.com"

    def test_missing_required_field(self):
        with pytest.raises(ValidationError):
            TaskCreate(name="test")

    def test_default_config(self):
        task = TaskCreate(
            name="test",
            target_type="web",
            target_config={"target_url": "https://example.com"},
            strategy="web_broad",
        )
        assert task.config == {}

    def test_max_iterations_default(self):
        task = TaskCreate(
            name="test",
            target_type="api",
            target_config={"target_url": "https://api.example.com"},
            strategy="api_focused",
        )
        assert task.max_iterations == 5

    def test_invalid_target_type(self):
        with pytest.raises(ValidationError):
            TaskCreate(
                name="test",
                target_type="invalid_type",
                target_config={},
                strategy="web_broad",
            )


class TestFindingEnums:
    """Finding 枚举值测试"""

    def test_severity_values(self):
        assert FindingSeverity.critical == "critical"
        assert FindingSeverity.high == "high"
        assert FindingSeverity.medium == "medium"
        assert FindingSeverity.low == "low"
        assert FindingSeverity.info == "info"

    def test_status_values(self):
        assert FindingStatus.draft == "draft"
        assert FindingStatus.pending_verification == "pending_verification"
        assert FindingStatus.verified == "verified"
        assert FindingStatus.reported == "reported"
        assert FindingStatus.fixed == "fixed"
        assert FindingStatus.rejected == "rejected"


class TestPaginatedResponse:
    """分页响应测试"""

    def test_paginated_response(self):
        resp = PaginatedResponse[dict](
            items=[{"id": "1"}, {"id": "2"}],
            total=10,
            page=1,
            page_size=2,
        )
        assert len(resp.items) == 2
        assert resp.total == 10
        assert resp.page == 1
        assert resp.page_size == 2
