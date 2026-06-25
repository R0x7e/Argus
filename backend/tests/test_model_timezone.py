"""
模型时区一致性测试

自动遍历所有 SQLAlchemy 模型的 DateTime 字段，
检查是否都声明了 timezone=True，防止未来新增模型时遗漏。
"""

import pytest
from sqlalchemy import DateTime
from sqlalchemy.orm import DeclarativeBase

# 导入所有模型，确保它们被注册到 Base.metadata
from app.models.agent_execution import AgentExecution
from app.models.base import Base, UUIDMixin
from app.models.event import Event
from app.models.finding import Finding
from app.models.llm_provider import LLMProvider
from app.models.report import Report
from app.models.task import Task
from app.models.user import User


def _get_all_datetime_columns():
    """获取所有模型中类型为 DateTime 的列"""
    result = []
    for mapper in Base.registry.mappers:
        model_cls = mapper.class_
        if not issubclass(model_cls, DeclarativeBase):
            continue
        table = mapper.local_table
        if table is None:
            continue
        for column in table.columns:
            if isinstance(column.type, DateTime):
                result.append((model_cls.__name__, column.name, column.type))
    return result


class TestModelTimezoneConsistency:
    """验证所有模型的 DateTime 字段都启用了时区"""

    def test_all_datetime_columns_have_timezone(self):
        """所有 DateTime 列必须声明 timezone=True"""
        datetime_columns = _get_all_datetime_columns()
        assert len(datetime_columns) > 0, "未找到任何 DateTime 列，测试可能有问题"

        violations = []
        for model_name, col_name, col_type in datetime_columns:
            if not col_type.timezone:
                violations.append(
                    f"{model_name}.{col_name} 的 DateTime 类型未启用 timezone=True"
                )

        assert not violations, (
            "以下 DateTime 字段缺少 timezone=True 声明:\n  "
            + "\n  ".join(violations)
        )
