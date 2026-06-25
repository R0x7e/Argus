"""初始数据库 Schema - 创建所有核心表

Revision ID: 001
Revises:
Create Date: 2025-01-01 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# 版本标识
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    升级迁移 - 创建所有核心表

    创建以下表：
    - users: 用户表
    - tasks: 漏洞挖掘任务表
    - events: Agent 事件流表
    - findings: 漏洞发现表
    - reports: 漏洞报告表
    - agent_executions: Agent 执行记录表
    """

    # === 用户表 ===
    op.create_table(
        "users",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
            comment="主键 UUID",
        ),
        sa.Column(
            "username",
            sa.String(100),
            unique=True,
            nullable=False,
            comment="用户名",
        ),
        sa.Column(
            "email",
            sa.String(200),
            unique=True,
            nullable=False,
            comment="邮箱地址",
        ),
        sa.Column(
            "password_hash",
            sa.String(500),
            nullable=False,
            comment="密码哈希值",
        ),
        sa.Column(
            "role",
            sa.String(20),
            nullable=False,
            server_default="operator",
            comment="用户角色",
        ),
        sa.Column(
            "last_login_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="最后登录时间",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            comment="创建时间",
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            comment="更新时间",
        ),
        comment="用户表",
    )

    # === 任务表 ===
    op.create_table(
        "tasks",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
            comment="主键 UUID",
        ),
        sa.Column(
            "name",
            sa.String(200),
            nullable=False,
            comment="任务名称",
        ),
        sa.Column(
            "target_type",
            sa.String(50),
            nullable=False,
            comment="目标类型",
        ),
        sa.Column(
            "target_config",
            postgresql.JSONB,
            nullable=False,
            comment="目标配置（JSONB）",
        ),
        sa.Column(
            "strategy",
            sa.String(50),
            nullable=False,
            comment="测试策略",
        ),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default="created",
            comment="任务状态",
        ),
        sa.Column(
            "progress",
            postgresql.JSONB,
            nullable=True,
            comment="任务进度",
        ),
        sa.Column(
            "config",
            postgresql.JSONB,
            nullable=True,
            comment="任务配置",
        ),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
            comment="创建者用户 ID",
        ),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="任务开始时间",
        ),
        sa.Column(
            "completed_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="任务完成时间",
        ),
        sa.Column(
            "error_info",
            postgresql.JSONB,
            nullable=True,
            comment="错误信息",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            comment="创建时间",
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            comment="更新时间",
        ),
        comment="漏洞挖掘任务表",
    )
    # 任务表索引
    op.create_index("ix_tasks_status", "tasks", ["status"])
    op.create_index("ix_tasks_created_at", "tasks", ["created_at"])

    # === 事件表 ===
    op.create_table(
        "events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
            comment="主键 UUID",
        ),
        sa.Column(
            "task_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tasks.id", ondelete="CASCADE"),
            nullable=False,
            comment="关联任务 ID",
        ),
        sa.Column(
            "parent_event_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
            comment="父事件 ID",
        ),
        sa.Column(
            "agent",
            sa.String(50),
            nullable=False,
            comment="Agent 名称",
        ),
        sa.Column(
            "type",
            sa.String(50),
            nullable=False,
            comment="事件类型",
        ),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
            comment="事件时间戳",
        ),
        sa.Column(
            "data",
            postgresql.JSONB,
            nullable=False,
            comment="事件数据",
        ),
        sa.Column(
            "tags",
            postgresql.ARRAY(sa.String),
            nullable=True,
            comment="事件标签",
        ),
        sa.Column(
            "confidence",
            sa.Float,
            nullable=True,
            comment="置信度",
        ),
        sa.Column(
            "cost",
            postgresql.JSONB,
            nullable=True,
            comment="成本信息",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            comment="创建时间",
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            comment="更新时间",
        ),
        comment="Agent 事件流表",
    )
    # 事件表索引
    op.create_index("ix_events_task_id_timestamp", "events", ["task_id", "timestamp"])
    op.create_index("ix_events_task_id_agent", "events", ["task_id", "agent"])

    # === 报告表（先创建，不含 finding_id FK，解决循环依赖） ===
    op.create_table(
        "reports",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
            comment="主键 UUID",
        ),
        # 关联任务 ID（任务汇总报告）
        sa.Column(
            "task_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tasks.id", ondelete="CASCADE"),
            nullable=True,
            comment="关联任务 ID（汇总报告）",
        ),
        # finding_id FK 稍后添加（解决循环依赖）
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
            comment="关联漏洞发现 ID",
        ),
        sa.Column(
            "format",
            sa.String(20),
            nullable=False,
            comment="报告格式",
        ),
        sa.Column(
            "content",
            sa.Text,
            nullable=False,
            comment="报告内容",
        ),
        sa.Column(
            "version",
            sa.Integer,
            nullable=False,
            server_default="1",
            comment="报告版本号",
        ),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
            comment="创建者用户 ID",
        ),
        sa.Column(
            "submitted_to",
            postgresql.JSONB,
            nullable=True,
            comment="提交信息",
        ),
        # 报告元数据（严重级别分布等）
        sa.Column(
            "report_metadata",
            postgresql.JSONB,
            nullable=True,
            comment="报告元数据",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            comment="创建时间",
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            comment="更新时间",
        ),
        comment="漏洞报告表",
    )

    # === 漏洞发现表（reports 已存在，可安全引用） ===
    op.create_table(
        "findings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
            comment="主键 UUID",
        ),
        sa.Column(
            "task_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tasks.id", ondelete="CASCADE"),
            nullable=False,
            comment="关联任务 ID",
        ),
        sa.Column(
            "hypothesis_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
            comment="关联假设 ID",
        ),
        sa.Column(
            "type",
            sa.String(50),
            nullable=False,
            comment="漏洞类型",
        ),
        sa.Column(
            "severity",
            sa.String(20),
            nullable=False,
            comment="严重级别",
        ),
        sa.Column(
            "title",
            sa.String(500),
            nullable=False,
            comment="漏洞标题",
        ),
        sa.Column(
            "description",
            sa.Text,
            nullable=False,
            comment="漏洞描述",
        ),
        sa.Column(
            "trigger_path",
            postgresql.JSONB,
            nullable=True,
            comment="触发路径",
        ),
        sa.Column(
            "payload",
            sa.Text,
            nullable=True,
            comment="攻击载荷",
        ),
        sa.Column(
            "reproduction_steps",
            postgresql.JSONB,
            nullable=True,
            comment="复现步骤",
        ),
        sa.Column(
            "evidence",
            postgresql.JSONB,
            nullable=True,
            comment="证据",
        ),
        sa.Column(
            "impact_assessment",
            sa.Text,
            nullable=True,
            comment="影响评估",
        ),
        sa.Column(
            "fix_suggestion",
            sa.Text,
            nullable=True,
            comment="修复建议",
        ),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default="draft",
            comment="发现状态",
        ),
        sa.Column(
            "report_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("reports.id", ondelete="SET NULL"),
            nullable=True,
            comment="关联报告 ID",
        ),
        sa.Column(
            "verified_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="验证时间",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            comment="创建时间",
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            comment="更新时间",
        ),
        comment="漏洞发现表",
    )
    # 漏洞发现表索引
    op.create_index("ix_findings_task_id", "findings", ["task_id"])
    op.create_index("ix_findings_type_severity", "findings", ["type", "severity"])
    op.create_index("ix_findings_status", "findings", ["status"])

    # 添加 reports.finding_id 外键（findings 表已创建，解决循环依赖）
    op.create_foreign_key(
        "fk_reports_finding_id",
        "reports",
        "findings",
        ["finding_id"],
        ["id"],
        ondelete="CASCADE",
    )

    # === Agent 执行记录表 ===
    op.create_table(
        "agent_executions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
            comment="主键 UUID",
        ),
        sa.Column(
            "task_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tasks.id", ondelete="CASCADE"),
            nullable=False,
            comment="关联任务 ID",
        ),
        sa.Column(
            "agent",
            sa.String(50),
            nullable=False,
            comment="Agent 名称",
        ),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            comment="执行状态",
        ),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            comment="开始时间",
        ),
        sa.Column(
            "completed_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="完成时间",
        ),
        sa.Column(
            "cost",
            postgresql.JSONB,
            nullable=True,
            comment="成本信息",
        ),
        sa.Column(
            "summary",
            sa.Text,
            nullable=True,
            comment="执行摘要",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            comment="创建时间",
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            comment="更新时间",
        ),
        comment="Agent 执行记录表",
    )

    # === LLM 供应商配置表 ===
    op.create_table(
        "llm_providers",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
            comment="主键 UUID",
        ),
        sa.Column(
            "provider_type",
            sa.String(30),
            nullable=False,
            comment="供应商类型: anthropic|openai|deepseek|zhipu|qwen|custom",
        ),
        sa.Column(
            "display_name",
            sa.String(100),
            nullable=False,
            comment="显示名称",
        ),
        sa.Column(
            "api_key_encrypted",
            sa.Text,
            nullable=False,
            comment="加密后的 API Key",
        ),
        sa.Column(
            "base_url",
            sa.String(500),
            nullable=True,
            comment="自定义 API 端点 URL",
        ),
        sa.Column(
            "default_model",
            sa.String(100),
            nullable=False,
            comment="默认模型 ID",
        ),
        sa.Column(
            "models_available",
            postgresql.JSONB,
            nullable=True,
            comment="可用模型列表",
        ),
        sa.Column(
            "is_active",
            sa.Boolean,
            nullable=False,
            server_default="true",
            comment="是否启用",
        ),
        sa.Column(
            "priority",
            sa.Integer,
            nullable=False,
            server_default="10",
            comment="优先级（越小越高）",
        ),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
            comment="创建者",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            comment="创建时间",
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            comment="更新时间",
        ),
        comment="LLM 供应商配置表",
    )


def downgrade() -> None:
    """
    降级迁移 - 按依赖逆序删除所有表
    """
    # 按外键依赖逆序删除
    op.drop_table("llm_providers")
    op.drop_table("agent_executions")
    op.drop_table("reports")
    op.drop_index("ix_findings_status", table_name="findings")
    op.drop_index("ix_findings_type_severity", table_name="findings")
    op.drop_index("ix_findings_task_id", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_events_task_id_agent", table_name="events")
    op.drop_index("ix_events_task_id_timestamp", table_name="events")
    op.drop_table("events")
    op.drop_index("ix_tasks_created_at", table_name="tasks")
    op.drop_index("ix_tasks_status", table_name="tasks")
    op.drop_table("tasks")
    op.drop_table("users")
