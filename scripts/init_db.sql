-- Argus 数据库初始化脚本
-- 在 PostgreSQL 容器首次启动时执行
-- 注意：此脚本应与 Alembic 迁移 (001_initial_schema.py) 保持一致

-- 启用 UUID 扩展
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- === 用户表 ===
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(200) NOT NULL UNIQUE,
    password_hash VARCHAR(500) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'operator',
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- === 任务表 ===
CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_config JSONB NOT NULL,
    strategy VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'created',
    progress JSONB,
    config JSONB,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_info JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS ix_tasks_created_at ON tasks(created_at);

-- === 事件表 ===
CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    parent_event_id UUID,
    agent VARCHAR(50) NOT NULL,
    type VARCHAR(50) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data JSONB NOT NULL,
    tags TEXT[],
    confidence FLOAT,
    cost JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_events_task_id_timestamp ON events(task_id, timestamp);
CREATE INDEX IF NOT EXISTS ix_events_task_id_agent ON events(task_id, agent);

-- === 报告表 (需在 findings 之前创建，因为 findings.report_id 引用 reports) ===
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID REFERENCES tasks(id) ON DELETE CASCADE,
    finding_id UUID,  -- 稍后添加 FK (findings 表创建后)
    format VARCHAR(20) NOT NULL,
    content TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    submitted_to JSONB,
    report_metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- === 漏洞发现表 ===
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    hypothesis_id UUID,
    type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    trigger_path JSONB,
    payload TEXT,
    reproduction_steps JSONB,
    evidence JSONB,
    impact_assessment TEXT,
    fix_suggestion TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'draft',
    report_id UUID REFERENCES reports(id) ON DELETE SET NULL,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_findings_task_id ON findings(task_id);
CREATE INDEX IF NOT EXISTS ix_findings_type_severity ON findings(type, severity);
CREATE INDEX IF NOT EXISTS ix_findings_status ON findings(status);

-- 延迟添加 reports.finding_id 外键 (findings 表已创建)
ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_finding_id_fkey;
ALTER TABLE reports ADD CONSTRAINT reports_finding_id_fkey
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE;

-- === Agent 执行记录表 ===
CREATE TABLE IF NOT EXISTS agent_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    agent VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    cost JSONB,
    summary TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- === LLM 供应商配置表 ===
CREATE TABLE IF NOT EXISTS llm_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_type VARCHAR(30) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    api_key_encrypted TEXT NOT NULL,
    base_url VARCHAR(500),
    default_model VARCHAR(100) NOT NULL,
    models_available JSONB,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    priority INTEGER NOT NULL DEFAULT 10,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
