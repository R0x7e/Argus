// ============================================================
// Argus 前端类型定义 — 与后端 FastAPI schema 保持一致
// ============================================================

/** 任务状态 */
export type TaskStatus = "created" | "pending" | "running" | "paused" | "completed" | "done" | "failed" | "terminated";

/** 漏洞严重级别 */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** 扫描任务 */
export interface Task {
  id: string;
  name: string;
  target_type: string;
  strategy: string;
  status: TaskStatus;
  progress: Record<string, any> | null;
  config: Record<string, any> | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  findings_count: number;
  error_info: Record<string, any> | null;
  agents?: TaskAgent[];
  // derived for display
  target_url?: string;
}

/** 任务关联的 Agent 信息 */
export interface TaskAgent {
  id: string;
  role: string;
  status: string;
}

/** Agent 事件（实时日志流） */
export interface AgentEvent {
  id: string;
  task_id: string;
  agent: string;
  agent_role?: string;
  event_type: string;
  type?: string;
  data: Record<string, any>;
  timestamp: string;
}

/** 漏洞发现 */
export interface Finding {
  id: string;
  task_id: string;
  hypothesis_id?: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: string;
  title: string;
  description: string;
  trigger_path?: any;
  payload?: string;
  reproduction_steps?: any;
  evidence?: Record<string, any>;
  impact_assessment?: string;
  fix_suggestion?: string;
  report_id?: string;
  verified_at?: string;
  created_at: string;
  updated_at?: string;
}

/** 扫描报告 */
export interface Report {
  id: string;
  task_id?: string;
  finding_id?: string;
  content: string;
  format: string;
  version: number;
  created_by?: string;
  submitted_to?: Record<string, any>;
  report_metadata?: Record<string, any>;
  created_at: string;
  updated_at?: string;
}

/** 分页响应 */
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages?: number;
}

/** 统一 API 响应包装 */
export interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
}

/** 仪表盘统计数据 */
export interface SystemStats {
  total_tasks: number;
  running_tasks: number;
  total_findings: number;
  critical_findings: number;
}

/** Agent 运行状态（监控面板用） */
export interface AgentStatus {
  agent_name: string;
  status: string;
  current_action: string;
  iterations_completed: number;
  token_usage: number;
}

/** 创建任务请求体 */
export interface TaskCreateRequest {
  name: string;
  target_type: "web" | "api" | "mobile" | "binary" | "llm_app";
  target_config: Record<string, any>;
  strategy: "web_broad" | "web_deep" | "api_focused" | "mobile_re" | "binary_fuzz" | "llm_specific";
  config?: Record<string, any>;
  max_iterations?: number;
}

// ---------------------- LLM 供应商配置 ----------------------

export type LLMProviderType = "anthropic" | "openai" | "deepseek" | "zhipu" | "qwen" | "custom";

export interface LLMProvider {
  id: string;
  provider_type: LLMProviderType;
  display_name: string;
  api_key_masked: string;
  base_url: string | null;
  default_model: string;
  models_available: string[] | null;
  is_active: boolean;
  priority: number;
  created_at: string;
  updated_at: string | null;
}

export interface LLMProviderCreate {
  provider_type: LLMProviderType;
  display_name: string;
  api_key: string;
  base_url?: string;
  default_model: string;
  models_available?: string[];
  is_active?: boolean;
  priority?: number;
}

export interface LLMProviderTestRequest {
  provider_type: LLMProviderType;
  api_key: string;
  base_url?: string;
  model: string;
}
