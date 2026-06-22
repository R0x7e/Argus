// ============================================================
// Argus API 客户端 — 基于原生 fetch 封装
// 自动注入 JWT Token 到每个请求
// ============================================================

import type {
  AgentEvent,
  Finding,
  LLMProvider,
  LLMProviderCreate,
  LLMProviderTestRequest,
  PaginatedResponse,
  Report,
  SystemStats,
  Task,
  TaskCreateRequest,
} from "@/types";
import { useAuthStore } from "@/stores/auth";

// 基础 URL：可通过环境变量覆盖，默认走 Next.js rewrite 代理
const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "";

/**
 * 通用请求函数
 * 自动拼接 API 前缀、注入 JWT Token、设置 JSON Content-Type、统一错误处理
 */
async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const token = useAuthStore.getState().token;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string>),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}/api/v1${path}`, {
    ...options,
    headers,
  });

  // Token 失效时自动登出
  if (res.status === 401) {
    useAuthStore.getState().logout();
    if (typeof window !== "undefined") {
      window.location.href = "/login";
    }
    throw new Error("认证已过期，请重新登录");
  }

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(error.detail || `HTTP ${res.status}`);
  }

  const json = await res.json();

  // 后端统一返回 {code, message, data} 结构，自动解包取 data
  if (json && typeof json === "object" && "code" in json && "data" in json) {
    return json.data as T;
  }

  return json as T;
}

// ---------------------- 认证 API ----------------------

export interface LoginData {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface UserData {
  id: string;
  username: string;
  email: string;
  role: string;
}

export const authApi = {
  login: (username: string, password: string) =>
    request<LoginData>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  register: (username: string, email: string, password: string) =>
    request<UserData>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, email, password }),
    }),

  me: () => request<UserData>("/auth/me"),
};

// ---------------------- 业务 API ----------------------

export const api = {
  // —— 任务管理 ——
  getTasks: (params?: Record<string, string>) =>
    request<PaginatedResponse<Task>>(
      `/tasks${params ? `?${new URLSearchParams(params)}` : ""}`
    ),

  getTask: (id: string) => request<Task>(`/tasks/${id}`),

  createTask: (data: TaskCreateRequest) =>
    request<Task>("/tasks", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  startTask: (id: string) =>
    request<Task>(`/tasks/${id}/start`, { method: "POST" }),

  pauseTask: (id: string) =>
    request<Task>(`/tasks/${id}/pause`, { method: "POST" }),

  resumeTask: (id: string) =>
    request<Task>(`/tasks/${id}/resume`, { method: "POST" }),

  terminateTask: (id: string) =>
    request<Task>(`/tasks/${id}/terminate`, { method: "POST" }),

  // —— 事件流 ——
  getEvents: (taskId: string, params?: Record<string, string>) =>
    request<PaginatedResponse<AgentEvent>>(
      `/tasks/${taskId}/events${params ? `?${new URLSearchParams(params)}` : ""}`
    ),

  // —— 漏洞发现 ——
  getFindings: (params?: Record<string, string>) =>
    request<PaginatedResponse<Finding>>(
      `/findings${params ? `?${new URLSearchParams(params)}` : ""}`
    ),

  getFinding: (id: string) => request<Finding>(`/findings/${id}`),

  updateFinding: (id: string, data: Partial<Finding>) =>
    request<Finding>(`/findings/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  // —— 报告 ——
  getReport: (taskId: string) =>
    request<Report>(`/tasks/${taskId}/report`),

  generateReport: (taskId: string) =>
    request<Report>(`/tasks/${taskId}/report/generate`, { method: "POST" }),

  // —— 系统 ——
  getStats: () => request<SystemStats>("/system/stats"),

  getHealth: () => request<{ status: string }>("/system/health"),
};

// ---------------------- 设置 API ----------------------

export const settingsApi = {
  getLLMProviders: () => request<LLMProvider[]>("/settings/llm-providers"),

  createLLMProvider: (data: LLMProviderCreate) =>
    request<LLMProvider>("/settings/llm-providers", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateLLMProvider: (id: string, data: Partial<LLMProviderCreate>) =>
    request<LLMProvider>(`/settings/llm-providers/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  deleteLLMProvider: (id: string) =>
    request<void>(`/settings/llm-providers/${id}`, { method: "DELETE" }),

  testLLMProvider: (data: LLMProviderTestRequest) =>
    request<{ success: boolean; latency_ms: number; error?: string }>(
      "/settings/llm-providers/test",
      { method: "POST", body: JSON.stringify(data) },
    ),
};
