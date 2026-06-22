"use client";

import { useParams } from "next/navigation";
import { useState, useEffect, useRef, useMemo } from "react";
import Link from "next/link";
import { MainLayout } from "@/components/layout/main-layout";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Loading } from "@/components/ui/loading";
import { EmptyState } from "@/components/ui/empty-state";
import { useTask, useTaskAction } from "@/hooks/use-tasks";
import { useEventStream } from "@/hooks/use-events";
import { useFindings } from "@/hooks/use-findings";
import { formatDate } from "@/lib/utils";
import type { AgentEvent } from "@/types";
import {
  Play,
  Pause,
  Square,
  Wifi,
  WifiOff,
  User,
  Filter,
  ArrowDown,
  Shield,
  Activity,
  FileText,
} from "lucide-react";

// ============================================================
// Agent 角色颜色映射（用于事件流中的 Agent 标签）
// ============================================================
const agentColors: Record<string, string> = {
  orchestrator: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  hypothesizer: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  verifier: "bg-red-500/20 text-red-400 border-red-500/30",
  reporter: "bg-green-500/20 text-green-400 border-green-500/30",
  system: "bg-slate-500/20 text-slate-400 border-slate-500/30",
  coordinator: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  scanner: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  analyzer: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  exploiter: "bg-red-500/20 text-red-400 border-red-500/30",
};

function getAgentColor(role: string) {
  return agentColors[role] ?? "bg-slate-500/20 text-slate-400 border-slate-500/30";
}

// ============================================================
// 事件类型图标和颜色
// ============================================================
const eventTypeStyle: Record<string, string> = {
  agent_started: "text-green-400",
  agent_stopped: "text-slate-400",
  tool_call: "text-blue-400",
  tool_result: "text-cyan-400",
  thinking: "text-yellow-400",
  finding: "text-red-400",
  finding_confirmed: "text-red-400",
  error: "text-red-500",
  progress: "text-indigo-400",
  log: "text-slate-400",
  recon_complete: "text-blue-300",
  target_profiled: "text-emerald-400",
  decision: "text-purple-400",
  hypotheses_generated: "text-amber-400",
  verification_start: "text-orange-400",
  tool_verification: "text-cyan-300",
  false_positive: "text-slate-500",
  risk_skipped: "text-orange-300",
  verification_complete: "text-green-300",
  report_generated: "text-emerald-300",
  max_iterations_reached: "text-yellow-300",
  no_pending: "text-slate-500",
};

/** 从事件数据中提取摘要显示文本 */
function getEventSummary(event: AgentEvent): string {
  const type = event.type ?? event.event_type;
  const data = event.data;
  if (data.message && typeof data.message === "string") return data.message;
  if (data.summary && typeof data.summary === "string") return data.summary;

  switch (type) {
    case "agent_started":
      return `Agent ${data.node ?? event.agent_role ?? event.agent} 已启动`;
    case "agent_stopped":
      return `Agent ${data.node ?? event.agent_role ?? event.agent} 已停止`;
    case "tool_call":
      return `调用工具: ${data.tool_name ?? "unknown"}`;
    case "tool_result":
      return `${data.tool_name ?? "工具"}${data.success ? " 成功" : " 失败"}${data.summary ? ` - ${data.summary}` : ""}`;
    case "thinking":
      return (data.content as string)?.slice(0, 120) ?? "思考中...";
    case "finding":
    case "finding_confirmed":
      return `发现漏洞: [${(data.severity as string)?.toUpperCase() ?? "?"}] ${data.type ?? data.title ?? "未知"}`;
    case "error":
      return `错误: ${data.error ?? data.content ?? "未知错误"}`;
    case "progress":
      return (data.content as string) ?? `进度: ${data.progress ?? "—"}%`;
    case "recon_complete":
      return `侦察完成: ${data.subdomains_found ?? 0} 子域名, ${data.ports_found ?? 0} 端口, ${data.dirs_found ?? 0} 目录`;
    case "target_profiled":
      return `目标画像完成, ${data.attack_surface_endpoints ?? 0} 个攻击面端点`;
    case "decision":
      return `决策: ${data.next_action ?? "?"} - ${(data.reasoning as string)?.slice(0, 80) ?? ""}`;
    case "hypotheses_generated":
      return `生成 ${data.count ?? 0} 个假设: ${(data.types as string[])?.join(", ") ?? ""}`;
    case "verification_start":
      return `开始验证 ${data.pending_count ?? 0} 个假设`;
    case "tool_verification":
      return `工具验证: ${data.tool_used ?? "无"} → ${data.tool_verified ? "确认" : "未确认"}`;
    case "false_positive":
      return `误报: ${data.reason ?? "验证未通过"}`;
    case "risk_skipped":
      return `风险跳过: 假设 ${data.hypothesis_id?.slice(0, 8)} 风险等级 ${data.risk_level}`;
    case "verification_complete":
      return `验证完成: ${data.findings_count ?? 0} 个发现, ${data.false_positives_count ?? 0} 个误报`;
    case "report_generated":
      return `报告生成: ${data.findings_count ?? 0} 个漏洞, ${data.recommendations_count ?? 0} 条建议`;
    case "max_iterations_reached":
      return `已达最大迭代 (${data.iteration}/${data.max_iterations})，转入报告`;
    case "no_pending":
      return data.content ?? "没有待处理项";
    case "log":
      return (data.content as string) ?? "";
    default:
      return JSON.stringify(data).slice(0, 100);
  }
}

// ============================================================
// 主组件
// ============================================================

export default function TaskMonitorPage() {
  const params = useParams();
  const taskId = params.id as string;

  // 数据源
  const { data: task, isLoading: taskLoading } = useTask(taskId);
  const { events, connected } = useEventStream(taskId);
  const { data: findingsData } = useFindings(
    taskId ? { task_id: taskId } : undefined
  );
  const taskAction = useTaskAction();

  // 事件流筛选
  const [agentFilter, setAgentFilter] = useState<string>("all");
  const [autoScroll, setAutoScroll] = useState(true);
  const eventListRef = useRef<HTMLDivElement>(null);

  // 收集所有出现过的 agent 角色，用于筛选下拉
  const agentRoles = useMemo(() => {
    const roles = new Set<string>();
    events.forEach((e) => roles.add(e.agent_role ?? e.agent));
    return Array.from(roles);
  }, [events]);

  // 从事件流推导 Agent 状态（当 task.agents 为空时）
  const derivedAgents = useMemo(() => {
    const agentMap = new Map<string, { role: string; status: string; eventCount: number }>();
    events.forEach((e) => {
      const role = e.agent_role ?? e.agent;
      if (!role || role === "system") return;
      const type = e.type ?? e.event_type;
      const existing = agentMap.get(role);
      if (!existing) {
        agentMap.set(role, { role, status: "idle", eventCount: 1 });
      } else {
        existing.eventCount++;
      }
      const entry = agentMap.get(role)!;
      if (type === "agent_started") entry.status = "running";
      else if (type === "agent_stopped") entry.status = "idle";
    });
    return Array.from(agentMap.values());
  }, [events]);

  // 过滤后的事件
  const filteredEvents = useMemo(() => {
    if (agentFilter === "all") return events;
    return events.filter((e) => (e.agent_role ?? e.agent) === agentFilter);
  }, [events, agentFilter]);

  // 自动滚动到底部
  useEffect(() => {
    if (autoScroll && eventListRef.current) {
      eventListRef.current.scrollTop = eventListRef.current.scrollHeight;
    }
  }, [filteredEvents, autoScroll]);

  /** 检测用户是否手动滚动 */
  const handleEventScroll = () => {
    if (!eventListRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = eventListRef.current;
    // 如果距离底部超过 100px，认为用户在查看历史
    setAutoScroll(scrollHeight - scrollTop - clientHeight < 100);
  };

  /** 任务操作 */
  const handleAction = (action: "start" | "pause" | "resume" | "terminate") => {
    taskAction.mutate({ taskId, action });
  };

  if (taskLoading) {
    return (
      <MainLayout title="任务监控">
        <Loading size="lg" label="加载任务详情..." />
      </MainLayout>
    );
  }

  if (!task) {
    return (
      <MainLayout title="任务监控">
        <EmptyState title="任务不存在" description="找不到该任务，可能已被删除" />
      </MainLayout>
    );
  }

  return (
    <MainLayout title={`任务监控 - ${task.name}`}>
      {/* ========== 顶部：任务信息 + 控制按钮 ========== */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Badge status={task.status}>{task.status}</Badge>
          <span className="text-sm text-slate-400">目标: {task.target_url}</span>
          {/* WebSocket 连接指示 */}
          <span className="flex items-center gap-1 text-xs text-slate-500">
            {connected ? (
              <>
                <Wifi className="h-3 w-3 text-green-400" /> 已连接
              </>
            ) : (
              <>
                <WifiOff className="h-3 w-3 text-red-400" /> 未连接
              </>
            )}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {(task.status === "pending" || task.status === "created") && (
            <Button
              variant="primary"
              size="sm"
              onClick={() => handleAction("start")}
              loading={taskAction.isPending}
            >
              <Play className="h-3 w-3" /> 启动
            </Button>
          )}
          {task.status === "running" && (
            <>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => handleAction("pause")}
                loading={taskAction.isPending && taskAction.variables?.action === "pause"}
              >
                <Pause className="h-3 w-3" /> 暂停
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={() => handleAction("terminate")}
                loading={taskAction.isPending && taskAction.variables?.action === "terminate"}
              >
                <Square className="h-3 w-3" /> 终止
              </Button>
            </>
          )}
          {task.status === "paused" && (
            <>
              <Button
                variant="primary"
                size="sm"
                onClick={() => handleAction("resume")}
                loading={taskAction.isPending && taskAction.variables?.action === "resume"}
              >
                <Play className="h-3 w-3" /> 恢复
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={() => handleAction("terminate")}
                loading={taskAction.isPending && taskAction.variables?.action === "terminate"}
              >
                <Square className="h-3 w-3" /> 终止
              </Button>
            </>
          )}
          {(task.status === "completed" || task.status === "failed") && (
            <Link href={`/tasks/${taskId}/report`}>
              <Button variant="secondary" size="sm">
                <FileText className="h-3 w-3" /> 查看报告
              </Button>
            </Link>
          )}
        </div>
      </div>

      {/* ========== 三栏布局 ========== */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        {/* -------- 左栏：Agent 状态面板 -------- */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>
              <User className="mr-1 inline h-4 w-4" />
              Agent 状态
            </CardTitle>
          </CardHeader>
          <CardContent>
            {(task.agents ?? []).length === 0 && derivedAgents.length === 0 ? (
              <p className="text-xs text-slate-500">等待 Agent 启动...</p>
            ) : (task.agents ?? []).length > 0 ? (
              <div className="space-y-3">
                {(task.agents ?? []).map((agent) => {
                  const iterations = events.filter(
                    (e) => e.agent === agent.id
                  ).length;

                  return (
                    <div
                      key={agent.id}
                      className="rounded-md border border-argus-border/50 bg-argus-dark p-3"
                    >
                      <div className="mb-1.5 flex items-center justify-between">
                        <span
                          className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${getAgentColor(agent.role)}`}
                        >
                          {agent.role}
                        </span>
                        <Badge status={agent.status}>{agent.status}</Badge>
                      </div>
                      <div className="flex items-center justify-between text-xs text-slate-500">
                        <span>事件数</span>
                        <span className="font-mono text-slate-300">{iterations}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="space-y-3">
                {derivedAgents.map((agent) => (
                  <div
                    key={agent.role}
                    className="rounded-md border border-argus-border/50 bg-argus-dark p-3"
                  >
                    <div className="mb-1.5 flex items-center justify-between">
                      <span
                        className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${getAgentColor(agent.role)}`}
                      >
                        {agent.role}
                      </span>
                      <span
                        className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${
                          agent.status === "running"
                            ? "bg-green-500/20 text-green-400"
                            : "bg-slate-600/20 text-slate-500"
                        }`}
                      >
                        {agent.status === "running" ? "运行中" : "已完成"}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-xs text-slate-500">
                      <span>事件数</span>
                      <span className="font-mono text-slate-300">{agent.eventCount}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* -------- 中栏：实时事件流 -------- */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>
              <Activity className="mr-1 inline h-4 w-4" />
              实时事件流
              <span className="ml-2 text-xs font-normal text-slate-500">
                ({filteredEvents.length} 条)
              </span>
            </CardTitle>
            <div className="flex items-center gap-2">
              {/* Agent 筛选 */}
              <div className="flex items-center gap-1">
                <Filter className="h-3 w-3 text-slate-500" />
                <select
                  value={agentFilter}
                  onChange={(e) => setAgentFilter(e.target.value)}
                  className="rounded border border-argus-border bg-argus-dark px-2 py-1 text-xs text-slate-300 focus:border-argus-primary focus:outline-none"
                >
                  <option value="all">全部 Agent</option>
                  {agentRoles.map((role) => (
                    <option key={role} value={role}>
                      {role}
                    </option>
                  ))}
                </select>
              </div>
              {/* 自动滚动按钮 */}
              <button
                onClick={() => {
                  setAutoScroll(true);
                  if (eventListRef.current) {
                    eventListRef.current.scrollTop = eventListRef.current.scrollHeight;
                  }
                }}
                className={`rounded p-1 text-xs ${
                  autoScroll
                    ? "text-argus-primary"
                    : "text-slate-500 hover:text-slate-300"
                }`}
                title="自动滚动到底部"
              >
                <ArrowDown className="h-3.5 w-3.5" />
              </button>
            </div>
          </CardHeader>
          <CardContent>
            <div
              ref={eventListRef}
              onScroll={handleEventScroll}
              className="h-[500px] overflow-y-auto scrollbar-thin space-y-0.5"
            >
              {filteredEvents.length === 0 ? (
                <div className="flex h-full items-center justify-center">
                  <p className="text-sm text-slate-500">
                    {connected ? "等待事件..." : "未连接到事件流"}
                  </p>
                </div>
              ) : (
                filteredEvents.map((event) => (
                  <div
                    key={event.id}
                    className="flex gap-2 rounded px-2 py-1.5 text-xs hover:bg-slate-700/30"
                  >
                    {/* 时间戳 */}
                    <span className="flex-shrink-0 font-mono text-slate-600">
                      {new Date(event.timestamp).toLocaleTimeString("zh-CN", {
                        hour12: false,
                      })}
                    </span>
                    {/* Agent 角色标签 */}
                    <span
                      className={`flex-shrink-0 inline-flex items-center rounded-full border px-1.5 py-0 text-[10px] font-medium ${getAgentColor(event.agent_role ?? event.agent)}`}
                    >
                      {event.agent_role ?? event.agent}
                    </span>
                    {/* 事件类型 */}
                    <span
                      className={`flex-shrink-0 font-medium ${eventTypeStyle[event.type ?? event.event_type] ?? "text-slate-400"}`}
                    >
                      [{event.type ?? event.event_type}]
                    </span>
                    {/* 事件摘要 */}
                    <span className="min-w-0 flex-1 truncate text-slate-300">
                      {getEventSummary(event)}
                    </span>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>

        {/* -------- 右栏：漏洞发现面板 -------- */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>
              <Shield className="mr-1 inline h-4 w-4" />
              发现漏洞
              <span className="ml-2 text-xs font-normal text-slate-500">
                ({findingsData?.total ?? 0})
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="max-h-[500px] space-y-2 overflow-y-auto scrollbar-thin">
              {!findingsData?.items.length ? (
                <p className="py-8 text-center text-xs text-slate-500">
                  暂未发现漏洞
                </p>
              ) : (
                findingsData.items.map((finding) => (
                  <Link
                    key={finding.id}
                    href={`/findings/${finding.id}`}
                    className="block rounded-md border border-argus-border/50 bg-argus-dark p-2.5 transition-colors hover:border-argus-primary/40"
                  >
                    <div className="mb-1 flex items-center justify-between gap-2">
                      <span className="min-w-0 truncate text-xs font-medium text-slate-200">
                        {finding.title}
                      </span>
                      <Badge severity={finding.severity}>
                        {finding.severity}
                      </Badge>
                    </div>
                    <p className="truncate text-[11px] text-slate-500">
                      {finding.type} {finding.trigger_path && `- ${typeof finding.trigger_path === 'object' ? (finding.trigger_path as any).url || JSON.stringify(finding.trigger_path) : finding.trigger_path}`}
                    </p>
                  </Link>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}
