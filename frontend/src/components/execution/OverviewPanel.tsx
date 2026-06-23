"use client";

import { useState, useEffect, useRef, useMemo } from "react";
import Link from "next/link";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { AgentEvent } from "@/types";
import {
  User,
  Filter,
  ArrowDown,
  Shield,
  Activity,
} from "lucide-react";

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
  lats_react: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  lats_recon: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  lats_mcts: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  lats_eval: "bg-indigo-500/20 text-indigo-400 border-indigo-500/30",
};

function getAgentColor(role: string) {
  return agentColors[role] ?? "bg-slate-500/20 text-slate-400 border-slate-500/30";
}

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
  react_step: "text-yellow-400",
  cycle_summary: "text-indigo-400",
  nodes_selected: "text-cyan-400",
  tree_initialized: "text-blue-400",
};

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
    case "react_step":
      return `[${(data.node_id as string)?.slice(0, 8) ?? "?"}] ${data.action}(${data.tool_name || ""}) → ${data.success ? "✓" : "✗"} ${(data.observation as string)?.slice(0, 60) ?? ""}`;
    case "cycle_summary":
      return `Cycle ${data.cycle}/${data.max_cycles}: ${data.findings_this_round ?? 0} findings, ${data.tree_stats?.total_nodes ?? "?"} nodes`;
    case "nodes_selected":
      return `选中 ${data.count} 个节点进行探索`;
    case "tree_initialized":
      return `搜索树已初始化: ${data.branch_count ?? "?"} 个分支`;
    case "log":
      return (data.content as string) ?? "";
    default:
      return JSON.stringify(data).slice(0, 100);
  }
}

interface OverviewPanelProps {
  task: any;
  events: AgentEvent[];
  connected: boolean;
  findingsData: any;
}

export function OverviewPanel({ task, events, connected, findingsData }: OverviewPanelProps) {
  const [agentFilter, setAgentFilter] = useState<string>("all");
  const [autoScroll, setAutoScroll] = useState(true);
  const eventListRef = useRef<HTMLDivElement>(null);

  const agentRoles = useMemo(() => {
    const roles = new Set<string>();
    events.forEach((e) => roles.add(e.agent_role ?? e.agent));
    return Array.from(roles);
  }, [events]);

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

  const filteredEvents = useMemo(() => {
    if (agentFilter === "all") return events;
    return events.filter((e) => (e.agent_role ?? e.agent) === agentFilter);
  }, [events, agentFilter]);

  useEffect(() => {
    if (autoScroll && eventListRef.current) {
      eventListRef.current.scrollTop = eventListRef.current.scrollHeight;
    }
  }, [filteredEvents, autoScroll]);

  const handleEventScroll = () => {
    if (!eventListRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = eventListRef.current;
    setAutoScroll(scrollHeight - scrollTop - clientHeight < 100);
  };

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
      {/* 左栏：Agent 状态面板 */}
      <Card className="lg:col-span-1">
        <CardHeader>
          <CardTitle>
            <User className="mr-1 inline h-4 w-4" />
            Agent 状态
          </CardTitle>
        </CardHeader>
        <CardContent>
          {derivedAgents.length === 0 ? (
            <p className="text-xs text-slate-500">等待 Agent 启动...</p>
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

      {/* 中栏：实时事件流 */}
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
            <button
              onClick={() => {
                setAutoScroll(true);
                if (eventListRef.current) {
                  eventListRef.current.scrollTop = eventListRef.current.scrollHeight;
                }
              }}
              className={`rounded p-1 text-xs ${
                autoScroll ? "text-argus-primary" : "text-slate-500 hover:text-slate-300"
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
                  <span className="flex-shrink-0 font-mono text-slate-600">
                    {new Date(event.timestamp).toLocaleTimeString("zh-CN", { hour12: false })}
                  </span>
                  <span
                    className={`flex-shrink-0 inline-flex items-center rounded-full border px-1.5 py-0 text-[10px] font-medium ${getAgentColor(event.agent_role ?? event.agent)}`}
                  >
                    {event.agent_role ?? event.agent}
                  </span>
                  <span
                    className={`flex-shrink-0 font-medium ${eventTypeStyle[event.type ?? event.event_type] ?? "text-slate-400"}`}
                  >
                    [{event.type ?? event.event_type}]
                  </span>
                  <span className="min-w-0 flex-1 truncate text-slate-300">
                    {getEventSummary(event)}
                  </span>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>

      {/* 右栏：漏洞发现面板 */}
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
            {!findingsData?.items?.length ? (
              <p className="py-8 text-center text-xs text-slate-500">暂未发现漏洞</p>
            ) : (
              findingsData.items.map((finding: any) => (
                <Link
                  key={finding.id}
                  href={`/findings/${finding.id}`}
                  className="block rounded-md border border-argus-border/50 bg-argus-dark p-2.5 transition-colors hover:border-argus-primary/40"
                >
                  <div className="mb-1 flex items-center justify-between gap-2">
                    <span className="min-w-0 truncate text-xs font-medium text-slate-200">
                      {finding.title}
                    </span>
                    <Badge severity={finding.severity}>{finding.severity}</Badge>
                  </div>
                  <p className="truncate text-[11px] text-slate-500">
                    {finding.type}
                  </p>
                </Link>
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
