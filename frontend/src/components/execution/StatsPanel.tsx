"use client";

import { useMemo } from "react";
import type { AgentEvent, Severity } from "@/types";

interface StatsPanelProps {
  events: AgentEvent[];
}

interface VulnCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface TreeStats {
  total_nodes: number;
  explored: number;
  confirmed_vulns: number;
  pruned: number;
  killed: number;
  graveyard_size: number;
  seeds: number;
  promoted: number;
  high_signal: number;
  prior_weight: number;
  exploration_weight: number;
}

interface KnowledgeSummary {
  endpoints_discovered: number;
  waf_profile: { detected: boolean; vendor_hint: string; filtered_chars_count: number; bypass_count: number };
  effective_params_count: number;
  vuln_signal_count: number;
  tech_stack: string[];
  explorations_completed: number;
}

interface TokenUsage {
  tokens_in: number;
  tokens_out: number;
  cumulative_spent: number;
  cumulative_budget: number;
  remaining_ratio: number;
}

export function StatsPanel({ events }: StatsPanelProps) {
  const vulnCounts = useMemo<VulnCount>(() => {
    const counts: VulnCount = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    events
      .filter((e) => e.type === "finding_confirmed" || e.event_type === "finding_confirmed")
      .forEach((e) => {
        const sev = (e.data?.severity || "info") as keyof VulnCount;
        if (sev in counts) counts[sev]++;
      });
    return counts;
  }, [events]);

  const treeStats = useMemo<TreeStats>(() => {
    const cycleEvents = events.filter((e) => e.type === "cycle_complete" || e.event_type === "cycle_summary");
    const last = cycleEvents[cycleEvents.length - 1];
    const stats = last?.data?.tree_stats || {};
    return {
      total_nodes: stats.total_nodes || 0,
      explored: stats.explored || 0,
      confirmed_vulns: stats.confirmed_vulns || 0,
      pruned: stats.pruned || 0,
      killed: stats.killed || 0,
      graveyard_size: stats.graveyard_size || 0,
      seeds: stats.seeds || 0,
      promoted: stats.promoted || 0,
      high_signal: stats.high_signal || 0,
      prior_weight: stats.prior_weight || 0.3,
      exploration_weight: stats.exploration_weight || 1.0,
    };
  }, [events]);

  const toolCounts = useMemo<Record<string, number>>(() => {
    const counts: Record<string, number> = {};
    events
      .filter((e) => e.type === "react_step" || e.event_type === "react_step")
      .forEach((e) => {
        const tool = e.data?.tool_name || e.data?.action || "unknown";
        counts[tool] = (counts[tool] || 0) + 1;
      });
    return counts;
  }, [events]);

  const tokenUsage = useMemo<TokenUsage>(() => {
    const tokenEvents = events.filter((e) => e.type === "token_usage" || e.event_type === "token_usage");
    const last = tokenEvents[tokenEvents.length - 1];
    if (!last?.data) return { tokens_in: 0, tokens_out: 0, cumulative_spent: 0, cumulative_budget: 500000, remaining_ratio: 1.0 };
    return last.data as TokenUsage;
  }, [events]);

  const knowledgeSummary = useMemo<KnowledgeSummary>(() => {
    const expEvents = events.filter((e) => e.type === "expansion_complete" || e.event_type === "expansion_complete");
    const last = expEvents[expEvents.length - 1];
    const ks = last?.data?.knowledge_summary || {};
    return {
      endpoints_discovered: ks.endpoints_discovered || 0,
      waf_profile: ks.waf_profile || { detected: false, vendor_hint: "", filtered_chars_count: 0, bypass_count: 0 },
      effective_params_count: ks.effective_params_count || 0,
      vuln_signal_count: ks.vuln_signal_count || 0,
      tech_stack: ks.tech_stack || [],
      explorations_completed: ks.explorations_completed || 0,
    };
  }, [events]);

  const cycleInfo = useMemo(() => {
    const cycleEvents = events.filter((e) => e.type === "cycle_complete" || e.event_type === "cycle_summary");
    const last = cycleEvents[cycleEvents.length - 1];
    return { cycle: last?.data?.cycle || 0, max_cycles: last?.data?.max_cycles || 15 };
  }, [events]);

  const toolTop5 = useMemo(() => {
    return Object.entries(toolCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5);
  }, [toolCounts]);

  const totalFindings = Object.values(vulnCounts).reduce((a, b) => a + b, 0);
  const tokenPct = tokenUsage.cumulative_budget > 0
    ? Math.round((tokenUsage.cumulative_spent / tokenUsage.cumulative_budget) * 100)
    : 0;
  const maxToolCount = Math.max(1, ...Object.values(toolCounts));

  const sevConfig: Record<keyof VulnCount, { color: string; label: string }> = {
    critical: { color: "bg-red-500", label: "严重" },
    high: { color: "bg-orange-500", label: "高危" },
    medium: { color: "bg-yellow-500", label: "中危" },
    low: { color: "bg-blue-500", label: "低危" },
    info: { color: "bg-slate-500", label: "信息" },
  };

  return (
    <div className="grid grid-cols-2 gap-4">
      {/* 漏洞发现分布 */}
      <div className="col-span-2 rounded-lg border border-slate-700/50 bg-slate-900/50 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-200">漏洞发现分布 ({totalFindings})</h3>
        <div className="space-y-2">
          {(Object.entries(vulnCounts) as [keyof VulnCount, number][]).map(([sev, count]) => (
            <div key={sev} className="flex items-center gap-2">
              <span className="w-10 text-xs text-slate-400">{sevConfig[sev].label}</span>
              <div className="flex-1 rounded-full bg-slate-800 h-4 overflow-hidden">
                <div
                  className={`h-full rounded-full ${sevConfig[sev].color} transition-all duration-500`}
                  style={{ width: `${totalFindings > 0 ? (count / Math.max(totalFindings, 1)) * 100 : 0}%`, minWidth: count > 0 ? "8px" : "0" }}
                />
              </div>
              <span className="w-6 text-right text-xs font-mono text-slate-300">{count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* 搜索树状态 */}
      <div className="rounded-lg border border-slate-700/50 bg-slate-900/50 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-200">搜索树状态</h3>
        <div className="grid grid-cols-2 gap-2 text-xs">
          {[
            { label: "总节点", value: treeStats.total_nodes },
            { label: "已探索", value: treeStats.explored },
            { label: "已确认漏洞", value: treeStats.confirmed_vulns, color: "text-green-400" },
            { label: "已剪枝", value: treeStats.pruned },
            { label: "已终止", value: treeStats.killed },
            { label: "种子等待", value: treeStats.seeds, color: "text-yellow-400" },
            { label: "已提升", value: treeStats.promoted, color: "text-blue-400" },
            { label: "高信号", value: treeStats.high_signal, color: "text-purple-400" },
          ].map((item) => (
            <div key={item.label} className="flex justify-between rounded bg-slate-800/50 px-2 py-1.5">
              <span className="text-slate-400">{item.label}</span>
              <span className={`font-mono ${item.color || "text-slate-200"}`}>{item.value}</span>
            </div>
          ))}
        </div>
        <div className="mt-3 text-xs text-slate-500">
          Graveyard: {treeStats.graveyard_size} | 周期: {cycleInfo.cycle}/{cycleInfo.max_cycles}
        </div>
      </div>

      {/* 工具使用频率 */}
      <div className="rounded-lg border border-slate-700/50 bg-slate-900/50 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-200">工具使用频率</h3>
        {toolTop5.length === 0 ? (
          <div className="text-xs text-slate-500">暂无数据</div>
        ) : (
          <div className="space-y-1.5">
            {toolTop5.map(([tool, count]) => (
              <div key={tool} className="flex items-center gap-2 text-xs">
                <span className="w-24 truncate text-slate-400 font-mono">{tool}</span>
                <div className="flex-1 rounded-full bg-slate-800 h-3 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-blue-500/60 transition-all"
                    style={{ width: `${(count / maxToolCount) * 100}%` }}
                  />
                </div>
                <span className="w-6 text-right font-mono text-slate-300">{count}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Token 消耗 */}
      <div className="rounded-lg border border-slate-700/50 bg-slate-900/50 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-200">Token 消耗</h3>
        <div className="mb-2 flex justify-between text-xs">
          <span className="text-slate-400">
            {tokenUsage.cumulative_spent.toLocaleString()} / {tokenUsage.cumulative_budget.toLocaleString()}
          </span>
          <span className={`font-mono ${tokenPct > 80 ? "text-red-400" : tokenPct > 50 ? "text-yellow-400" : "text-green-400"}`}>
            {tokenPct}%
          </span>
        </div>
        <div className="rounded-full bg-slate-800 h-4 overflow-hidden mb-3">
          <div
            className={`h-full rounded-full transition-all duration-500 ${
              tokenPct > 80 ? "bg-red-500" : tokenPct > 50 ? "bg-yellow-500" : "bg-green-500"
            }`}
            style={{ width: `${Math.min(100, tokenPct)}%` }}
          />
        </div>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="rounded bg-slate-800/50 px-2 py-1.5">
            <span className="text-slate-500">本次输入</span>
            <span className="float-right font-mono text-slate-300">{tokenUsage.tokens_in.toLocaleString()}</span>
          </div>
          <div className="rounded bg-slate-800/50 px-2 py-1.5">
            <span className="text-slate-500">本次输出</span>
            <span className="float-right font-mono text-slate-300">{tokenUsage.tokens_out.toLocaleString()}</span>
          </div>
          <div className="rounded bg-slate-800/50 px-2 py-1.5">
            <span className="text-slate-500">剩余比例</span>
            <span className="float-right font-mono text-slate-300">{(tokenUsage.remaining_ratio * 100).toFixed(0)}%</span>
          </div>
          <div className="rounded bg-slate-800/50 px-2 py-1.5">
            <span className="text-slate-500">γ(prior)</span>
            <span className="float-right font-mono text-cyan-400">{treeStats.prior_weight.toFixed(3)}</span>
          </div>
        </div>
      </div>

      {/* 知识库摘要 */}
      <div className="rounded-lg border border-slate-700/50 bg-slate-900/50 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-200">知识库</h3>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="rounded bg-slate-800/50 px-2 py-1.5">
            <span className="text-slate-500">发现端点</span>
            <span className="float-right font-mono text-slate-300">{knowledgeSummary.endpoints_discovered}</span>
          </div>
          <div className="rounded bg-slate-800/50 px-2 py-1.5">
            <span className="text-slate-500">WAF 检测</span>
            <span className={`float-right font-mono ${knowledgeSummary.waf_profile.detected ? "text-orange-400" : "text-green-400"}`}>
              {knowledgeSummary.waf_profile.detected ? "是" : "否"}
            </span>
          </div>
          <div className="rounded bg-slate-800/50 px-2 py-1.5">
            <span className="text-slate-500">绕过技术</span>
            <span className="float-right font-mono text-slate-300">{knowledgeSummary.waf_profile.bypass_count}</span>
          </div>
          <div className="rounded bg-slate-800/50 px-2 py-1.5">
            <span className="text-slate-500">有效参数</span>
            <span className="float-right font-mono text-slate-300">{knowledgeSummary.effective_params_count}</span>
          </div>
          <div className="rounded bg-slate-800/50 px-2 py-1.5">
            <span className="text-slate-500">漏洞信号</span>
            <span className="float-right font-mono text-slate-300">{knowledgeSummary.vuln_signal_count}</span>
          </div>
          <div className="rounded bg-slate-800/50 px-2 py-1.5">
            <span className="text-slate-500">技术栈</span>
            <span className="float-right font-mono text-slate-300 truncate ml-2 max-w-[100px]">{knowledgeSummary.tech_stack.join(", ") || "未知"}</span>
          </div>
        </div>
      </div>

      {/* 自适应权重 */}
      <div className="rounded-lg border border-slate-700/50 bg-slate-900/50 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-200">选择权重 (实时)</h3>
        <div className="space-y-2 text-xs">
          {[
            { label: "γ 先验权重", value: treeStats.prior_weight, color: "bg-amber-500", desc: "启发式规则影响力" },
            { label: "α 经验权重", value: 1 - 0.6 * Math.exp(-(cycleInfo.cycle * 4) / 80), color: "bg-green-500", desc: "实际探测数据影响力" },
            { label: "β 探索权重", value: treeStats.exploration_weight, color: "bg-blue-500", desc: "探索未知道路倾向" },
          ].map((item) => (
            <div key={item.label}>
              <div className="flex justify-between mb-1">
                <span className="text-slate-400">{item.label}</span>
                <span className="font-mono text-slate-300">{item.value.toFixed(3)}</span>
              </div>
              <div className="rounded-full bg-slate-800 h-2 overflow-hidden">
                <div
                  className={`h-full rounded-full ${item.color} transition-all duration-1000`}
                  style={{ width: `${Math.min(100, item.value * 100)}%` }}
                />
              </div>
              <div className="text-[10px] text-slate-600 mt-0.5">{item.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
