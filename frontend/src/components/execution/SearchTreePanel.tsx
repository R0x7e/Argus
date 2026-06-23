"use client";

import { useMemo } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import type { AgentEvent } from "@/types";
import { GitBranch, Target, CheckCircle, XCircle, Scissors } from "lucide-react";

interface TreeNode {
  id: string;
  parent: string | null;
  endpoint: string;
  vuln_type: string;
  param: string | null;
  value: number;
  visits: number;
  status: string;
  depth: number;
}

interface SearchTreePanelProps {
  events: AgentEvent[];
  onSelectNode?: (nodeId: string) => void;
}

function getStatusIcon(status: string) {
  switch (status) {
    case "confirmed_vuln":
      return <CheckCircle className="h-3.5 w-3.5 text-red-400" />;
    case "pruned":
      return <Scissors className="h-3.5 w-3.5 text-slate-500" />;
    case "exhausted":
      return <XCircle className="h-3.5 w-3.5 text-slate-500" />;
    case "exploring":
      return <Target className="h-3.5 w-3.5 text-green-400 animate-pulse" />;
    default:
      return <GitBranch className="h-3.5 w-3.5 text-slate-400" />;
  }
}

function getValueColor(value: number): string {
  if (value >= 0.7) return "border-red-500/50 bg-red-500/10";
  if (value >= 0.4) return "border-yellow-500/50 bg-yellow-500/10";
  if (value > 0) return "border-blue-500/50 bg-blue-500/10";
  return "border-argus-border/50 bg-argus-dark";
}

export function SearchTreePanel({ events, onSelectNode }: SearchTreePanelProps) {
  const latestSnapshot = useMemo(() => {
    const cycleSummaries = events.filter(
      (e) => (e.type ?? e.event_type) === "cycle_summary" && e.data?.tree_snapshot
    );
    if (cycleSummaries.length === 0) return null;
    const latest = cycleSummaries[cycleSummaries.length - 1];
    return {
      cycle: latest.data?.cycle ?? 0,
      nodes: (latest.data?.tree_snapshot ?? []) as TreeNode[],
      stats: latest.data?.tree_stats ?? {},
    };
  }, [events]);

  const treeByDepth = useMemo(() => {
    if (!latestSnapshot) return new Map<number, TreeNode[]>();
    const map = new Map<number, TreeNode[]>();
    for (const node of latestSnapshot.nodes) {
      const depth = node.depth ?? 0;
      if (!map.has(depth)) map.set(depth, []);
      map.get(depth)!.push(node);
    }
    return map;
  }, [latestSnapshot]);

  const maxDepth = useMemo(() => {
    if (treeByDepth.size === 0) return 0;
    return Math.max(...treeByDepth.keys());
  }, [treeByDepth]);

  if (!latestSnapshot || latestSnapshot.nodes.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>
            <GitBranch className="mr-1 inline h-4 w-4" />
            搜索树
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex h-60 items-center justify-center">
            <p className="text-sm text-slate-500">等待 MCTS 搜索树初始化...</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <GitBranch className="mr-1 inline h-4 w-4" />
          搜索树
          <span className="ml-2 text-xs font-normal text-slate-500">
            Cycle {latestSnapshot.cycle} | {latestSnapshot.nodes.length} 节点
          </span>
        </CardTitle>
        <div className="flex gap-3 text-[10px] text-slate-500">
          <span>探索: {latestSnapshot.stats.explored ?? 0}</span>
          <span>剪枝: {latestSnapshot.stats.pruned ?? 0}</span>
          <span>确认: {latestSnapshot.stats.confirmed_vulns ?? 0}</span>
        </div>
      </CardHeader>
      <CardContent>
        <div className="max-h-[600px] overflow-auto scrollbar-thin">
          {/* 图例 */}
          <div className="mb-4 flex flex-wrap gap-3 text-[10px] text-slate-500">
            <span className="flex items-center gap-1">
              <Target className="h-3 w-3 text-green-400" /> 探索中
            </span>
            <span className="flex items-center gap-1">
              <CheckCircle className="h-3 w-3 text-red-400" /> 已确认
            </span>
            <span className="flex items-center gap-1">
              <XCircle className="h-3 w-3 text-slate-500" /> 已穷尽
            </span>
            <span className="flex items-center gap-1">
              <Scissors className="h-3 w-3 text-slate-500" /> 已剪枝
            </span>
          </div>

          {/* 层级树视图 */}
          <div className="space-y-4">
            {Array.from({ length: maxDepth + 1 }, (_, depth) => {
              const nodes = treeByDepth.get(depth) ?? [];
              if (nodes.length === 0) return null;
              return (
                <div key={depth}>
                  <div className="mb-1.5 text-[10px] font-medium text-slate-600">
                    Depth {depth}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {nodes.map((node) => (
                      <button
                        key={node.id}
                        onClick={() => onSelectNode?.(node.id)}
                        className={`rounded-md border p-2 text-left transition-all hover:scale-105 ${getValueColor(node.value)}`}
                        title={`${node.endpoint}\n${node.vuln_type}\nvalue: ${node.value} | visits: ${node.visits}`}
                      >
                        <div className="mb-1 flex items-center gap-1.5">
                          {getStatusIcon(node.status)}
                          <span className="font-mono text-[10px] text-slate-400">
                            {node.id.slice(0, 6)}
                          </span>
                        </div>
                        <div className="max-w-[120px] truncate text-[10px] text-slate-300">
                          {node.endpoint || "/"}
                        </div>
                        {node.vuln_type && (
                          <div className="mt-0.5 truncate text-[10px] text-slate-500">
                            {node.vuln_type}
                          </div>
                        )}
                        <div className="mt-1 flex items-center gap-2 text-[9px] text-slate-600">
                          <span>v={node.value}</span>
                          <span>n={node.visits}</span>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
