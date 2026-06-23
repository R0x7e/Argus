"use client";

import { useMemo } from "react";
import { GitBranch, CheckCircle, XCircle, Search } from "lucide-react";

interface NodeInfo {
  id: string;
  vuln_type: string;
  endpoint: string;
  param: string | null;
  stepCount: number;
  hasVuln: boolean;
  lastStatus: string;
}

interface NodeListSidebarProps {
  steps: Array<{ data: Record<string, any> }>;
  selectedNodeId: string | null;
  onSelectNode: (nodeId: string) => void;
}

export function NodeListSidebar({ steps, selectedNodeId, onSelectNode }: NodeListSidebarProps) {
  const nodes = useMemo(() => {
    const nodeMap = new Map<string, NodeInfo>();
    for (const step of steps) {
      const d = step.data ?? step;
      const nodeId = d.node_id;
      if (!nodeId) continue;

      const existing = nodeMap.get(nodeId);
      if (!existing) {
        nodeMap.set(nodeId, {
          id: nodeId,
          vuln_type: d.vuln_type ?? "",
          endpoint: d.endpoint ?? "",
          param: d.param ?? null,
          stepCount: 1,
          hasVuln: d.vuln_confirmed ?? false,
          lastStatus: d.action ?? "",
        });
      } else {
        existing.stepCount++;
        if (d.vuln_confirmed) existing.hasVuln = true;
        existing.lastStatus = d.action ?? existing.lastStatus;
      }
    }
    return Array.from(nodeMap.values());
  }, [steps]);

  if (nodes.length === 0) {
    return (
      <div className="flex h-full items-center justify-center p-4">
        <div className="text-center">
          <Search className="mx-auto mb-2 h-6 w-6 text-slate-600" />
          <p className="text-xs text-slate-500">等待 Agent 执行...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-1.5 overflow-y-auto p-2">
      <div className="mb-2 px-1 text-[10px] font-medium uppercase tracking-wide text-slate-500">
        搜索节点 ({nodes.length})
      </div>
      {nodes.map((node) => (
        <button
          key={node.id}
          onClick={() => onSelectNode(node.id)}
          className={`w-full rounded-md border p-2.5 text-left transition-colors ${
            selectedNodeId === node.id
              ? "border-argus-primary/60 bg-argus-primary/10"
              : "border-argus-border/30 bg-argus-dark hover:border-argus-border"
          }`}
        >
          <div className="mb-1 flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              {node.hasVuln ? (
                <CheckCircle className="h-3 w-3 text-red-400" />
              ) : (
                <GitBranch className="h-3 w-3 text-slate-500" />
              )}
              <span className="font-mono text-[10px] text-slate-400">
                {node.id.slice(0, 8)}
              </span>
            </div>
            <span className="rounded bg-slate-700/50 px-1.5 py-0.5 text-[10px] text-slate-500">
              {node.stepCount} steps
            </span>
          </div>
          {node.vuln_type && (
            <span
              className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-medium ${
                node.hasVuln
                  ? "bg-red-500/20 text-red-400"
                  : "bg-slate-600/30 text-slate-400"
              }`}
            >
              {node.vuln_type}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}
