"use client";

import { useState, useMemo, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { NodeListSidebar } from "./NodeListSidebar";
import { StepCard } from "./StepCard";
import type { AgentEvent } from "@/types";
import { Brain } from "lucide-react";

interface ThoughtChainPanelProps {
  events: AgentEvent[];
  initialNodeId?: string | null;
}

export function ThoughtChainPanel({ events, initialNodeId }: ThoughtChainPanelProps) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(initialNodeId ?? null);

  useEffect(() => {
    if (initialNodeId) setSelectedNodeId(initialNodeId);
  }, [initialNodeId]);

  const reactSteps = useMemo(
    () => events.filter((e) => (e.type ?? e.event_type) === "react_step"),
    [events]
  );

  const selectedSteps = useMemo(() => {
    if (!selectedNodeId) {
      if (reactSteps.length > 0) {
        const firstNodeId = reactSteps[0]?.data?.node_id;
        if (firstNodeId) {
          return reactSteps.filter((e) => e.data?.node_id === firstNodeId);
        }
      }
      return reactSteps.slice(0, 50);
    }
    return reactSteps.filter((e) => e.data?.node_id === selectedNodeId);
  }, [reactSteps, selectedNodeId]);

  const handleSelectNode = (nodeId: string) => {
    setSelectedNodeId(nodeId === selectedNodeId ? null : nodeId);
  };

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
      {/* 左侧节点列表 */}
      <Card className="lg:col-span-1">
        <CardHeader>
          <CardTitle>
            <Brain className="mr-1 inline h-4 w-4" />
            搜索节点
          </CardTitle>
        </CardHeader>
        <CardContent className="max-h-[600px] overflow-y-auto p-0">
          <NodeListSidebar
            steps={reactSteps}
            selectedNodeId={selectedNodeId}
            onSelectNode={handleSelectNode}
          />
        </CardContent>
      </Card>

      {/* 右侧步骤详情 */}
      <Card className="lg:col-span-3">
        <CardHeader>
          <CardTitle>
            执行步骤
            {selectedNodeId && (
              <span className="ml-2 font-mono text-xs font-normal text-slate-500">
                node: {selectedNodeId.slice(0, 12)}
              </span>
            )}
            <span className="ml-2 text-xs font-normal text-slate-500">
              ({selectedSteps.length} steps)
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="max-h-[600px] space-y-3 overflow-y-auto scrollbar-thin">
            {selectedSteps.length === 0 ? (
              <div className="flex h-40 items-center justify-center">
                <p className="text-sm text-slate-500">
                  {reactSteps.length === 0
                    ? "等待 ReAct Agent 开始执行..."
                    : "选择左侧节点查看执行步骤"}
                </p>
              </div>
            ) : (
              selectedSteps.map((event, idx) => (
                <StepCard
                  key={event.id || idx}
                  step={{
                    node_id: event.data?.node_id ?? "",
                    step: event.data?.step ?? idx,
                    thought: event.data?.thought ?? "",
                    action: event.data?.action ?? "",
                    action_params: event.data?.action_params ?? {},
                    observation: event.data?.observation ?? "",
                    success: event.data?.success ?? false,
                    reward: event.data?.reward ?? 0,
                    new_facts: event.data?.new_facts ?? [],
                    vuln_confirmed: event.data?.vuln_confirmed ?? false,
                    duration_ms: event.data?.duration_ms ?? 0,
                    tool_name: event.data?.tool_name ?? "",
                    timestamp: event.timestamp,
                  }}
                />
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
