"use client";

import { useParams } from "next/navigation";
import { useState, useRef, useCallback } from "react";
import Link from "next/link";
import { MainLayout } from "@/components/layout/main-layout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Loading } from "@/components/ui/loading";
import { EmptyState } from "@/components/ui/empty-state";
import { useTask, useTaskAction } from "@/hooks/use-tasks";
import { useEventStream } from "@/hooks/use-events";
import { useFindings } from "@/hooks/use-findings";
import { OverviewPanel } from "@/components/execution/OverviewPanel";
import { ThoughtChainPanel } from "@/components/execution/ThoughtChainPanel";
import { SearchTreePanel } from "@/components/execution/SearchTreePanel";
import { StatsPanel } from "@/components/execution/StatsPanel";
import { InterventionPanel } from "@/components/execution/InterventionPanel";
import {
  Play, Pause, Square, Wifi, WifiOff, FileText,
  Activity, Brain, GitBranch, BarChart3, Settings2,
} from "lucide-react";

type TabKey = "overview" | "thoughts" | "tree" | "stats" | "intervention";

const tabs: { key: TabKey; label: string; icon: React.ReactNode }[] = [
  { key: "overview", label: "概览", icon: <Activity className="h-3.5 w-3.5" /> },
  { key: "thoughts", label: "思维链", icon: <Brain className="h-3.5 w-3.5" /> },
  { key: "tree", label: "搜索树", icon: <GitBranch className="h-3.5 w-3.5" /> },
  { key: "stats", label: "统计", icon: <BarChart3 className="h-3.5 w-3.5" /> },
  { key: "intervention", label: "干预", icon: <Settings2 className="h-3.5 w-3.5" /> },
];

export default function TaskMonitorPage() {
  const params = useParams();
  const taskId = params.id as string;
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const { data: task, isLoading: taskLoading } = useTask(taskId);
  const { events, connected } = useEventStream(taskId);
  const { data: findingsData } = useFindings(
    taskId ? { task_id: taskId } : undefined
  );
  const taskAction = useTaskAction();

  const wsSend = useCallback((msg: object) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  }, []);

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

  const findings = findingsData?.items || [];

  return (
    <MainLayout title={`任务监控 - ${task.name}`}>
      {/* 顶部：任务信息 + 控制按钮 */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Badge status={task.status}>{task.status}</Badge>
          <span className="text-sm text-slate-400">目标: {task.target_url}</span>
          <span className="flex items-center gap-1 text-xs text-slate-500">
            {connected ? (
              <><Wifi className="h-3 w-3 text-green-400" /> 已连接</>
            ) : (
              <><WifiOff className="h-3 w-3 text-red-400" /> 未连接</>
            )}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {(task.status === "pending" || task.status === "created") && (
            <Button variant="primary" size="sm" onClick={() => handleAction("start")} loading={taskAction.isPending}>
              <Play className="h-3 w-3" /> 启动
            </Button>
          )}
          {task.status === "running" && (
            <>
              <Button variant="secondary" size="sm" onClick={() => handleAction("pause")}
                loading={taskAction.isPending && taskAction.variables?.action === "pause"}>
                <Pause className="h-3 w-3" /> 暂停
              </Button>
              <Button variant="danger" size="sm" onClick={() => handleAction("terminate")}
                loading={taskAction.isPending && taskAction.variables?.action === "terminate"}>
                <Square className="h-3 w-3" /> 终止
              </Button>
            </>
          )}
          {task.status === "paused" && (
            <>
              <Button variant="primary" size="sm" onClick={() => handleAction("resume")}
                loading={taskAction.isPending && taskAction.variables?.action === "resume"}>
                <Play className="h-3 w-3" /> 恢复
              </Button>
              <Button variant="danger" size="sm" onClick={() => handleAction("terminate")}
                loading={taskAction.isPending && taskAction.variables?.action === "terminate"}>
                <Square className="h-3 w-3" /> 终止
              </Button>
            </>
          )}
          {(task.status === "completed" || task.status === "done" || task.status === "failed") && (
            <Link href={`/tasks/${taskId}/report`}>
              <Button variant="secondary" size="sm"><FileText className="h-3 w-3" /> 查看报告</Button>
            </Link>
          )}
        </div>
      </div>

      {/* Tab 导航 */}
      <div className="mb-4 flex items-center gap-1 border-b border-argus-border/50 overflow-x-auto">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium transition-colors whitespace-nowrap ${
              activeTab === tab.key
                ? "border-b-2 border-argus-primary text-argus-primary"
                : "text-slate-500 hover:text-slate-300"
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab 内容 */}
      {activeTab === "overview" && (
        <OverviewPanel task={task} events={events} connected={connected} findingsData={findingsData} />
      )}
      {activeTab === "thoughts" && (
        <ThoughtChainPanel events={events} initialNodeId={selectedNodeId} />
      )}
      {activeTab === "tree" && (
        <SearchTreePanel events={events} onSelectNode={(nodeId) => { setSelectedNodeId(nodeId); setActiveTab("thoughts"); }} />
      )}
      {activeTab === "stats" && (
        <StatsPanel events={events} />
      )}
      {activeTab === "intervention" && (
        <InterventionPanel events={events} findings={findings} connected={connected} taskId={taskId} wsSend={wsSend} />
      )}
    </MainLayout>
  );
}
