"use client";

import Link from "next/link";
import { MainLayout } from "@/components/layout/main-layout";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Loading } from "@/components/ui/loading";
import { EmptyState } from "@/components/ui/empty-state";
import { useStats } from "@/hooks/use-stats";
import { useTasks } from "@/hooks/use-tasks";
import { formatDate } from "@/lib/utils";
import {
  ClipboardList,
  Play,
  ShieldAlert,
  AlertTriangle,
  Plus,
} from "lucide-react";

/** 统计卡片数据结构 */
interface StatItem {
  label: string;
  value: number | undefined;
  icon: React.ElementType;
  color: string;
}

export default function DashboardPage() {
  const { data: stats, isLoading: statsLoading } = useStats();
  const { data: tasksData, isLoading: tasksLoading } = useTasks({
    page_size: "5",
  });

  // 统计卡片配置
  const statCards: StatItem[] = [
    {
      label: "总任务数",
      value: stats?.total_tasks,
      icon: ClipboardList,
      color: "text-blue-400",
    },
    {
      label: "运行中",
      value: stats?.running_tasks,
      icon: Play,
      color: "text-green-400",
    },
    {
      label: "漏洞总数",
      value: stats?.total_findings,
      icon: ShieldAlert,
      color: "text-yellow-400",
    },
    {
      label: "高危漏洞",
      value: stats?.critical_findings,
      icon: AlertTriangle,
      color: "text-red-400",
    },
  ];

  return (
    <MainLayout title="控制台">
      {/* ========== 统计卡片行 ========== */}
      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {statCards.map((item) => (
          <Card key={item.label}>
            <CardContent className="flex items-center gap-4">
              <div className="rounded-lg bg-slate-700/50 p-3">
                <item.icon className={`h-6 w-6 ${item.color}`} />
              </div>
              <div>
                <p className="text-xs text-slate-500">{item.label}</p>
                <p className="text-2xl font-bold text-slate-100">
                  {statsLoading ? "—" : (item.value ?? 0)}
                </p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* ========== 最近任务 + 快捷操作 ========== */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* 最近任务表格 */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>最近任务</CardTitle>
            <Link href="/tasks">
              <span className="text-xs text-argus-primary hover:underline">
                查看全部
              </span>
            </Link>
          </CardHeader>
          <CardContent>
            {tasksLoading ? (
              <Loading label="加载中..." />
            ) : !tasksData?.items.length ? (
              <EmptyState
                title="暂无任务"
                description="创建第一个扫描任务开始漏洞挖掘"
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-argus-border text-left text-xs text-slate-500">
                      <th className="pb-2 pr-4 font-medium">任务名称</th>
                      <th className="pb-2 pr-4 font-medium">目标</th>
                      <th className="pb-2 pr-4 font-medium">状态</th>
                      <th className="pb-2 font-medium">创建时间</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tasksData.items.map((task) => (
                      <tr
                        key={task.id}
                        className="border-b border-argus-border/50 last:border-0"
                      >
                        <td className="py-3 pr-4">
                          <Link
                            href={`/tasks/${task.id}`}
                            className="text-slate-200 hover:text-argus-primary"
                          >
                            {task.name}
                          </Link>
                        </td>
                        <td className="py-3 pr-4 text-slate-400">
                          <span className="max-w-[200px] truncate block">
                            {task.target_url}
                          </span>
                        </td>
                        <td className="py-3 pr-4">
                          <Badge status={task.status}>{task.status}</Badge>
                        </td>
                        <td className="py-3 text-slate-500">
                          {formatDate(task.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>

        {/* 快捷操作 */}
        <Card>
          <CardHeader>
            <CardTitle>快捷操作</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <Link href="/tasks/new">
              <Button variant="primary" className="w-full">
                <Plus className="h-4 w-4" />
                新建任务
              </Button>
            </Link>
            <Link href="/findings">
              <Button variant="secondary" className="w-full">
                <ShieldAlert className="h-4 w-4" />
                查看漏洞
              </Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}
