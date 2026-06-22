"use client";

import Link from "next/link";
import { MainLayout } from "@/components/layout/main-layout";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Loading } from "@/components/ui/loading";
import { EmptyState } from "@/components/ui/empty-state";
import { useTasks, useTaskAction } from "@/hooks/use-tasks";
import { formatDate } from "@/lib/utils";
import type { Task, TaskStatus } from "@/types";
import { Plus, Play, Pause, Square, ListTodo } from "lucide-react";

/**
 * 根据任务状态返回可用操作按钮列表
 */
function getTaskActions(task: Task) {
  const actions: { action: "start" | "pause" | "resume" | "terminate"; icon: React.ElementType; label: string; variant: "primary" | "secondary" | "danger" }[] = [];

  switch (task.status) {
    case "pending":
    case "created":
      actions.push({ action: "start", icon: Play, label: "启动", variant: "primary" });
      break;
    case "running":
      actions.push({ action: "pause", icon: Pause, label: "暂停", variant: "secondary" });
      actions.push({ action: "terminate", icon: Square, label: "终止", variant: "danger" });
      break;
    case "paused":
      actions.push({ action: "resume", icon: Play, label: "恢复", variant: "primary" });
      actions.push({ action: "terminate", icon: Square, label: "终止", variant: "danger" });
      break;
  }

  return actions;
}

export default function TasksPage() {
  const { data, isLoading } = useTasks();
  const taskAction = useTaskAction();

  const handleAction = (taskId: string, action: "start" | "pause" | "resume" | "terminate") => {
    taskAction.mutate({ taskId, action });
  };

  return (
    <MainLayout title="任务管理">
      {/* 顶部操作区 */}
      <div className="mb-6 flex items-center justify-between">
        <p className="text-sm text-slate-400">
          共 {data?.total ?? 0} 个任务
        </p>
        <Link href="/tasks/new">
          <Button variant="primary" size="md">
            <Plus className="h-4 w-4" />
            新建任务
          </Button>
        </Link>
      </div>

      {/* 任务列表 */}
      <Card>
        <CardContent>
          {isLoading ? (
            <Loading label="加载任务列表..." />
          ) : !data?.items.length ? (
            <EmptyState
              icon={ListTodo}
              title="暂无任务"
              description='点击「新建任务」创建第一个漏洞挖掘任务'
              actionLabel="新建任务"
              onAction={() => {
                window.location.href = "/tasks/new";
              }}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-argus-border text-left text-xs text-slate-500">
                    <th className="pb-3 pr-4 font-medium">任务名称</th>
                    <th className="pb-3 pr-4 font-medium">目标</th>
                    <th className="pb-3 pr-4 font-medium">状态</th>
                    <th className="pb-3 pr-4 font-medium">创建时间</th>
                    <th className="pb-3 font-medium text-right">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((task) => (
                    <tr
                      key={task.id}
                      className="border-b border-argus-border/50 last:border-0"
                    >
                      <td className="py-3 pr-4">
                        <Link
                          href={`/tasks/${task.id}`}
                          className="font-medium text-slate-200 hover:text-argus-primary"
                        >
                          {task.name}
                        </Link>
                      </td>
                      <td className="py-3 pr-4 text-slate-400">
                        <span className="block max-w-[240px] truncate">
                          {task.target_url}
                        </span>
                      </td>
                      <td className="py-3 pr-4">
                        <Badge status={task.status}>{task.status}</Badge>
                      </td>
                      <td className="py-3 pr-4 text-slate-500">
                        {formatDate(task.created_at)}
                      </td>
                      <td className="py-3 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {getTaskActions(task).map(({ action, icon: Icon, label, variant }) => (
                            <Button
                              key={action}
                              variant={variant}
                              size="sm"
                              onClick={() => handleAction(task.id, action)}
                              loading={
                                taskAction.isPending &&
                                taskAction.variables?.taskId === task.id &&
                                taskAction.variables?.action === action
                              }
                            >
                              <Icon className="h-3 w-3" />
                              {label}
                            </Button>
                          ))}
                          {/* 查看详情链接 */}
                          <Link href={`/tasks/${task.id}`}>
                            <Button variant="ghost" size="sm">
                              详情
                            </Button>
                          </Link>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </MainLayout>
  );
}
