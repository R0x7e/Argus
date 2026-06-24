// ============================================================
// 任务相关 React Hooks — 基于 TanStack Query
// ============================================================

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Task, TaskCreateRequest } from "@/types";

// ---------------------- 查询 Keys ----------------------

export const taskKeys = {
  all: ["tasks"] as const,
  lists: () => [...taskKeys.all, "list"] as const,
  list: (filters?: Record<string, string>) =>
    [...taskKeys.lists(), filters] as const,
  details: () => [...taskKeys.all, "detail"] as const,
  detail: (id: string) => [...taskKeys.details(), id] as const,
};

// ---------------------- 任务列表 ----------------------

/**
 * 获取任务列表
 * 当存在 running 状态的任务时，每 10 秒自动轮询
 */
export function useTasks(filters?: Record<string, string>) {
  return useQuery({
    queryKey: taskKeys.list(filters),
    queryFn: () => api.getTasks(filters),
    // 有运行中的任务时启用 10s 轮询
    refetchInterval: (query) => {
      const data = query.state.data;
      const hasRunning = data?.items?.some((t) => t.status === "running");
      return hasRunning ? 10_000 : false;
    },
  });
}

// ---------------------- 单个任务 ----------------------

/**
 * 获取单个任务详情
 * 任务处于 running 状态时每 5 秒轮询
 */
export function useTask(id: string | null) {
  return useQuery({
    queryKey: taskKeys.detail(id!),
    queryFn: () => api.getTask(id!),
    enabled: !!id,
    refetchInterval: (query) => {
      const task = query.state.data;
      return task?.status === "running" ? 5_000 : false;
    },
  });
}

// ---------------------- 创建任务 ----------------------

export function useCreateTask() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: TaskCreateRequest) => api.createTask(data),
    onSuccess: () => {
      // 创建成功后刷新任务列表
      queryClient.invalidateQueries({ queryKey: taskKeys.lists() });
    },
  });
}

// ---------------------- 任务操作 ----------------------

type TaskAction = "start" | "pause" | "resume" | "terminate";

interface TaskActionParams {
  taskId: string;
  action: TaskAction;
}

/** 任务操作映射表 */
const actionMap: Record<TaskAction, (id: string) => Promise<Task>> = {
  start: api.startTask,
  pause: api.pauseTask,
  resume: api.resumeTask,
  terminate: api.terminateTask,
};

/** 删除任务 hook */
export function useDeleteTask() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (taskId: string) => api.deleteTask(taskId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: taskKeys.lists() });
    },
  });
}

/**
 * 任务操作 mutation（启动 / 暂停 / 恢复 / 终止）
 * 操作完成后自动刷新对应任务及列表缓存
 */
export function useTaskAction() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ taskId, action }: TaskActionParams) =>
      actionMap[action](taskId),
    onSuccess: (_data, { taskId }) => {
      // 同时刷新任务详情和列表
      queryClient.invalidateQueries({ queryKey: taskKeys.detail(taskId) });
      queryClient.invalidateQueries({ queryKey: taskKeys.lists() });
    },
  });
}
