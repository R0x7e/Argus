// ============================================================
// 任务监控页面状态管理 — Zustand Store
// ============================================================

import { create } from "zustand";

interface TaskMonitorState {
  /** 当前选中的任务 ID */
  selectedTaskId: string | null;
  /** 事件过滤关键词 */
  eventFilter: string;
  /** 是否自动滚动到最新事件 */
  autoScroll: boolean;

  /** 设置选中的任务 */
  setSelectedTask: (id: string | null) => void;
  /** 设置事件过滤关键词 */
  setEventFilter: (filter: string) => void;
  /** 切换自动滚动状态 */
  toggleAutoScroll: () => void;
}

export const useTaskMonitorStore = create<TaskMonitorState>((set) => ({
  selectedTaskId: null,
  eventFilter: "",
  autoScroll: true,

  setSelectedTask: (id) => set({ selectedTaskId: id }),
  setEventFilter: (filter) => set({ eventFilter: filter }),
  toggleAutoScroll: () => set((state) => ({ autoScroll: !state.autoScroll })),
}));
