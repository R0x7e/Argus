// ============================================================
// 系统统计 React Hook — 仪表盘数据
// ============================================================

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

// ---------------------- 查询 Keys ----------------------

export const statsKeys = {
  all: ["stats"] as const,
};

// ---------------------- 系统统计 ----------------------

/**
 * 获取系统统计数据
 * 每 30 秒自动刷新，用于仪表盘展示
 */
export function useStats() {
  return useQuery({
    queryKey: statsKeys.all,
    queryFn: () => api.getStats(),
    refetchInterval: 30_000,
  });
}
