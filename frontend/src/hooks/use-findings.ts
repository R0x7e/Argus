// ============================================================
// 漏洞发现相关 React Hooks — 基于 TanStack Query
// ============================================================

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Finding } from "@/types";

// ---------------------- 查询 Keys ----------------------

export const findingKeys = {
  all: ["findings"] as const,
  lists: () => [...findingKeys.all, "list"] as const,
  list: (params?: Record<string, string>) =>
    [...findingKeys.lists(), params] as const,
  details: () => [...findingKeys.all, "detail"] as const,
  detail: (id: string) => [...findingKeys.details(), id] as const,
};

// ---------------------- 发现列表 ----------------------

/** 获取漏洞发现列表，支持过滤参数 */
export function useFindings(params?: Record<string, string>) {
  return useQuery({
    queryKey: findingKeys.list(params),
    queryFn: () => api.getFindings(params),
  });
}

// ---------------------- 单个发现 ----------------------

/** 获取单个漏洞发现详情 */
export function useFinding(id: string | null) {
  return useQuery({
    queryKey: findingKeys.detail(id!),
    queryFn: () => api.getFinding(id!),
    enabled: !!id,
  });
}

// ---------------------- 更新发现 ----------------------

interface UpdateFindingParams {
  id: string;
  data: Partial<Finding>;
}

/**
 * 更新漏洞发现
 * 操作完成后同时刷新详情和列表缓存
 */
export function useUpdateFinding() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: UpdateFindingParams) =>
      api.updateFinding(id, data),
    onSuccess: (_data, { id }) => {
      queryClient.invalidateQueries({ queryKey: findingKeys.detail(id) });
      queryClient.invalidateQueries({ queryKey: findingKeys.lists() });
    },
  });
}
