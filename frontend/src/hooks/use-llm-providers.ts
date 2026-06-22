// ============================================================
// LLM 供应商管理 Hooks — 基于 TanStack Query
// ============================================================

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { settingsApi } from "@/lib/api";
import type { LLMProviderCreate, LLMProviderTestRequest } from "@/types";

export const providerKeys = {
  all: ["llm-providers"] as const,
};

export function useLLMProviders() {
  return useQuery({
    queryKey: providerKeys.all,
    queryFn: () => settingsApi.getLLMProviders(),
  });
}

export function useCreateLLMProvider() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: LLMProviderCreate) => settingsApi.createLLMProvider(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: providerKeys.all });
    },
  });
}

export function useUpdateLLMProvider() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<LLMProviderCreate> }) =>
      settingsApi.updateLLMProvider(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: providerKeys.all });
    },
  });
}

export function useDeleteLLMProvider() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => settingsApi.deleteLLMProvider(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: providerKeys.all });
    },
  });
}

export function useTestLLMProvider() {
  return useMutation({
    mutationFn: (data: LLMProviderTestRequest) => settingsApi.testLLMProvider(data),
  });
}
