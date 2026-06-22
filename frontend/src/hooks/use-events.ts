// ============================================================
// 事件相关 React Hooks — 列表查询 + WebSocket 实时流
// ============================================================

import { useCallback, useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { WebSocketManager } from "@/lib/websocket";
import type { AgentEvent } from "@/types";
import { taskKeys } from "@/hooks/use-tasks";
import { findingKeys } from "@/hooks/use-findings";

// ---------------------- 查询 Keys ----------------------

export const eventKeys = {
  all: ["events"] as const,
  list: (taskId: string, params?: Record<string, string>) =>
    [...eventKeys.all, taskId, params] as const,
};

// ---------------------- 事件列表 ----------------------

/** 获取某个任务的事件列表（分页） */
export function useEvents(
  taskId: string | null,
  params?: Record<string, string>
) {
  return useQuery({
    queryKey: eventKeys.list(taskId!, params),
    queryFn: () => api.getEvents(taskId!, params),
    enabled: !!taskId,
  });
}

// ---------------------- WebSocket 实时事件流 ----------------------

/**
 * 通过 WebSocket 实时接收任务事件
 *
 * 返回值：
 * - events: 当前已接收的事件列表
 * - connected: 精确的连接状态
 * - clearEvents: 清空已接收的事件
 *
 * 副作用：
 * - 收到 finding 类型事件时自动刷新 findings 缓存
 * - 收到任务状态变更事件时自动刷新 task 缓存
 *
 * 生命周期：
 * - taskId 变化时自动断开旧连接并建立新连接
 * - 定时心跳保活（每 30 秒）
 * - 组件卸载时自动断开
 */
export function useEventStream(taskId: string | null) {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocketManager | null>(null);
  const queryClient = useQueryClient();
  const seenIds = useRef<Set<string>>(new Set());

  // 加载历史事件
  useEffect(() => {
    if (!taskId) return;

    api.getEvents(taskId, { page_size: "200" }).then((data) => {
      const items: AgentEvent[] = (data as any)?.items ?? [];
      if (items.length > 0) {
        // API 返回按时间倒序，翻转为正序
        const sorted = [...items].reverse();
        sorted.forEach((e) => seenIds.current.add(e.id));
        setEvents(sorted);
      }
    }).catch(() => {
      // 静默失败，历史事件不可用时仍然可以接收实时事件
    });
  }, [taskId]);

  useEffect(() => {
    if (!taskId) {
      setConnected(false);
      return;
    }

    // 创建新的 WebSocket 管理器
    const manager = new WebSocketManager(taskId);
    wsRef.current = manager;

    // 监听连接状态
    manager.onConnectionChange((isConnected) => {
      setConnected(isConnected);
    });

    // 订阅事件
    const unsubscribe = manager.subscribe((event) => {
      // 去重：防止历史事件和实时事件重复
      if (seenIds.current.has(event.id)) return;
      seenIds.current.add(event.id);

      setEvents((prev) => [...prev, event]);

      // 收到 finding 相关事件时刷新 findings 缓存
      const eventType = event.type ?? event.event_type;
      if (
        eventType === "finding_confirmed" ||
        eventType === "finding" ||
        eventType === "verification_complete"
      ) {
        queryClient.invalidateQueries({ queryKey: findingKeys.lists() });
      }

      // 收到任务状态变更事件时刷新 task 缓存
      if (
        eventType === "agent_started" ||
        eventType === "agent_stopped" ||
        eventType === "max_iterations_reached" ||
        eventType === "report_generated" ||
        eventType === "decision"
      ) {
        queryClient.invalidateQueries({ queryKey: taskKeys.detail(taskId) });
      }
    });

    // 建立连接
    manager.connect();

    // 心跳保活：每 30 秒发送 ping
    const heartbeat = setInterval(() => {
      manager.ping();
    }, 30_000);

    return () => {
      clearInterval(heartbeat);
      unsubscribe();
      manager.disconnect();
      wsRef.current = null;
    };
  }, [taskId, queryClient]);

  /** 清空已接收的事件 */
  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  return { events, connected, clearEvents };
}
