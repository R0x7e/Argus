// ============================================================
// WebSocket 管理器 — 用于实时事件流推送
// 支持 JWT Token 认证和精确连接状态追踪
// ============================================================

import type { AgentEvent } from "@/types";
import { useAuthStore } from "@/stores/auth";

type EventCallback = (event: AgentEvent) => void;
type ConnectionCallback = (connected: boolean) => void;

/**
 * WebSocket 连接管理器
 *
 * 功能：
 * - 通过 query param 传递 JWT Token 认证
 * - 自动根据页面协议选择 ws / wss
 * - 指数退避重连（最多 5 次，上限 30 秒）
 * - 精确的连接状态回调
 * - 支持多个订阅回调
 */
export class WebSocketManager {
  private ws: WebSocket | null = null;
  private callbacks: Set<EventCallback> = new Set();
  private connectionCallbacks: Set<ConnectionCallback> = new Set();
  private taskId: string;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private _connected = false;

  constructor(taskId: string) {
    this.taskId = taskId;
  }

  get connected(): boolean {
    return this._connected;
  }

  /** 建立 WebSocket 连接 */
  connect() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host =
      process.env.NEXT_PUBLIC_WS_HOST || window.location.host;

    // 携带 JWT Token 作为 query param（WebSocket 不支持自定义 header）
    const token = useAuthStore.getState().token;
    const tokenParam = token ? `?token=${encodeURIComponent(token)}` : "";

    this.ws = new WebSocket(
      `${protocol}//${host}/api/v1/ws/tasks/${this.taskId}/stream${tokenParam}`
    );

    this.ws.onopen = () => {
      this.reconnectAttempts = 0;
      this._connected = true;
      this.notifyConnection(true);
    };

    this.ws.onmessage = (e: MessageEvent) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === "event") {
          this.callbacks.forEach((cb) => cb(msg.data as AgentEvent));
        }
      } catch {
        // 解析失败静默忽略
      }
    };

    this.ws.onclose = () => {
      this._connected = false;
      this.notifyConnection(false);
      this.scheduleReconnect();
    };

    this.ws.onerror = () => {
      this.ws?.close();
    };
  }

  /** 订阅事件 */
  subscribe(cb: EventCallback): () => void {
    this.callbacks.add(cb);
    return () => {
      this.callbacks.delete(cb);
    };
  }

  /** 订阅连接状态变化 */
  onConnectionChange(cb: ConnectionCallback): () => void {
    this.connectionCallbacks.add(cb);
    return () => {
      this.connectionCallbacks.delete(cb);
    };
  }

  /** 断开连接并清理所有状态 */
  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.ws?.close();
    this.ws = null;
    this._connected = false;
    this.callbacks.clear();
    this.connectionCallbacks.clear();
  }

  /** 发送心跳 */
  ping() {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ action: "ping" }));
    }
  }

  private notifyConnection(connected: boolean) {
    this.connectionCallbacks.forEach((cb) => cb(connected));
  }

  /** 指数退避重连调度 */
  private scheduleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      return;
    }
    const delay = Math.min(1000 * 2 ** this.reconnectAttempts, 30000);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectAttempts++;
      this.connect();
    }, delay);
  }
}
