// ============================================================
// WebSocket 管理器 v2 — 双向通信 (事件接收 + 用户干预发送)
// ============================================================

import type { AgentEvent } from "@/types";
import { useAuthStore } from "@/stores/auth";

type EventCallback = (event: AgentEvent) => void;
type ConnectionCallback = (connected: boolean) => void;
type MessageCallback = (msg: any) => void;

export class WebSocketManager {
  private ws: WebSocket | null = null;
  private callbacks: Set<EventCallback> = new Set();
  private connectionCallbacks: Set<ConnectionCallback> = new Set();
  private messageCallbacks: Set<MessageCallback> = new Set();  // v2: 通用消息回调
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

  /** 发送消息到后端 (v2: 用户干预) */
  send(msg: object): boolean {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
      return true;
    }
    return false;
  }

  /** 建立 WebSocket 连接 */
  connect() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = process.env.NEXT_PUBLIC_WS_HOST || window.location.host;
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
        // v2: 转发所有消息给通用回调 (user_action_ack 等)
        this.messageCallbacks.forEach((cb) => cb(msg));
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
    return () => { this.callbacks.delete(cb); };
  }

  /** 订阅所有消息 (v2: 包括 user_action_ack) */
  onMessage(cb: MessageCallback): () => void {
    this.messageCallbacks.add(cb);
    return () => { this.messageCallbacks.delete(cb); };
  }

  /** 订阅连接状态变化 */
  onConnectionChange(cb: ConnectionCallback): () => void {
    this.connectionCallbacks.add(cb);
    return () => { this.connectionCallbacks.delete(cb); };
  }

  /** 断开连接 */
  disconnect() {
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
    this.ws?.close();
    this.ws = null;
    this._connected = false;
    this.callbacks.clear();
    this.connectionCallbacks.clear();
    this.messageCallbacks.clear();
  }

  /** 发送心跳 */
  ping() {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: "ping" }));
    }
  }

  private notifyConnection(connected: boolean) {
    this.connectionCallbacks.forEach((cb) => cb(connected));
  }

  /** 指数退避重连 */
  private scheduleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) return;
    const delay = Math.min(1000 * 2 ** this.reconnectAttempts, 30000);
    this.reconnectTimer = setTimeout(() => { this.reconnectAttempts++; this.connect(); }, delay);
  }
}
