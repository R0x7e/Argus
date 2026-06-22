import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { format } from "date-fns";

/**
 * 合并 Tailwind 类名，自动处理冲突
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * 格式化日期为 "YYYY-MM-DD HH:mm:ss"
 */
export function formatDate(date: string | Date): string {
  const d = typeof date === "string" ? new Date(date) : date;
  return format(d, "yyyy-MM-dd HH:mm:ss");
}

/**
 * 根据漏洞严重程度返回对应的 Tailwind 颜色类
 */
export function severityColor(
  severity: "critical" | "high" | "medium" | "low" | "info"
): string {
  const colorMap: Record<string, string> = {
    critical: "text-red-500 bg-red-500/10 border-red-500/30",
    high: "text-orange-500 bg-orange-500/10 border-orange-500/30",
    medium: "text-yellow-500 bg-yellow-500/10 border-yellow-500/30",
    low: "text-blue-400 bg-blue-400/10 border-blue-400/30",
    info: "text-slate-400 bg-slate-400/10 border-slate-400/30",
  };
  return colorMap[severity] ?? colorMap.info;
}

/**
 * 根据任务状态返回对应的 Tailwind 颜色类
 */
export function statusColor(
  status:
    | "pending"
    | "running"
    | "paused"
    | "completed"
    | "failed"
    | "terminated"
): string {
  const colorMap: Record<string, string> = {
    pending: "text-slate-400 bg-slate-400/10",
    running: "text-green-400 bg-green-400/10",
    paused: "text-yellow-400 bg-yellow-400/10",
    completed: "text-blue-400 bg-blue-400/10",
    failed: "text-red-500 bg-red-500/10",
    terminated: "text-orange-500 bg-orange-500/10",
  };
  return colorMap[status] ?? colorMap.pending;
}
