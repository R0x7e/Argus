"use client";

import { cn } from "@/lib/utils";

// 变体样式映射
const variantStyles: Record<string, string> = {
  default: "bg-slate-600/20 text-slate-300 border-slate-600/30",
  success: "bg-green-500/15 text-green-400 border-green-500/30",
  warning: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  danger: "bg-red-500/15 text-red-400 border-red-500/30",
  info: "bg-blue-500/15 text-blue-400 border-blue-500/30",
};

// 严重程度 → 变体映射
const severityVariant: Record<string, string> = {
  critical: "danger",
  high: "warning",
  medium: "warning",
  low: "info",
  info: "default",
};

// 任务状态 → 变体映射
const statusVariant: Record<string, string> = {
  pending: "default",
  running: "success",
  paused: "warning",
  completed: "info",
  failed: "danger",
  terminated: "danger",
  // Finding 状态
  open: "warning",
  confirmed: "danger",
  false_positive: "default",
  fixed: "success",
  wont_fix: "default",
};

interface BadgeProps {
  children: React.ReactNode;
  variant?: keyof typeof variantStyles;
  /** 自动根据 severity 值选择颜色 */
  severity?: string;
  /** 自动根据 status 值选择颜色 */
  status?: string;
  className?: string;
}

/**
 * 通用标签组件
 * 支持直接指定 variant，或通过 severity / status 自动映射
 */
export function Badge({
  children,
  variant,
  severity,
  status,
  className,
}: BadgeProps) {
  // 优先级：显式 variant > severity > status > default
  let resolvedVariant = variant ?? "default";
  if (!variant && severity) {
    resolvedVariant = severityVariant[severity] ?? "default";
  } else if (!variant && status) {
    resolvedVariant = statusVariant[status] ?? "default";
  }

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium",
        variantStyles[resolvedVariant] ?? variantStyles.default,
        className
      )}
    >
      {children}
    </span>
  );
}
