"use client";

import { cn } from "@/lib/utils";
import { Inbox } from "lucide-react";
import { Button } from "./button";

interface EmptyStateProps {
  /** 图标组件，默认 InboxIcon */
  icon?: React.ElementType;
  title: string;
  description?: string;
  /** 操作按钮文本 */
  actionLabel?: string;
  /** 操作按钮回调 */
  onAction?: () => void;
  className?: string;
}

/**
 * 空状态占位组件
 * 用于列表/表格数据为空时展示
 */
export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  actionLabel,
  onAction,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center py-16 text-center",
        className
      )}
    >
      <div className="mb-4 rounded-full bg-slate-800 p-4">
        <Icon className="h-8 w-8 text-slate-500" />
      </div>
      <h3 className="mb-1 text-base font-medium text-slate-300">{title}</h3>
      {description && (
        <p className="mb-4 max-w-sm text-sm text-slate-500">{description}</p>
      )}
      {actionLabel && onAction && (
        <Button variant="primary" size="sm" onClick={onAction}>
          {actionLabel}
        </Button>
      )}
    </div>
  );
}
