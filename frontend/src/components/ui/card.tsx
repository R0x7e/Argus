"use client";

import { cn } from "@/lib/utils";

interface CardProps {
  children: React.ReactNode;
  className?: string;
  /** 是否启用悬停效果 */
  hover?: boolean;
  onClick?: () => void;
}

/**
 * 暗色主题卡片容器
 */
export function Card({ children, className, hover, onClick }: CardProps) {
  return (
    <div
      className={cn(
        "rounded-lg border border-argus-border bg-argus-card p-4",
        hover && "card-hover cursor-pointer",
        className
      )}
      onClick={onClick}
    >
      {children}
    </div>
  );
}

/** 卡片标题区域 */
export function CardHeader({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("mb-3 flex items-center justify-between", className)}>
      {children}
    </div>
  );
}

/** 卡片标题文本 */
export function CardTitle({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <h3 className={cn("text-sm font-semibold text-slate-200", className)}>
      {children}
    </h3>
  );
}

/** 卡片内容区域 */
export function CardContent({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <div className={cn(className)}>{children}</div>;
}
