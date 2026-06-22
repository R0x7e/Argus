"use client";

import { cn } from "@/lib/utils";
import { Loader2 } from "lucide-react";

// ---------------------- 加载旋转器 ----------------------

interface SpinnerProps {
  className?: string;
  size?: "sm" | "md" | "lg";
  /** 加载提示文字 */
  label?: string;
}

const spinnerSizes: Record<string, string> = {
  sm: "h-4 w-4",
  md: "h-6 w-6",
  lg: "h-10 w-10",
};

/**
 * 全屏或内嵌加载旋转器
 */
export function Loading({ className, size = "md", label }: SpinnerProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-3 py-12 text-slate-400",
        className
      )}
    >
      <Loader2 className={cn("animate-spin", spinnerSizes[size])} />
      {label && <span className="text-sm">{label}</span>}
    </div>
  );
}

// ---------------------- 骨架屏加载 ----------------------

interface SkeletonProps {
  className?: string;
}

/**
 * 骨架屏占位组件
 * 通过 className 控制宽高: e.g. className="h-4 w-32"
 */
export function Skeleton({ className }: SkeletonProps) {
  return (
    <div
      className={cn(
        "animate-pulse rounded-md bg-slate-700/50",
        className
      )}
    />
  );
}

/** 表格行骨架屏 */
export function TableSkeleton({ rows = 5, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4">
          {Array.from({ length: cols }).map((_, j) => (
            <Skeleton
              key={j}
              className={cn("h-8", j === 0 ? "w-1/3" : "flex-1")}
            />
          ))}
        </div>
      ))}
    </div>
  );
}
