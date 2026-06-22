"use client";

import { cn } from "@/lib/utils";
import { Loader2 } from "lucide-react";

// 按钮变体样式
const variants: Record<string, string> = {
  primary:
    "bg-argus-primary hover:bg-indigo-600 text-white shadow-sm shadow-argus-primary/20",
  secondary:
    "bg-slate-700 hover:bg-slate-600 text-slate-200 border border-argus-border",
  danger: "bg-red-600 hover:bg-red-700 text-white",
  ghost: "bg-transparent hover:bg-slate-700/50 text-slate-300",
};

// 按钮尺寸
const sizes: Record<string, string> = {
  sm: "px-2.5 py-1 text-xs",
  md: "px-4 py-2 text-sm",
  lg: "px-6 py-2.5 text-base",
};

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: keyof typeof variants;
  size?: keyof typeof sizes;
  loading?: boolean;
  children: React.ReactNode;
}

/**
 * 通用按钮组件
 * 支持多种变体、尺寸和加载状态
 */
export function Button({
  variant = "primary",
  size = "md",
  loading = false,
  disabled,
  className,
  children,
  ...props
}: ButtonProps) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-md font-medium transition-colors duration-150",
        "focus:outline-none focus:ring-2 focus:ring-argus-primary/50 focus:ring-offset-2 focus:ring-offset-argus-dark",
        "disabled:cursor-not-allowed disabled:opacity-50",
        variants[variant],
        sizes[size],
        className
      )}
      disabled={disabled || loading}
      {...props}
    >
      {loading && <Loader2 className="h-4 w-4 animate-spin" />}
      {children}
    </button>
  );
}
