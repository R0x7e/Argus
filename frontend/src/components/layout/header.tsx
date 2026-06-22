"use client";

import { cn } from "@/lib/utils";
import { Bell, LogOut, User } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { useAuthStore } from "@/stores/auth";

interface HeaderProps {
  title: string;
}

/**
 * 顶部标题栏
 * - 页面标题（由父组件传入）
 * - 系统健康指示灯
 * - 用户菜单（用户名 + 登出）
 */
export function Header({ title }: HeaderProps) {
  const router = useRouter();
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);

  // 轮询系统健康状态，每 60 秒检查一次
  const { data: health } = useQuery({
    queryKey: ["health"],
    queryFn: () => api.getHealth(),
    refetchInterval: 60_000,
    retry: false,
  });

  const isHealthy = health?.status === "ok";

  const handleLogout = () => {
    logout();
    router.push("/login");
  };

  return (
    <header className="flex h-16 items-center justify-between border-b border-argus-border bg-argus-dark px-6">
      {/* 页面标题 */}
      <h1 className="text-lg font-semibold text-slate-100 lg:pl-0 pl-10">
        {title}
      </h1>

      {/* 右侧工具区 */}
      <div className="flex items-center gap-4">
        {/* 系统健康指示灯 */}
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <div
            className={cn(
              "h-2 w-2 rounded-full",
              isHealthy ? "bg-green-400 shadow-sm shadow-green-400/50" : "bg-red-500 shadow-sm shadow-red-500/50"
            )}
          />
          <span>{isHealthy ? "系统正常" : "系统异常"}</span>
        </div>

        {/* 通知铃铛 */}
        <button
          className="relative rounded-md p-2 text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-200"
          aria-label="通知"
        >
          <Bell className="h-4 w-4" />
          <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-argus-primary" />
        </button>

        {/* 用户信息 + 登出 */}
        <div className="flex items-center gap-2 border-l border-slate-700 pl-4">
          <div className="flex items-center gap-1.5 text-sm text-slate-300">
            <User className="h-4 w-4 text-slate-400" />
            <span>{user?.username ?? "未登录"}</span>
          </div>
          <button
            onClick={handleLogout}
            className="rounded-md p-1.5 text-slate-400 transition-colors hover:bg-slate-800 hover:text-red-400"
            aria-label="登出"
            title="退出登录"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </header>
  );
}
