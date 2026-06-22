"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/stores/auth";

/**
 * 认证守卫 — 包裹需要登录才能访问的页面内容
 * 未认证时自动跳转到 /login
 * 等待 Zustand persist hydration 完成后再判断
 */
export function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const token = useAuthStore((s) => s.token);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    setHydrated(true);
  }, []);

  useEffect(() => {
    if (hydrated && (!isAuthenticated || !token)) {
      router.replace("/login");
    }
  }, [hydrated, isAuthenticated, token, router]);

  if (!hydrated) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950">
        <div className="text-slate-400">加载中...</div>
      </div>
    );
  }

  if (!isAuthenticated || !token) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950">
        <div className="text-slate-400">正在跳转到登录页...</div>
      </div>
    );
  }

  return <>{children}</>;
}
