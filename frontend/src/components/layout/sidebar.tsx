"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard,
  ListTodo,
  Shield,
  Settings,
  Menu,
  X,
} from "lucide-react";

/** 导航链接配置 */
const navLinks = [
  { href: "/", label: "控制台", icon: LayoutDashboard },
  { href: "/tasks", label: "任务管理", icon: ListTodo },
  { href: "/findings", label: "漏洞列表", icon: Shield },
  { href: "/settings", label: "系统设置", icon: Settings },
];

/**
 * 左侧导航栏
 * - 桌面端固定展开
 * - 移动端可折叠（汉堡菜单切换）
 */
export function Sidebar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  /** 判断链接是否处于活跃状态 */
  const isActive = (href: string) => {
    if (href === "/") return pathname === "/";
    return pathname.startsWith(href);
  };

  return (
    <>
      {/* 移动端：汉堡按钮（固定在左上角） */}
      <button
        className="fixed left-4 top-4 z-50 rounded-md bg-argus-card p-2 text-slate-400 hover:text-white lg:hidden"
        onClick={() => setMobileOpen(!mobileOpen)}
        aria-label="切换导航"
      >
        {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
      </button>

      {/* 移动端遮罩层 */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* 侧边栏主体 */}
      <aside
        className={cn(
          "fixed left-0 top-0 z-40 flex h-screen w-60 flex-col border-r border-argus-border bg-argus-dark transition-transform duration-200",
          // 移动端：默认隐藏，展开时滑入
          mobileOpen ? "translate-x-0" : "-translate-x-full",
          // 桌面端：始终可见
          "lg:translate-x-0"
        )}
      >
        {/* Logo 区域 */}
        <div className="flex h-16 items-center gap-2 border-b border-argus-border px-6">
          <Shield className="h-6 w-6 text-argus-primary" />
          <span className="text-lg font-bold tracking-wide text-white">
            ARGUS
          </span>
        </div>

        {/* 导航链接列表 */}
        <nav className="mt-4 flex flex-1 flex-col gap-1 px-3">
          {navLinks.map(({ href, label, icon: Icon }) => (
            <Link
              key={href}
              href={href}
              onClick={() => setMobileOpen(false)}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-colors duration-150",
                isActive(href)
                  ? "bg-argus-primary/15 text-argus-primary"
                  : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
              )}
            >
              <Icon className="h-4 w-4 flex-shrink-0" />
              {label}
            </Link>
          ))}
        </nav>

        {/* 底部版本信息 */}
        <div className="border-t border-argus-border px-6 py-3">
          <p className="text-xs text-slate-600">Argus v0.1.0</p>
        </div>
      </aside>
    </>
  );
}
