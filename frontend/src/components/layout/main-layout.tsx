"use client";

import { AuthGuard } from "./auth-guard";
import { Sidebar } from "./sidebar";
import { Header } from "./header";

interface MainLayoutProps {
  children: React.ReactNode;
  title: string;
}

/**
 * 主布局组件
 * 组合：认证守卫 + 左侧导航栏 + 顶部标题栏 + 主内容区
 */
export function MainLayout({ children, title }: MainLayoutProps) {
  return (
    <AuthGuard>
      <div className="flex min-h-screen">
        {/* 左侧固定导航栏 */}
        <Sidebar />

        {/* 右侧内容区（桌面端给侧边栏留出 w-60 的空间） */}
        <div className="flex flex-1 flex-col lg:pl-60">
          <Header title={title} />

          {/* 主内容区 */}
          <main className="flex-1 overflow-auto p-6 scrollbar-thin">
            {children}
          </main>
        </div>
      </div>
    </AuthGuard>
  );
}
