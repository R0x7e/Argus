"use client";

import { useState } from "react";
import Link from "next/link";
import { MainLayout } from "@/components/layout/main-layout";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Loading } from "@/components/ui/loading";
import { EmptyState } from "@/components/ui/empty-state";
import { useFindings } from "@/hooks/use-findings";
import { formatDate, cn } from "@/lib/utils";
import type { Severity, Finding } from "@/types";
import { Shield, ChevronDown, ChevronUp } from "lucide-react";

/** 严重程度筛选选项 */
const severityOptions: { value: string; label: string }[] = [
  { value: "all", label: "全部" },
  { value: "critical", label: "严重" },
  { value: "high", label: "高危" },
  { value: "medium", label: "中危" },
  { value: "low", label: "低危" },
];

export default function FindingsPage() {
  const [severityFilter, setSeverityFilter] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // 构建查询参数
  const params: Record<string, string> = {};
  if (severityFilter !== "all") {
    params.severity = severityFilter;
  }

  const { data, isLoading } = useFindings(
    Object.keys(params).length > 0 ? params : undefined
  );

  /** 切换展开行 */
  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  return (
    <MainLayout title="漏洞列表">
      {/* 筛选栏 */}
      <div className="mb-6 flex flex-wrap items-center gap-2">
        <span className="text-sm text-slate-400">严重程度:</span>
        {severityOptions.map((opt) => (
          <Button
            key={opt.value}
            variant={severityFilter === opt.value ? "primary" : "ghost"}
            size="sm"
            onClick={() => setSeverityFilter(opt.value)}
          >
            {opt.label}
          </Button>
        ))}
        <span className="ml-auto text-sm text-slate-500">
          共 {data?.total ?? 0} 条
        </span>
      </div>

      {/* 漏洞表格 */}
      <Card>
        <CardContent>
          {isLoading ? (
            <Loading label="加载漏洞列表..." />
          ) : !data?.items.length ? (
            <EmptyState
              icon={Shield}
              title="暂无漏洞发现"
              description="当扫描任务运行后，发现的漏洞将会展示在这里"
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-argus-border text-left text-xs text-slate-500">
                    <th className="pb-3 pr-4 font-medium w-8"></th>
                    <th className="pb-3 pr-4 font-medium">标题</th>
                    <th className="pb-3 pr-4 font-medium">类型</th>
                    <th className="pb-3 pr-4 font-medium">严重程度</th>
                    <th className="pb-3 pr-4 font-medium">状态</th>
                    <th className="pb-3 pr-4 font-medium">关联任务</th>
                    <th className="pb-3 font-medium">发现时间</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((finding) => (
                    <>
                      {/* 主行 */}
                      <tr
                        key={finding.id}
                        className={cn(
                          "border-b border-argus-border/50 cursor-pointer transition-colors hover:bg-slate-700/20",
                          expandedId === finding.id && "bg-slate-700/20"
                        )}
                        onClick={() => toggleExpand(finding.id)}
                      >
                        <td className="py-3 pr-2">
                          {expandedId === finding.id ? (
                            <ChevronUp className="h-3.5 w-3.5 text-slate-500" />
                          ) : (
                            <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
                          )}
                        </td>
                        <td className="py-3 pr-4">
                          <Link
                            href={`/findings/${finding.id}`}
                            className="font-medium text-slate-200 hover:text-argus-primary"
                            onClick={(e) => e.stopPropagation()}
                          >
                            {finding.title}
                          </Link>
                        </td>
                        <td className="py-3 pr-4 text-slate-400">
                          {finding.type}
                        </td>
                        <td className="py-3 pr-4">
                          <Badge severity={finding.severity}>
                            {finding.severity}
                          </Badge>
                        </td>
                        <td className="py-3 pr-4">
                          <Badge status={finding.status}>
                            {finding.status}
                          </Badge>
                        </td>
                        <td className="py-3 pr-4">
                          <Link
                            href={`/tasks/${finding.task_id}`}
                            className="text-xs text-argus-primary hover:underline"
                            onClick={(e) => e.stopPropagation()}
                          >
                            查看任务
                          </Link>
                        </td>
                        <td className="py-3 text-slate-500">
                          {formatDate(finding.created_at)}
                        </td>
                      </tr>

                      {/* 展开详情行 */}
                      {expandedId === finding.id && (
                        <tr key={`${finding.id}-detail`} className="border-b border-argus-border/50">
                          <td colSpan={7} className="px-4 py-4">
                            <div className="rounded-md border border-argus-border/50 bg-argus-dark p-4 text-xs">
                              <p className="mb-2 text-slate-300">
                                {finding.description || "暂无描述"}
                              </p>
                              {finding.trigger_path && (
                                <p className="text-slate-500">
                                  路径: {typeof finding.trigger_path === 'object' ? JSON.stringify(finding.trigger_path) : finding.trigger_path}
                                </p>
                              )}
                              {finding.fix_suggestion && (
                                <p className="mt-2 text-slate-400">
                                  建议: {finding.fix_suggestion}
                                </p>
                              )}
                              <div className="mt-3">
                                <Link href={`/findings/${finding.id}`}>
                                  <Button variant="ghost" size="sm">
                                    查看完整详情
                                  </Button>
                                </Link>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </MainLayout>
  );
}
