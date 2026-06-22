"use client";

import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { MainLayout } from "@/components/layout/main-layout";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Loading } from "@/components/ui/loading";
import { EmptyState } from "@/components/ui/empty-state";
import { api } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { ArrowLeft, FileText, Download } from "lucide-react";

export default function TaskReportPage() {
  const params = useParams();
  const router = useRouter();
  const taskId = params.id as string;

  const {
    data: report,
    isLoading,
    error,
  } = useQuery({
    queryKey: ["report", taskId],
    queryFn: () => api.getReport(taskId),
    enabled: !!taskId,
  });

  const handleDownload = () => {
    if (!report) return;
    const blob = new Blob([report.content], {
      type: report.format === "json" ? "application/json" : "text/markdown",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `report-${taskId.slice(0, 8)}.${report.format === "json" ? "json" : "md"}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading) {
    return (
      <MainLayout title="扫描报告">
        <Loading size="lg" label="加载报告..." />
      </MainLayout>
    );
  }

  if (error || !report) {
    return (
      <MainLayout title="扫描报告">
        <button
          onClick={() => router.back()}
          className="mb-4 flex items-center gap-1 text-sm text-slate-400 hover:text-slate-200"
        >
          <ArrowLeft className="h-4 w-4" />
          返回
        </button>
        <EmptyState
          icon={FileText}
          title="暂无报告"
          description="该任务尚未生成报告，请等待扫描完成后查看"
        />
      </MainLayout>
    );
  }

  return (
    <MainLayout title="扫描报告">
      {/* 顶部导航 */}
      <div className="mb-4 flex items-center justify-between">
        <button
          onClick={() => router.back()}
          className="flex items-center gap-1 text-sm text-slate-400 hover:text-slate-200"
        >
          <ArrowLeft className="h-4 w-4" />
          返回任务
        </button>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-500">
            生成时间: {formatDate(report.created_at)}
          </span>
          <span className="text-xs text-slate-500">
            版本: v{report.version}
          </span>
          <Button variant="secondary" size="sm" onClick={handleDownload}>
            <Download className="h-3.5 w-3.5" />
            导出
          </Button>
        </div>
      </div>

      {/* 报告内容 */}
      <Card>
        <CardHeader>
          <CardTitle>
            <FileText className="mr-1 inline h-4 w-4" />
            漏洞扫描报告
          </CardTitle>
        </CardHeader>
        <CardContent>
          {report.format === "json" ? (
            <pre className="overflow-x-auto rounded-md bg-argus-dark p-4 text-xs leading-relaxed text-slate-300 scrollbar-thin">
              <code>
                {typeof report.content === "string"
                  ? (() => {
                      try {
                        return JSON.stringify(JSON.parse(report.content), null, 2);
                      } catch {
                        return report.content;
                      }
                    })()
                  : JSON.stringify(report.content, null, 2)}
              </code>
            </pre>
          ) : (
            <div className="whitespace-pre-wrap text-sm leading-relaxed text-slate-300">
              {report.content}
            </div>
          )}
        </CardContent>
      </Card>

      {/* 报告元数据 */}
      {report.report_metadata && Object.keys(report.report_metadata).length > 0 && (
        <Card className="mt-4">
          <CardHeader>
            <CardTitle>报告元数据</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="overflow-x-auto rounded-md bg-argus-dark p-4 text-xs leading-relaxed text-slate-300 scrollbar-thin">
              <code>{JSON.stringify(report.report_metadata, null, 2)}</code>
            </pre>
          </CardContent>
        </Card>
      )}
    </MainLayout>
  );
}
