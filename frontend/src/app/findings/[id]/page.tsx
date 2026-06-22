"use client";

import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { MainLayout } from "@/components/layout/main-layout";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Loading } from "@/components/ui/loading";
import { EmptyState } from "@/components/ui/empty-state";
import { useFinding, useUpdateFinding } from "@/hooks/use-findings";
import { formatDate } from "@/lib/utils";
import {
  ArrowLeft,
  CheckCircle,
  XCircle,
  FileCode,
  AlertTriangle,
} from "lucide-react";

export default function FindingDetailPage() {
  const params = useParams();
  const router = useRouter();
  const findingId = params.id as string;

  const { data: finding, isLoading } = useFinding(findingId);
  const updateFinding = useUpdateFinding();

  /** 确认漏洞 */
  const handleConfirm = () => {
    updateFinding.mutate({
      id: findingId,
      data: { status: "confirmed" },
    });
  };

  /** 标记为误报 */
  const handleFalsePositive = () => {
    updateFinding.mutate({
      id: findingId,
      data: { status: "false_positive" },
    });
  };

  if (isLoading) {
    return (
      <MainLayout title="漏洞详情">
        <Loading size="lg" label="加载漏洞详情..." />
      </MainLayout>
    );
  }

  if (!finding) {
    return (
      <MainLayout title="漏洞详情">
        <EmptyState
          title="漏洞不存在"
          description="找不到该漏洞记录，可能已被删除"
        />
      </MainLayout>
    );
  }

  return (
    <MainLayout title="漏洞详情">
      {/* 返回导航 */}
      <button
        onClick={() => router.back()}
        className="mb-4 flex items-center gap-1 text-sm text-slate-400 hover:text-slate-200"
      >
        <ArrowLeft className="h-4 w-4" />
        返回
      </button>

      {/* ========== 头部：标题 + 标签 + 操作 ========== */}
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="mb-2 text-xl font-bold text-slate-100">
            {finding.title}
          </h2>
          <div className="flex flex-wrap items-center gap-2">
            <Badge severity={finding.severity}>{finding.severity}</Badge>
            <Badge status={finding.status}>{finding.status}</Badge>
            <span className="text-xs text-slate-500">
              类型: {finding.type}
            </span>
          </div>
        </div>

        {/* 操作按钮 */}
        <div className="flex gap-2">
          {finding.status === "draft" && (
            <>
              <Button
                variant="primary"
                size="sm"
                onClick={handleConfirm}
                loading={
                  updateFinding.isPending &&
                  updateFinding.variables?.data.status === "confirmed"
                }
              >
                <CheckCircle className="h-4 w-4" />
                确认漏洞
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={handleFalsePositive}
                loading={
                  updateFinding.isPending &&
                  updateFinding.variables?.data.status === "false_positive"
                }
              >
                <XCircle className="h-4 w-4" />
                标记误报
              </Button>
            </>
          )}
          <Link href={`/tasks/${finding.task_id}`}>
            <Button variant="ghost" size="sm">
              查看关联任务
            </Button>
          </Link>
        </div>
      </div>

      {/* ========== 详情内容区 ========== */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* 描述 */}
        <Card>
          <CardHeader>
            <CardTitle>
              <AlertTriangle className="mr-1 inline h-4 w-4" />
              漏洞描述
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-300">
              {finding.description || "暂无描述"}
            </p>
            {finding.payload && (
              <div className="mt-4 border-t border-argus-border/50 pt-3">
                <span className="text-xs text-slate-500">Payload: </span>
                <code className="text-xs text-slate-300">{finding.payload}</code>
              </div>
            )}
          </CardContent>
        </Card>

        {/* 元信息 */}
        <Card>
          <CardHeader>
            <CardTitle>详细信息</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="space-y-3 text-sm">
              {finding.trigger_path && (
                <div>
                  <dt className="text-xs text-slate-500">触发路径</dt>
                  <dd className="font-mono text-slate-300">
                    {typeof finding.trigger_path === 'object'
                      ? JSON.stringify(finding.trigger_path, null, 2)
                      : finding.trigger_path}
                  </dd>
                </div>
              )}
              {finding.impact_assessment && (
                <div>
                  <dt className="text-xs text-slate-500">影响评估</dt>
                  <dd className="text-slate-300">{finding.impact_assessment}</dd>
                </div>
              )}
              {finding.verified_at && (
                <div>
                  <dt className="text-xs text-slate-500">验证时间</dt>
                  <dd className="text-slate-300">{formatDate(finding.verified_at)}</dd>
                </div>
              )}
              <div>
                <dt className="text-xs text-slate-500">发现时间</dt>
                <dd className="text-slate-300">{formatDate(finding.created_at)}</dd>
              </div>
              <div>
                <dt className="text-xs text-slate-500">更新时间</dt>
                <dd className="text-slate-300">{formatDate(finding.updated_at ?? finding.created_at)}</dd>
              </div>
            </dl>
          </CardContent>
        </Card>

        {/* 证据 */}
        {finding.evidence && Object.keys(finding.evidence).length > 0 && (
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>
                <FileCode className="mr-1 inline h-4 w-4" />
                证据
              </CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="overflow-x-auto rounded-md bg-argus-dark p-4 text-xs leading-relaxed text-slate-300 scrollbar-thin">
                <code>{JSON.stringify(finding.evidence, null, 2)}</code>
              </pre>
            </CardContent>
          </Card>
        )}

        {/* 复现步骤 */}
        {finding.reproduction_steps && (
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>复现步骤</CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="overflow-x-auto rounded-md bg-argus-dark p-4 text-xs leading-relaxed text-slate-300 scrollbar-thin">
                <code>{JSON.stringify(finding.reproduction_steps, null, 2)}</code>
              </pre>
            </CardContent>
          </Card>
        )}

        {/* 修复建议 */}
        {finding.fix_suggestion && (
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>修复建议</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-300">
                {finding.fix_suggestion}
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </MainLayout>
  );
}
