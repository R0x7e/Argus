"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { MainLayout } from "@/components/layout/main-layout";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useCreateTask } from "@/hooks/use-tasks";

/** 目标类型选项 */
const targetTypes = [
  { value: "web", label: "Web 应用" },
  { value: "api", label: "API 接口" },
  { value: "mobile", label: "移动应用" },
  { value: "binary", label: "二进制程序" },
  { value: "llm_app", label: "LLM 应用" },
] as const;

/** 策略选项 */
const strategies = [
  { value: "web_broad", label: "Web 广度扫描", target: "web" },
  { value: "web_deep", label: "Web 深度扫描", target: "web" },
  { value: "api_focused", label: "API 专项测试", target: "api" },
  { value: "mobile_re", label: "移动逆向分析", target: "mobile" },
  { value: "binary_fuzz", label: "二进制 Fuzz", target: "binary" },
  { value: "llm_specific", label: "LLM 专项测试", target: "llm_app" },
] as const;

export default function NewTaskPage() {
  const router = useRouter();
  const createTask = useCreateTask();

  const [name, setName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [targetType, setTargetType] = useState<string>("web");
  const [strategy, setStrategy] = useState<string>("web_broad");
  const [maxIterations, setMaxIterations] = useState(5);
  const [error, setError] = useState<string | null>(null);

  const availableStrategies = strategies.filter((s) => s.target === targetType);

  const handleTargetTypeChange = (type: string) => {
    setTargetType(type);
    const firstStrategy = strategies.find((s) => s.target === type);
    if (firstStrategy) setStrategy(firstStrategy.value);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!name.trim()) {
      setError("请输入任务名称");
      return;
    }
    if (!targetUrl.trim()) {
      setError("请输入目标 URL");
      return;
    }

    try {
      await createTask.mutateAsync({
        name: name.trim(),
        target_type: targetType as any,
        target_config: { target_url: targetUrl.trim() },
        strategy: strategy as any,
        max_iterations: maxIterations,
      });
      router.push("/tasks");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "创建任务失败");
    }
  };

  const inputClass =
    "w-full rounded-md border border-argus-border bg-argus-dark px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:border-argus-primary focus:outline-none focus:ring-1 focus:ring-argus-primary/50";

  return (
    <MainLayout title="新建任务">
      <div className="mx-auto max-w-2xl">
        <Card>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-5">
              {error && (
                <div className="rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                  {error}
                </div>
              )}

              {/* 任务名称 */}
              <div>
                <label className="mb-1.5 block text-sm font-medium text-slate-300">
                  任务名称 <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="例：Example.com 安全扫描"
                  className={inputClass}
                />
              </div>

              {/* 目标 URL */}
              <div>
                <label className="mb-1.5 block text-sm font-medium text-slate-300">
                  目标 URL <span className="text-red-400">*</span>
                </label>
                <input
                  type="url"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  className={inputClass}
                />
              </div>

              {/* 目标类型 */}
              <div>
                <label className="mb-1.5 block text-sm font-medium text-slate-300">
                  目标类型
                </label>
                <select
                  value={targetType}
                  onChange={(e) => handleTargetTypeChange(e.target.value)}
                  className={inputClass}
                >
                  {targetTypes.map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.label}
                    </option>
                  ))}
                </select>
              </div>

              {/* 测试策略 */}
              <div>
                <label className="mb-1.5 block text-sm font-medium text-slate-300">
                  测试策略
                </label>
                <select
                  value={strategy}
                  onChange={(e) => setStrategy(e.target.value)}
                  className={inputClass}
                >
                  {availableStrategies.map((s) => (
                    <option key={s.value} value={s.value}>
                      {s.label}
                    </option>
                  ))}
                </select>
              </div>

              {/* 最大迭代次数 */}
              <div>
                <label className="mb-1.5 block text-sm font-medium text-slate-300">
                  最大迭代次数
                </label>
                <input
                  type="number"
                  min={1}
                  max={20}
                  value={maxIterations}
                  onChange={(e) => setMaxIterations(parseInt(e.target.value) || 5)}
                  className={inputClass}
                />
                <p className="mt-1 text-xs text-slate-500">
                  Agent 循环执行的最大次数，越多越深入但耗时更长
                </p>
              </div>

              {/* 提交按钮 */}
              <div className="flex items-center justify-end gap-3 pt-2">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => router.push("/tasks")}
                >
                  取消
                </Button>
                <Button
                  type="submit"
                  variant="primary"
                  loading={createTask.isPending}
                >
                  创建任务
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}
