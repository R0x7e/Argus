"use client";

import { useState } from "react";
import { MainLayout } from "@/components/layout/main-layout";
import {
  useLLMProviders,
  useCreateLLMProvider,
  useUpdateLLMProvider,
  useDeleteLLMProvider,
  useTestLLMProvider,
} from "@/hooks/use-llm-providers";
import type { LLMProvider, LLMProviderCreate, LLMProviderType } from "@/types";

const PROVIDER_TYPES: { value: LLMProviderType; label: string }[] = [
  { value: "anthropic", label: "Anthropic (Claude)" },
  { value: "openai", label: "OpenAI (GPT)" },
  { value: "deepseek", label: "DeepSeek" },
  { value: "zhipu", label: "智谱 (GLM)" },
  { value: "qwen", label: "通义千问 (Qwen)" },
  { value: "custom", label: "自定义 (OpenAI 兼容)" },
];

const DEFAULT_MODELS: Record<LLMProviderType, string> = {
  anthropic: "claude-sonnet-4-6",
  openai: "gpt-4o",
  deepseek: "deepseek-chat",
  zhipu: "glm-4",
  qwen: "qwen-plus",
  custom: "",
};

const DEFAULT_BASE_URLS: Record<string, string> = {
  deepseek: "https://api.deepseek.com/v1",
  zhipu: "https://open.bigmodel.cn/api/paas/v4",
  qwen: "https://dashscope.aliyuncs.com/compatible-mode/v1",
};

function ProviderBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    anthropic: "bg-orange-500/20 text-orange-300",
    openai: "bg-green-500/20 text-green-300",
    deepseek: "bg-blue-500/20 text-blue-300",
    zhipu: "bg-purple-500/20 text-purple-300",
    qwen: "bg-cyan-500/20 text-cyan-300",
    custom: "bg-slate-500/20 text-slate-300",
  };
  return (
    <span className={`inline-flex rounded px-2 py-0.5 text-xs font-medium ${colors[type] || colors.custom}`}>
      {PROVIDER_TYPES.find((p) => p.value === type)?.label || type}
    </span>
  );
}

interface FormState {
  provider_type: LLMProviderType;
  display_name: string;
  api_key: string;
  base_url: string;
  default_model: string;
  is_active: boolean;
  priority: number;
}

const emptyForm: FormState = {
  provider_type: "anthropic",
  display_name: "",
  api_key: "",
  base_url: "",
  default_model: "claude-sonnet-4-6",
  is_active: true,
  priority: 10,
};

export default function SettingsPage() {
  const { data: providers, isLoading } = useLLMProviders();
  const createMutation = useCreateLLMProvider();
  const updateMutation = useUpdateLLMProvider();
  const deleteMutation = useDeleteLLMProvider();
  const testMutation = useTestLLMProvider();

  const [showModal, setShowModal] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<FormState>(emptyForm);
  const [testResult, setTestResult] = useState<{ success: boolean; latency_ms?: number; error?: string } | null>(null);

  const openCreate = () => {
    setEditingId(null);
    setForm(emptyForm);
    setTestResult(null);
    setShowModal(true);
  };

  const openEdit = (provider: LLMProvider) => {
    setEditingId(provider.id);
    setForm({
      provider_type: provider.provider_type,
      display_name: provider.display_name,
      api_key: "",
      base_url: provider.base_url || "",
      default_model: provider.default_model,
      is_active: provider.is_active,
      priority: provider.priority,
    });
    setTestResult(null);
    setShowModal(true);
  };

  const handleProviderTypeChange = (type: LLMProviderType) => {
    setForm((f) => ({
      ...f,
      provider_type: type,
      default_model: DEFAULT_MODELS[type] || f.default_model,
      base_url: DEFAULT_BASE_URLS[type] || "",
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const payload: LLMProviderCreate = {
      provider_type: form.provider_type,
      display_name: form.display_name,
      api_key: form.api_key,
      default_model: form.default_model,
      is_active: form.is_active,
      priority: form.priority,
    };
    if (form.base_url) payload.base_url = form.base_url;

    if (editingId) {
      const updatePayload: Partial<LLMProviderCreate> = { ...payload };
      if (!form.api_key) delete updatePayload.api_key;
      await updateMutation.mutateAsync({ id: editingId, data: updatePayload });
    } else {
      await createMutation.mutateAsync(payload);
    }
    setShowModal(false);
  };

  const handleTest = async () => {
    setTestResult(null);
    const result = await testMutation.mutateAsync({
      provider_type: form.provider_type,
      api_key: form.api_key,
      base_url: form.base_url || undefined,
      model: form.default_model,
    });
    setTestResult(result);
  };

  const handleDelete = async (id: string) => {
    if (confirm("确认删除此供应商配置？")) {
      await deleteMutation.mutateAsync(id);
    }
  };

  const inputClass =
    "w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500/50";

  const showBaseUrl = form.provider_type !== "anthropic";

  return (
    <MainLayout title="系统设置">
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-medium text-slate-100">AI 供应商配置</h2>
            <p className="mt-1 text-sm text-slate-400">
              配置 LLM 供应商的 API Key 和模型，支持多个供应商按优先级切换
            </p>
          </div>
          <button
            onClick={openCreate}
            className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
          >
            添加供应商
          </button>
        </div>

        {/* Provider List */}
        {isLoading ? (
          <div className="py-12 text-center text-slate-400">加载中...</div>
        ) : !providers?.length ? (
          <div className="rounded-lg border border-slate-800 bg-slate-900/50 px-6 py-12 text-center">
            <p className="text-slate-400">暂未配置任何 AI 供应商</p>
            <p className="mt-1 text-sm text-slate-500">
              点击"添加供应商"配置 API Key，系统将使用环境变量中的 ANTHROPIC_API_KEY 作为备选
            </p>
          </div>
        ) : (
          <div className="overflow-hidden rounded-lg border border-slate-800">
            <table className="w-full text-sm">
              <thead className="border-b border-slate-800 bg-slate-900/80">
                <tr>
                  <th className="px-4 py-3 text-left font-medium text-slate-400">名称</th>
                  <th className="px-4 py-3 text-left font-medium text-slate-400">类型</th>
                  <th className="px-4 py-3 text-left font-medium text-slate-400">模型</th>
                  <th className="px-4 py-3 text-left font-medium text-slate-400">API Key</th>
                  <th className="px-4 py-3 text-left font-medium text-slate-400">优先级</th>
                  <th className="px-4 py-3 text-left font-medium text-slate-400">状态</th>
                  <th className="px-4 py-3 text-right font-medium text-slate-400">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {providers.map((provider) => (
                  <tr key={provider.id} className="bg-slate-900/30 hover:bg-slate-900/60">
                    <td className="px-4 py-3 text-slate-200">{provider.display_name}</td>
                    <td className="px-4 py-3">
                      <ProviderBadge type={provider.provider_type} />
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-300">{provider.default_model}</td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-500">{provider.api_key_masked}</td>
                    <td className="px-4 py-3 text-slate-400">{provider.priority}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex rounded-full px-2 py-0.5 text-xs ${
                          provider.is_active
                            ? "bg-green-500/20 text-green-400"
                            : "bg-slate-600/20 text-slate-500"
                        }`}
                      >
                        {provider.is_active ? "启用" : "禁用"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => openEdit(provider)}
                        className="mr-2 text-indigo-400 hover:text-indigo-300"
                      >
                        编辑
                      </button>
                      <button
                        onClick={() => handleDelete(provider.id)}
                        className="text-red-400 hover:text-red-300"
                      >
                        删除
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
          <div className="w-full max-w-lg rounded-lg border border-slate-700 bg-slate-900 p-6">
            <h3 className="mb-4 text-lg font-medium text-slate-100">
              {editingId ? "编辑供应商" : "添加供应商"}
            </h3>

            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Provider Type */}
              <div>
                <label className="mb-1 block text-sm text-slate-400">供应商类型</label>
                <select
                  value={form.provider_type}
                  onChange={(e) => handleProviderTypeChange(e.target.value as LLMProviderType)}
                  className={inputClass}
                  disabled={!!editingId}
                >
                  {PROVIDER_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.label}
                    </option>
                  ))}
                </select>
              </div>

              {/* Display Name */}
              <div>
                <label className="mb-1 block text-sm text-slate-400">显示名称</label>
                <input
                  type="text"
                  value={form.display_name}
                  onChange={(e) => setForm((f) => ({ ...f, display_name: e.target.value }))}
                  placeholder="例如: 生产环境 Claude"
                  required
                  className={inputClass}
                />
              </div>

              {/* API Key */}
              <div>
                <label className="mb-1 block text-sm text-slate-400">
                  API Key {editingId && <span className="text-slate-600">(留空则不更新)</span>}
                </label>
                <input
                  type="password"
                  value={form.api_key}
                  onChange={(e) => setForm((f) => ({ ...f, api_key: e.target.value }))}
                  placeholder={editingId ? "••••••••" : "sk-..."}
                  required={!editingId}
                  className={inputClass}
                />
              </div>

              {/* Base URL */}
              {showBaseUrl && (
                <div>
                  <label className="mb-1 block text-sm text-slate-400">API Base URL</label>
                  <input
                    type="url"
                    value={form.base_url}
                    onChange={(e) => setForm((f) => ({ ...f, base_url: e.target.value }))}
                    placeholder="https://api.example.com/v1"
                    className={inputClass}
                  />
                </div>
              )}

              {/* Default Model */}
              <div>
                <label className="mb-1 block text-sm text-slate-400">默认模型</label>
                <input
                  type="text"
                  value={form.default_model}
                  onChange={(e) => setForm((f) => ({ ...f, default_model: e.target.value }))}
                  placeholder="模型 ID"
                  required
                  className={inputClass}
                />
              </div>

              {/* Priority & Active */}
              <div className="flex gap-4">
                <div className="flex-1">
                  <label className="mb-1 block text-sm text-slate-400">优先级 (1-100)</label>
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={form.priority}
                    onChange={(e) => setForm((f) => ({ ...f, priority: parseInt(e.target.value) || 10 }))}
                    className={inputClass}
                  />
                </div>
                <div className="flex items-end pb-1">
                  <label className="flex cursor-pointer items-center gap-2 text-sm text-slate-300">
                    <input
                      type="checkbox"
                      checked={form.is_active}
                      onChange={(e) => setForm((f) => ({ ...f, is_active: e.target.checked }))}
                      className="h-4 w-4 rounded border-slate-600 bg-slate-800"
                    />
                    启用
                  </label>
                </div>
              </div>

              {/* Test Connection */}
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={handleTest}
                  disabled={!form.api_key || !form.default_model || testMutation.isPending}
                  className="rounded-md border border-slate-600 px-3 py-1.5 text-sm text-slate-300 hover:border-slate-500 hover:text-slate-200 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {testMutation.isPending ? "测试中..." : "测试连接"}
                </button>
                {testResult && (
                  <span className={`text-sm ${testResult.success ? "text-green-400" : "text-red-400"}`}>
                    {testResult.success
                      ? `连接成功 (${testResult.latency_ms}ms)`
                      : `失败: ${testResult.error?.slice(0, 60)}`}
                  </span>
                )}
              </div>

              {/* Actions */}
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="rounded-md border border-slate-600 px-4 py-2 text-sm text-slate-300 hover:border-slate-500"
                >
                  取消
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending || updateMutation.isPending}
                  className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
                >
                  {createMutation.isPending || updateMutation.isPending ? "保存中..." : "保存"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </MainLayout>
  );
}
