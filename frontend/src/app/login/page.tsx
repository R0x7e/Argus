"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/stores/auth";
import { authApi } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const login = useAuthStore((s) => s.login);

  const [isRegister, setIsRegister] = useState(false);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (isRegister) {
        // 注册后自动登录
        await authApi.register(username, email, password);
      }

      // 登录
      const tokenData = await authApi.login(username, password);
      const { access_token } = tokenData;

      // 先保存 token，再请求 /me（否则 Authorization 头为空）
      login(access_token, { id: "", username, email: "", role: "" });

      // 获取完整用户信息并更新
      const userData = await authApi.me();
      login(access_token, userData);

      router.push("/");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "操作失败");
    } finally {
      setLoading(false);
    }
  };

  const inputClass =
    "w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2.5 text-sm text-slate-200 placeholder-slate-500 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500/50";

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
      <div className="w-full max-w-sm">
        {/* Logo / Title */}
        <div className="mb-8 text-center">
          <h1 className="text-3xl font-bold text-slate-100">Argus</h1>
          <p className="mt-2 text-sm text-slate-400">
            AI 漏洞挖掘多 Agent 系统
          </p>
        </div>

        {/* Form Card */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-6">
          <h2 className="mb-5 text-lg font-medium text-slate-200">
            {isRegister ? "创建账户" : "登录"}
          </h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
                {error}
              </div>
            )}

            <div>
              <label className="mb-1 block text-sm text-slate-400">
                用户名
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="输入用户名"
                required
                minLength={2}
                className={inputClass}
              />
            </div>

            {isRegister && (
              <div>
                <label className="mb-1 block text-sm text-slate-400">
                  邮箱
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@example.com"
                  required
                  className={inputClass}
                />
              </div>
            )}

            <div>
              <label className="mb-1 block text-sm text-slate-400">
                密码
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="至少 6 位"
                required
                minLength={6}
                className={inputClass}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-md bg-indigo-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? "处理中..." : isRegister ? "注册" : "登录"}
            </button>
          </form>

          <div className="mt-4 text-center">
            <button
              onClick={() => {
                setIsRegister(!isRegister);
                setError(null);
              }}
              className="text-sm text-indigo-400 hover:text-indigo-300"
            >
              {isRegister ? "已有账户? 去登录" : "没有账户? 去注册"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
