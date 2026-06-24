"use client";

import { useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import type { AgentEvent, Finding } from "@/types";

interface InterventionPanelProps {
  events: AgentEvent[];
  findings: Finding[];
  connected: boolean;
  taskId: string;
  wsSend?: (msg: object) => void;
}

const PRESET_PAYLOADS: Record<string, string[]> = {
  sqli: [
    "' OR '1'='1",
    "1 AND SLEEP(5)",
    "' UNION SELECT NULL,NULL,NULL--",
    "1; EXEC xp_cmdshell('whoami')--",
  ],
  xss: [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
  ],
  ssti: [
    "{{7*7}}",
    "${7*7}",
    "{{config}}",
  ],
  lfi: [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "php://filter/convert.base64-encode/resource=index",
  ],
  ssrf: [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8080/admin",
  ],
};

const FOCUS_OPTIONS = ["sql_injection", "xss", "ssrf", "auth_bypass", "idor", "lfi", "rce", "ssti", "info_disclosure"];

export function InterventionPanel({ events, findings, connected, taskId, wsSend }: InterventionPanelProps) {
  const [customEndpoint, setCustomEndpoint] = useState("");
  const [customParam, setCustomParam] = useState("");
  const [customType, setCustomType] = useState("sql_injection");
  const [customPayload, setCustomPayload] = useState("");
  const [customReason, setCustomReason] = useState("");
  const [selectedTab, setSelectedTab] = useState<"branch" | "payload" | "steer" | "falsepos">("branch");
  const [steeringDirective, setSteeringDirective] = useState("");
  const [focusTypes, setFocusTypes] = useState<string[]>([]);
  const [actionLog, setActionLog] = useState<string[]>([]);

  const sendAction = useCallback((action: string, params: Record<string, unknown>) => {
    if (!connected || !wsSend) {
      setActionLog((prev) => [...prev, `[离线] 无法发送 ${action}`].slice(-20));
      return;
    }
    wsSend({ type: "user_action", action, params });
    setActionLog((prev) => [...prev, `[已发送] ${action}`].slice(-20));
  }, [connected, wsSend]);

  const handleCreateBranch = () => {
    if (!customEndpoint) return;
    sendAction("create_branch", {
      endpoint: customEndpoint,
      param: customParam || null,
      vuln_type: customType,
      payload: customPayload,
      reason: customReason || "用户手动创建分支",
    });
    setCustomEndpoint("");
    setCustomParam("");
    setCustomReason("");
  };

  const handleInjectPayload = (payload: string) => {
    const treeEvents = events.filter((e) => e.type === "nodes_selected" || e.event_type === "nodes_selected");
    const lastSelection = treeEvents[treeEvents.length - 1];
    const nodeIds: string[] = lastSelection?.data?.selection_path || [];
    if (nodeIds.length > 0) {
      sendAction("inject_payload", { node_id: nodeIds[0], payload });
    } else {
      setActionLog((prev) => [...prev, "[错误] 没有选中的节点"].slice(-20));
    }
  };

  const handleSteer = () => {
    sendAction("steer_direction", {
      directive: steeringDirective,
      focus_types: focusTypes,
    });
    setSteeringDirective("");
  };

  const handleMarkFP = (findingId: string) => {
    sendAction("mark_false_positive", {
      finding_id: findingId,
      reason: "用户标记为误报",
    });
  };

  const toggleFocusType = (t: string) => {
    setFocusTypes((prev) => prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]);
  };

  const tabs = [
    { key: "branch" as const, label: "分支操作" },
    { key: "payload" as const, label: "Payload" },
    { key: "steer" as const, label: "方向引导" },
    { key: "falsepos" as const, label: "误报" },
  ];

  return (
    <div className="flex flex-col gap-4">
      {/* Tab 导航 */}
      <div className="flex gap-1 border-b border-slate-700/50 pb-2">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setSelectedTab(tab.key)}
            className={`px-3 py-1.5 text-xs font-medium rounded-t transition-colors ${
              selectedTab === tab.key
                ? "bg-slate-800 text-slate-200 border-t border-x border-slate-700/50"
                : "text-slate-500 hover:text-slate-300"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* 分支操作 */}
      {selectedTab === "branch" && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-slate-200">创建自定义分支</h3>
          <div className="space-y-2">
            <input
              type="text"
              placeholder="端点路径 (如 /api/admin/users)"
              value={customEndpoint}
              onChange={(e) => setCustomEndpoint(e.target.value)}
              className="w-full rounded bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500/50"
            />
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="参数名 (如 id)"
                value={customParam}
                onChange={(e) => setCustomParam(e.target.value)}
                className="flex-1 rounded bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500/50"
              />
              <select
                value={customType}
                onChange={(e) => setCustomType(e.target.value)}
                className="rounded bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-slate-200 focus:outline-none"
              >
                {FOCUS_OPTIONS.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
            <input
              type="text"
              placeholder="Payload (可选)"
              value={customPayload}
              onChange={(e) => setCustomPayload(e.target.value)}
              className="w-full rounded bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500/50 font-mono"
            />
            <input
              type="text"
              placeholder="理由 (可选)"
              value={customReason}
              onChange={(e) => setCustomReason(e.target.value)}
              className="w-full rounded bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500/50"
            />
            <Button variant="primary" size="sm" onClick={handleCreateBranch} disabled={!customEndpoint || !connected} className="w-full">
              创建分支 (HIGH_SIGNAL)
            </Button>
          </div>
        </div>
      )}

      {/* Payload 注入 */}
      {selectedTab === "payload" && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-slate-200">Payload 注入器</h3>
          {Object.entries(PRESET_PAYLOADS).map(([category, payloads]) => (
            <div key={category}>
              <div className="text-xs text-slate-500 mb-1.5 font-mono">{category.toUpperCase()}</div>
              <div className="space-y-1">
                {payloads.map((p) => (
                  <button
                    key={p}
                    onClick={() => handleInjectPayload(p)}
                    disabled={!connected}
                    className="w-full text-left rounded bg-slate-800 border border-slate-700/50 px-2 py-1.5 text-xs font-mono text-slate-300 hover:bg-slate-700/50 hover:border-blue-500/30 transition-colors truncate disabled:opacity-50"
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* 方向引导 */}
      {selectedTab === "steer" && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-slate-200">搜索方向引导</h3>
          <div className="space-y-2">
            <div className="flex flex-wrap gap-1">
              {FOCUS_OPTIONS.map((t) => (
                <button
                  key={t}
                  onClick={() => toggleFocusType(t)}
                  className={`px-2 py-1 rounded text-xs font-mono transition-colors ${
                    focusTypes.includes(t)
                      ? "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                      : "bg-slate-800 text-slate-500 border border-slate-700/50 hover:border-slate-600"
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
            <textarea
              placeholder="自定义指令 (如: 请重点关注 /api/internal/ 路径下的认证绕过漏洞)"
              value={steeringDirective}
              onChange={(e) => setSteeringDirective(e.target.value)}
              rows={3}
              className="w-full rounded bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500/50 resize-none"
            />
            <Button variant="primary" size="sm" onClick={handleSteer} disabled={!connected} className="w-full">
              应用指令
            </Button>
          </div>
        </div>
      )}

      {/* 误报标记 */}
      {selectedTab === "falsepos" && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-slate-200">误报管理 ({findings.length} 个发现)</h3>
          {findings.length === 0 ? (
            <div className="text-xs text-slate-500">暂无已确认发现</div>
          ) : (
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {findings.map((f) => (
                <div key={f.id} className="rounded bg-slate-800/50 border border-slate-700/30 p-2">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 mb-1">
                        <span className={`inline-block w-2 h-2 rounded-full ${
                          f.severity === "critical" ? "bg-red-500" :
                          f.severity === "high" ? "bg-orange-500" :
                          f.severity === "medium" ? "bg-yellow-500" : "bg-blue-500"
                        }`} />
                        <span className="text-xs font-medium text-slate-300 truncate">{f.title}</span>
                      </div>
                      <div className="text-[10px] text-slate-500 truncate">{f.description?.slice(0, 80)}</div>
                    </div>
                    <button
                      onClick={() => handleMarkFP(f.id)}
                      disabled={!connected}
                      className="shrink-0 px-2 py-1 text-[10px] rounded bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-colors disabled:opacity-50"
                    >
                      标记误报
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 操作日志 */}
      <div className="rounded-lg border border-slate-700/30 bg-slate-900/30 p-3">
        <h3 className="text-xs font-semibold text-slate-400 mb-2">操作日志</h3>
        <div className="max-h-32 overflow-y-auto space-y-0.5">
          {actionLog.length === 0 ? (
            <div className="text-[10px] text-slate-600">暂无操作</div>
          ) : (
            actionLog.map((log, i) => (
              <div key={i} className="text-[10px] font-mono text-slate-500">{log}</div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
