"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight, Zap, Brain, Eye } from "lucide-react";

interface StepData {
  node_id: string;
  step: number;
  thought: string;
  action: string;
  action_params: Record<string, any>;
  observation: string;
  success: boolean;
  reward: number;
  new_facts: string[];
  vuln_confirmed: boolean;
  duration_ms: number;
  tool_name: string;
  timestamp?: string;
}

interface StepCardProps {
  step: StepData;
}

export function StepCard({ step }: StepCardProps) {
  const [paramsExpanded, setParamsExpanded] = useState(false);

  return (
    <div className="rounded-lg border border-argus-border/50 bg-argus-dark p-3">
      {/* Header */}
      <div className="mb-2 flex items-center justify-between">
        <span className="text-xs font-medium text-slate-400">
          Step {step.step + 1}
        </span>
        <div className="flex items-center gap-2 text-[10px] text-slate-500">
          {step.duration_ms > 0 && (
            <span>{step.duration_ms}ms</span>
          )}
          <span
            className={`rounded px-1.5 py-0.5 font-mono ${
              step.reward > 0.5
                ? "bg-green-500/10 text-green-400"
                : step.reward > 0
                ? "bg-yellow-500/10 text-yellow-400"
                : "bg-slate-500/10 text-slate-500"
            }`}
          >
            r={step.reward.toFixed(2)}
          </span>
        </div>
      </div>

      {/* Thought */}
      <div className="mb-2 rounded border-l-2 border-yellow-500/60 bg-yellow-500/5 px-3 py-2">
        <div className="mb-1 flex items-center gap-1 text-[10px] font-medium text-yellow-400">
          <Brain className="h-3 w-3" />
          Thought
        </div>
        <p className="text-xs leading-relaxed text-slate-300">{step.thought || "—"}</p>
      </div>

      {/* Action */}
      <div className="mb-2 rounded border-l-2 border-blue-500/60 bg-blue-500/5 px-3 py-2">
        <div className="mb-1 flex items-center gap-1 text-[10px] font-medium text-blue-400">
          <Zap className="h-3 w-3" />
          Action
          <span className="ml-1 rounded bg-blue-500/20 px-1.5 py-0.5 font-mono text-[10px]">
            {step.action}
          </span>
          {step.tool_name && (
            <span className="rounded bg-slate-600/40 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
              {step.tool_name}
            </span>
          )}
        </div>
        {step.action_params && Object.keys(step.action_params).length > 0 && (
          <div>
            <button
              onClick={() => setParamsExpanded(!paramsExpanded)}
              className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-300"
            >
              {paramsExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
              参数
            </button>
            {paramsExpanded && (
              <pre className="mt-1 overflow-x-auto rounded bg-slate-900/50 p-2 text-[10px] text-slate-400">
                {JSON.stringify(step.action_params, null, 2)}
              </pre>
            )}
          </div>
        )}
      </div>

      {/* Observation */}
      <div
        className={`rounded border-l-2 px-3 py-2 ${
          step.vuln_confirmed
            ? "border-red-500/60 bg-red-500/5"
            : step.success
            ? "border-green-500/60 bg-green-500/5"
            : "border-slate-500/60 bg-slate-500/5"
        }`}
      >
        <div
          className={`mb-1 flex items-center gap-1 text-[10px] font-medium ${
            step.vuln_confirmed
              ? "text-red-400"
              : step.success
              ? "text-green-400"
              : "text-slate-400"
          }`}
        >
          <Eye className="h-3 w-3" />
          Observation
          {step.vuln_confirmed && (
            <span className="ml-1 rounded bg-red-500/20 px-1.5 py-0.5 text-[10px] font-bold text-red-300">
              漏洞确认
            </span>
          )}
        </div>
        <p className="text-xs leading-relaxed text-slate-300">{step.observation || "—"}</p>
        {step.new_facts && step.new_facts.length > 0 && (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {step.new_facts.map((fact, i) => (
              <span
                key={i}
                className="rounded bg-emerald-500/10 px-1.5 py-0.5 text-[10px] text-emerald-400"
              >
                {fact}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
