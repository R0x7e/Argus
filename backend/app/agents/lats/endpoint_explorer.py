"""
端点聚焦探索器 (v21 — HDE 架构 Phase 1)

用 PerEndpointContext 替代 MCTS 组合树搜索中的 SearchNode 分支。
每个端点维护独立的探索上下文，包含基线响应、已知参数、假设历史和诊断记录。

架构变更:
- 旧: 每个 (endpoint, vuln_type, param) 三元组 → 独立 SearchNode
- 新: 每个 endpoint → 一个 PerEndpointContext, 内含多假设探索管线
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class HypothesisRecord:
    """单条假设记录"""
    vuln_type: str
    param: str | None = None
    payload: str = ""
    result: str = ""           # "confirmed" | "rejected" | "inconclusive"
    evidence: str = ""
    step_count: int = 0
    diagnostic_category: str = ""  # DiagnosticProber 返回的分类


@dataclass
class PerEndpointContext:
    """单个端点的完整探索上下文

    替代 MCTS 的 SearchNode 树，将 (endpoint × vuln_type × param)
    的笛卡尔积扁平化为端点级的假设驱动探索。
    """

    endpoint_id: str
    endpoint_path: str           # URL 路径, 如 /vul/rce/rce_ping.php
    full_url: str = ""           # 完整 URL
    source: str = ""             # "target_url" | "form" | "crawl" | "dir_scan"

    # ── 端点特征 ──
    path_hints: list[str] = field(default_factory=list)   # URL路径暗示的漏洞类型
    known_params: list[str] = field(default_factory=list)  # 已知参数名列表
    known_forms: list[dict] = field(default_factory=list)

    # ── 基线响应 ──
    baseline_status: int = 0
    baseline_len: int = 0
    baseline_time_ms: int = 0
    baseline_headers: dict = field(default_factory=dict)
    baseline_body_preview: str = ""

    # ── 探索状态 ──
    priority_score: float = 0.0
    status: str = "pending"      # "pending" | "exploring" | "exhausted" | "confirmed"
    explored_count: int = 0

    # ── 假设历史 ──
    active_hypothesis: HypothesisRecord | None = None
    tried_hypotheses: list[HypothesisRecord] = field(default_factory=list)
    confirmed_vulns: list[dict] = field(default_factory=list)

    # ── 诊断历史 ──
    diagnostic_history: list[str] = field(default_factory=list)
    last_diagnostic: str = ""

    def mark_exploring(self) -> None:
        self.status = "exploring"

    def mark_exhausted(self) -> None:
        self.status = "exhausted"

    def mark_confirmed(self, finding: dict) -> None:
        self.status = "confirmed"
        self.confirmed_vulns.append(finding)

    def record_hypothesis(self, record: HypothesisRecord) -> None:
        self.tried_hypotheses.append(record)
        if record.result == "confirmed":
            self.active_hypothesis = record

    def record_diagnostic(self, category: str) -> None:
        self.diagnostic_history.append(category)
        self.last_diagnostic = category

    def get_unattempted_params(self) -> list[str]:
        """返回尚未尝试过的参数名"""
        tried_params = {h.param for h in self.tried_hypotheses if h.param}
        return [p for p in self.known_params if p not in tried_params]

    def get_unattempted_vuln_types(self) -> list[str]:
        """返回尚未尝试过的漏洞类型"""
        tried_types = {h.vuln_type for h in self.tried_hypotheses}
        return [t for t in self.path_hints if t not in tried_types]

    def to_dict(self) -> dict:
        return {
            "endpoint_id": self.endpoint_id,
            "endpoint_path": self.endpoint_path,
            "full_url": self.full_url,
            "source": self.source,
            "path_hints": self.path_hints,
            "known_params": self.known_params,
            "priority_score": round(self.priority_score, 3),
            "status": self.status,
            "explored_count": self.explored_count,
            "active_hypothesis": {
                "vuln_type": self.active_hypothesis.vuln_type,
                "param": self.active_hypothesis.param,
            } if self.active_hypothesis else None,
            "diagnostic_history": self.diagnostic_history[-5:],
            "confirmed_vulns": [
                {"type": v.get("type", ""), "severity": v.get("severity", "")}
                for v in self.confirmed_vulns
            ],
        }


class EndpointExplorer:
    """端点探索管理器 — 替代 SearchTree 的探索调度

    职责:
    1. 管理 PerEndpointContext 列表
    2. 提供端点状态查询接口
    3. 生成前端兼容的端点快照
    """

    def __init__(self):
        self.contexts: dict[str, PerEndpointContext] = {}
        self.global_step: int = 0
        self.total_confirmed: int = 0

    def add_context(self, ctx: PerEndpointContext) -> None:
        self.contexts[ctx.endpoint_id] = ctx

    def get_context(self, endpoint_id: str) -> PerEndpointContext | None:
        return self.contexts.get(endpoint_id)

    def get_active_contexts(self) -> list[PerEndpointContext]:
        """获取所有非 exhausted 的端点"""
        return [
            ctx for ctx in self.contexts.values()
            if ctx.status != "exhausted"
        ]

    def get_pending_contexts(self) -> list[PerEndpointContext]:
        return [ctx for ctx in self.contexts.values() if ctx.status == "pending"]

    def all_explored(self) -> bool:
        active = [c for c in self.contexts.values() if c.status not in ("exhausted", "confirmed")]
        return len(active) == 0

    def stats(self) -> dict:
        total = len(self.contexts)
        explored = sum(1 for c in self.contexts.values() if c.explored_count > 0)
        confirmed = sum(1 for c in self.contexts.values() if c.confirmed_vulns)
        hypotheses = sum(len(c.tried_hypotheses) for c in self.contexts.values())
        return {
            "total_endpoints": total,
            "endpoints_explored": explored,
            "endpoints_confirmed": confirmed,
            "total_hypotheses": hypotheses,
            "total_confirmed_vulns": self.total_confirmed,
            "global_step": self.global_step,
        }

    def snapshot(self) -> list[dict]:
        """生成前端兼容的端点快照"""
        snapshots = []
        for ctx in self.contexts.values():
            snapshots.append(ctx.to_dict())
        # 按优先级降序排列
        snapshots.sort(key=lambda x: x["priority_score"], reverse=True)
        return snapshots
