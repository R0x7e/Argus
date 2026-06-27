"""
端点优先级排序器 (v21 — HDE 架构 Phase 1)

替代 MCTS 的 select_batch，用端点级的优先级评分取代分支级的 UCB 选择。
评分公式:
  priority = 0.40 × vuln_type_severity (路径暗示的漏洞严重度)
           + 0.25 × endpoint_accessibility (端点可达性)
           + 0.20 × param_availability (参数可用性)
           + 0.10 × source_credibility (来源可信度)
           + 0.05 × diversity_bonus (端点多样性奖励)
"""

import math
from typing import Any

from .endpoint_explorer import PerEndpointContext

# 漏洞类型基础严重度 (越高越优先)
VULN_TYPE_SEVERITY: dict[str, float] = {
    "rce": 1.0,
    "sql_injection": 0.9,
    "ssrf": 0.85,
    "ssti": 0.8,
    "lfi": 0.7,
    "path_traversal": 0.7,
    "idor": 0.6,
    "xss": 0.5,
    "open_redirect": 0.4,
    "auth_bypass": 0.35,
    "info_disclosure": 0.3,
}


class EndpointSelector:
    """端点优先级排序器

    按多维评分对端点排序，替代 MCTS 的 select_batch。
    天然避免组合树的分支爆炸问题。
    """

    def __init__(self, focus_vuln_types: list[str] | None = None):
        self.focus_vuln_types = focus_vuln_types or []
        self.recently_selected: list[str] = []

    def _vuln_type_score(self, ctx: PerEndpointContext) -> float:
        """计算端点暗示的漏洞类型严重度得分"""
        if not ctx.path_hints:
            return 0.3  # 默认低优先级

        max_severity = 0.0
        for vt in ctx.path_hints:
            severity = VULN_TYPE_SEVERITY.get(vt, 0.3)
            # 焦点类型加成
            if vt in self.focus_vuln_types:
                severity += 0.35
            max_severity = max(max_severity, severity)
        return min(1.0, max_severity)

    def _accessibility_score(self, ctx: PerEndpointContext) -> float:
        """计算端点可达性得分"""
        status = ctx.baseline_status
        if status == 200:
            return 1.0
        elif status in (301, 302, 303, 307, 308):
            return 0.7
        elif status == 401:
            return 0.5
        elif status == 403:
            return 0.4
        elif status == 404:
            return 0.1
        elif status == 0:
            return 0.0  # 未探测
        return 0.3

    def _param_score(self, ctx: PerEndpointContext) -> float:
        """计算参数可用性得分"""
        total_params = len(ctx.known_params)
        unattempted = len(ctx.get_unattempted_params())
        if total_params == 0:
            return 0.2  # 无参数 → 低但非零 (可能有路径注入)
        return min(1.0, 0.3 + 0.7 * (unattempted / max(1, total_params)))

    def _source_score(self, ctx: PerEndpointContext) -> float:
        """计算来源可信度得分"""
        source_map = {
            "target_url": 1.0,    # 用户直接指定的目标
            "form": 0.8,           # 从 HTML 表单提取
            "crawl": 0.6,          # 从爬虫结果提取
            "url_inferred": 0.5,   # URL 语义推断
            "dir_scan": 0.3,       # 目录扫描发现
            "fallback": 0.2,       # 兜底创建
        }
        return source_map.get(ctx.source, 0.3)

    def _diversity_bonus(self, ctx: PerEndpointContext, selected: list[PerEndpointContext]) -> float:
        """多样性奖励 — 与已选端点路径差异越大奖励越高"""
        if not selected:
            return 1.0
        similarities = []
        for sel in selected:
            # 简单路径前缀相似度
            parts1 = ctx.endpoint_path.strip("/").split("/")
            parts2 = sel.endpoint_path.strip("/").split("/")
            common = sum(1 for a, b in zip(parts1, parts2) if a == b)
            sim = common / max(1, max(len(parts1), len(parts2)))
            similarities.append(sim)
        avg_sim = sum(similarities) / len(similarities)
        return 1.0 - avg_sim

    def rank(self, contexts: list[PerEndpointContext]) -> list[PerEndpointContext]:
        """对端点列表按优先级降序排列"""
        for ctx in contexts:
            ctx.priority_score = (
                0.40 * self._vuln_type_score(ctx)
                + 0.25 * self._accessibility_score(ctx)
                + 0.20 * self._param_score(ctx)
                + 0.10 * self._source_score(ctx)
            )
        contexts.sort(key=lambda c: c.priority_score, reverse=True)
        return contexts

    def select_top_k(
        self,
        contexts: list[PerEndpointContext],
        k: int = 4,
        include_diversity: bool = True,
    ) -> list[PerEndpointContext]:
        """选出 Top-K 个端点，可选多样性过滤"""
        ranked = self.rank(contexts)
        if not include_diversity or len(ranked) <= k:
            return ranked[:k]

        selected: list[PerEndpointContext] = [ranked[0]]
        for ctx in ranked[1:]:
            if len(selected) >= k:
                break
            bonus = self._diversity_bonus(ctx, selected)
            if bonus > 0.3:  # 路径差异度 > 30% 才纳入
                selected.append(ctx)

        # 如果多样性过滤后不足 k 个，按优先级补足
        if len(selected) < k:
            remaining = [c for c in ranked if c not in selected]
            selected.extend(remaining[:k - len(selected)])

        self.recently_selected = [c.endpoint_id for c in selected]
        return selected
