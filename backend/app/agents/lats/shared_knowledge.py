"""
跨分支共享知识库 (Shared Knowledge Base)

解决 v1 架构中每个 ReAct Agent 完全独立运行的问题。
所有分支的发现汇聚于此，供:
- ExpansionEngine: 更精准的扩展建议
- AdaptiveSelector: knowledge_score 因子
- Evaluate node: 覆盖率分析和终止决策

一次发现，全局受益。
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EndpointInfo:
    """端点信息记录"""
    path: str
    methods: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    requires_auth: bool = False
    response_status: int = 0
    response_length: int = 0
    content_type: str = ""
    discovery_source: str = ""
    last_probed_at: int = 0
    accessibility: str = "unknown"  # accessible | redirect | auth_required | not_found


@dataclass
class ParamInfo:
    """参数信息记录"""
    name: str
    found_on_endpoints: list[str] = field(default_factory=list)
    injection_context: str = "query"  # query | body | header | path
    reflected: bool = False
    filtered: bool = False
    vuln_signals: dict[str, dict] = field(default_factory=dict)


@dataclass
class VulnSignal:
    """漏洞信号记录"""
    endpoint: str
    param: str
    vuln_type: str
    signal_type: str = ""       # error_leaked | time_anomaly | reflected | status_anomaly
    confidence: float = 0.5
    evidence: str = ""
    source_step: int = 0
    source_node_id: str = ""


@dataclass
class SuccessfulRequestVector:
    """成功的请求向量记录 (v22: 跨Agent知识共享)

    记录任何产生响应差异的请求组合，供其他Agent学习。
    解决"Auth_bypass Agent发现POST有效但RCE Agent不知道"的问题。
    """
    endpoint: str
    method: str            # GET / POST / PUT
    param: str             # 产生响应的参数名
    payload_class: str     # 使用的payload类别 (rce/sqli/xss/...)
    content_type: str = "" # application/x-www-form-urlencoded
    form_fields: list = field(default_factory=list)  # 附加表单字段
    status_code: int = 0
    body_length: int = 0
    baseline_length: int = 0
    length_diff: int = 0
    evidence: str = ""
    timestamp: str = ""


class SharedKnowledge:
    """
    跨分支共享知识库

    记录所有分支探索中积累的信息，避免重复踩坑。
    线程安全: asyncio.Lock 保护写操作。
    """

    def __init__(self):
        self._lock = asyncio.Lock()

        # ── 端点信息 ──
        self.endpoints: dict[str, EndpointInfo] = {}

        # ── WAF 指纹与绕过 ──
        self.waf_profile: dict[str, Any] = {
            "detected": False,
            "vendor_hint": "",
            "filtered_chars": [],
            "allowed_chars": [],
            "blocked_payloads": [],
            "bypass_techniques": [],
            "rate_limiting": {"triggered": False, "threshold_estimate": 0},
        }

        # ── 有效参数 ──
        self.effective_params: dict[str, ParamInfo] = {}

        # ── 漏洞信号 ──
        self.vuln_signals: dict[str, list[VulnSignal]] = {}  # endpoint_path → signals

        # ── 技术栈 ──
        self.tech_stack: dict[str, Any] = {
            "confirmed": [],
            "suspected": [],
            "discovery_sources": {},
        }

        # ── 认证上下文 ──
        self.auth_contexts: list[dict[str, Any]] = []

        # ── v17: 漏洞类型失败追踪 ──
        self.vuln_type_failures: dict[str, int] = {}     # {"rce": 3, "sql_injection": 0}
        self.vuln_type_successes: dict[str, int] = {}    # 成功发现数

        # ── 探索历史 ──
        self.exploration_history: list[dict[str, Any]] = []

        # ── 最近变更追踪 (用于 Graveyard 复活) ──
        self._recent_changes: list[str] = []

        # ── v22: 成功请求向量 (跨Agent知识共享) ──
        self.successful_vectors: dict[str, list[SuccessfulRequestVector]] = {}  # endpoint → vectors

    # ──── 写入接口 ────

    async def record_endpoint(
        self,
        path: str,
        method: str = "GET",
        status: int = 0,
        content_length: int = 0,
        content_type: str = "",
        source: str = "react",
        requires_auth: bool = False,
    ) -> None:
        """记录端点信息"""
        async with self._lock:
            if path not in self.endpoints:
                self.endpoints[path] = EndpointInfo(
                    path=path,
                    discovery_source=source,
                )
                self._recent_changes.append("new_endpoint")

            ep = self.endpoints[path]
            if method not in ep.methods:
                ep.methods.append(method)
            if status:
                ep.response_status = status
            if content_length:
                ep.response_length = content_length
            if content_type:
                ep.content_type = content_type
            if requires_auth:
                ep.requires_auth = True
            if status in (401, 403):
                ep.accessibility = "auth_required"
            elif status == 200:
                ep.accessibility = "accessible"
            elif status in (301, 302):
                ep.accessibility = "redirect"
            elif status == 404:
                ep.accessibility = "not_found"

    async def record_waf_rule(
        self,
        filtered_char: str | None = None,
        allowed_char: str | None = None,
        bypass_technique: dict | None = None,
        vendor_hint: str = "",
    ) -> None:
        """记录 WAF 规则信息"""
        async with self._lock:
            if filtered_char and filtered_char not in self.waf_profile["filtered_chars"]:
                self.waf_profile["filtered_chars"].append(filtered_char)
                self.waf_profile["detected"] = True
                self._recent_changes.append("waf_rule")

            if allowed_char and allowed_char not in self.waf_profile["allowed_chars"]:
                self.waf_profile["allowed_chars"].append(allowed_char)

            if vendor_hint and not self.waf_profile["vendor_hint"]:
                self.waf_profile["vendor_hint"] = vendor_hint

            if bypass_technique:
                technique_name = bypass_technique.get("technique", "")
                existing = [t for t in self.waf_profile["bypass_techniques"]
                           if t.get("technique") == technique_name]
                if not existing:
                    self.waf_profile["bypass_techniques"].append(bypass_technique)
                    self._recent_changes.append("bypass_technique")

    async def record_vuln_signal(
        self,
        endpoint: str,
        param: str,
        vuln_type: str,
        signal_type: str,
        confidence: float = 0.5,
        evidence: str = "",
        source_step: int = 0,
        source_node_id: str = "",
    ) -> None:
        """记录漏洞信号"""
        async with self._lock:
            if endpoint not in self.vuln_signals:
                self.vuln_signals[endpoint] = []

            signal = VulnSignal(
                endpoint=endpoint,
                param=param,
                vuln_type=vuln_type,
                signal_type=signal_type,
                confidence=confidence,
                evidence=evidence,
                source_step=source_step,
                source_node_id=source_node_id,
            )

            # 去重: 同 endpoint+param+vuln_type+signal_type 只保留最新的
            existing = [s for s in self.vuln_signals[endpoint]
                       if s.param == param and s.vuln_type == vuln_type and s.signal_type == signal_type]
            if existing:
                # 更新现有信号
                existing[0].confidence = max(existing[0].confidence, confidence)
                existing[0].evidence = evidence
            else:
                self.vuln_signals[endpoint].append(signal)

            self._recent_changes.append("vuln_signal")

    async def record_param(
        self,
        param_name: str,
        endpoint: str,
        context: str = "query",
        reflected: bool = False,
        filtered: bool = False,
    ) -> None:
        """记录有效参数"""
        async with self._lock:
            if param_name not in self.effective_params:
                self.effective_params[param_name] = ParamInfo(
                    name=param_name,
                    injection_context=context,
                )
                self._recent_changes.append("new_param")

            pi = self.effective_params[param_name]
            if endpoint not in pi.found_on_endpoints:
                pi.found_on_endpoints.append(endpoint)
            pi.reflected = pi.reflected or reflected
            pi.filtered = pi.filtered or filtered

    async def record_tech_discovery(self, tech_name: str, source: str = "") -> None:
        """记录技术栈发现"""
        async with self._lock:
            if tech_name not in self.tech_stack["confirmed"]:
                self.tech_stack["confirmed"].append(tech_name)
                if source:
                    self.tech_stack["discovery_sources"][tech_name] = source
                self._recent_changes.append("tech_discovery")
                logger.info("SharedKnowledge: 技术栈发现 — %s (来源: %s)", tech_name, source)

    async def record_auth_context(self, context: dict[str, Any]) -> None:
        """记录认证上下文"""
        async with self._lock:
            self.auth_contexts.append(context)
            self._recent_changes.append("auth_context")

    async def record_vuln_type_failure(self, vuln_type: str) -> None:
        """v17: 记录漏洞类型失败 (exhaust 时调用)"""
        async with self._lock:
            self.vuln_type_failures[vuln_type] = self.vuln_type_failures.get(vuln_type, 0) + 1
            self._recent_changes.append("vuln_type_failure")

    async def record_vuln_type_success(self, vuln_type: str) -> None:
        """v17: 记录漏洞类型成功 (finding 时调用)"""
        async with self._lock:
            self.vuln_type_successes[vuln_type] = self.vuln_type_successes.get(vuln_type, 0) + 1

    def get_vuln_type_penalty(self, vuln_type: str) -> float:
        """v17: 获取漏洞类型惩罚权重 (失败越多, 惩罚越大)"""
        failures = self.vuln_type_failures.get(vuln_type, 0)
        if failures >= 5:
            return 0.3   # 5+ 失败 → 降低 30%
        elif failures >= 3:
            return 0.15  # 3-4 失败 → 降低 15%
        return 0.0

    async def record_exploration(
        self,
        node_id: str,
        vuln_type: str,
        endpoint: str,
        param: str | None,
        result: str,
        key_findings: list[str] | None = None,
    ) -> None:
        """记录探索结果"""
        async with self._lock:
            self.exploration_history.append({
                "node_id": node_id,
                "vuln_type": vuln_type,
                "endpoint": endpoint,
                "param": param,
                "result": result,
                "key_findings": key_findings or [],
            })
            # 保留最近 200 条
            if len(self.exploration_history) > 200:
                self.exploration_history = self.exploration_history[-200:]

    # ──── 读取接口 ────

    def get_recent_changes(self) -> list[str]:
        """获取最近的知识变更并清空"""
        changes = list(self._recent_changes)
        self._recent_changes = []
        return changes

    def get_bypass_techniques(self) -> list[dict]:
        """获取已验证的 WAF 绕过技术"""
        return [t for t in self.waf_profile["bypass_techniques"]
                if t.get("confirmed", False)]

    def get_effective_params(self) -> list[str]:
        """获取已确认有效的参数名列表"""
        return list(self.effective_params.keys())

    def get_high_signal_endpoints(self, min_confidence: float = 0.5) -> list[str]:
        """获取有高置信度漏洞信号的端点"""
        high_signal = set()
        for endpoint, signals in self.vuln_signals.items():
            for sig in signals:
                if sig.confidence >= min_confidence:
                    high_signal.add(endpoint)
        return list(high_signal)

    def get_unexplored_combinations(self, known_endpoints: list[str]) -> list[tuple]:
        """获取尚未探索的 (endpoint, param, vuln_type) 组合"""
        # 简单启发式: 返回知识库中有信号但未被完全探索的组合
        combinations = []
        for endpoint, signals in self.vuln_signals.items():
            if endpoint not in known_endpoints:
                for sig in signals:
                    combinations.append((endpoint, sig.param, sig.vuln_type))
        return combinations

    def is_waf_detected(self) -> bool:
        """是否检测到 WAF"""
        return bool(self.waf_profile.get("detected", False))

    def get_waf_vendor_hint(self) -> str:
        """获取 WAF 供应商提示"""
        return self.waf_profile.get("vendor_hint", "")

    def get_coverage_stats(self) -> dict:
        """获取探索覆盖率统计"""
        total_endpoints = len(self.endpoints)
        accessible = sum(1 for ep in self.endpoints.values()
                        if ep.accessibility == "accessible")
        auth_required = sum(1 for ep in self.endpoints.values()
                          if ep.accessibility == "auth_required")
        total_signals = sum(len(signals) for signals in self.vuln_signals.values())
        total_params = len(self.effective_params)

        return {
            "total_endpoints": total_endpoints,
            "accessible_endpoints": accessible,
            "auth_required_endpoints": auth_required,
            "total_vuln_signals": total_signals,
            "total_effective_params": total_params,
            "waf_detected": self.is_waf_detected(),
            "bypass_techniques_count": len(self.get_bypass_techniques()),
            "tech_stack_confirmed": self.tech_stack.get("confirmed", []),
        }

    def get_summary(self) -> dict:
        """获取知识库摘要 (供前端展示)"""
        return {
            "endpoints_discovered": len(self.endpoints),
            "waf_profile": {
                "detected": self.waf_profile["detected"],
                "vendor_hint": self.waf_profile["vendor_hint"],
                "filtered_chars_count": len(self.waf_profile["filtered_chars"]),
                "bypass_count": len(self.get_bypass_techniques()),
            },
            "effective_params_count": len(self.effective_params),
            "vuln_signal_count": sum(len(s) for s in self.vuln_signals.values()),
            "tech_stack": self.tech_stack.get("confirmed", []),
            "explorations_completed": len(self.exploration_history),
            "successful_vectors_count": sum(len(v) for v in self.successful_vectors.values()),
        }

    # ──── v22: 成功请求向量 (跨Agent知识共享) ────

    async def record_successful_vector(self, vector: SuccessfulRequestVector) -> None:
        """记录成功的请求向量，供其他 Agent 查询"""
        async with self._lock:
            ep_key = vector.endpoint
            if ep_key not in self.successful_vectors:
                self.successful_vectors[ep_key] = []
            # 去重：已有相同 (method, param, form_fields) 的向量则跳过
            for existing in self.successful_vectors[ep_key]:
                if (existing.method == vector.method
                        and existing.param == vector.param
                        and set(existing.form_fields) == set(vector.form_fields)):
                    # 更新差异（可能更大）
                    if vector.length_diff > existing.length_diff:
                        existing.length_diff = vector.length_diff
                        existing.evidence = vector.evidence
                    return
            self.successful_vectors[ep_key].append(vector)
            # 保留最近 20 个
            if len(self.successful_vectors[ep_key]) > 20:
                self.successful_vectors[ep_key] = self.successful_vectors[ep_key][-20:]
            self._recent_changes.append("successful_vector")

    def get_successful_vectors(self, endpoint: str) -> list[SuccessfulRequestVector]:
        """获取指定端点上所有 Agent 发现的有效请求向量"""
        return self.successful_vectors.get(endpoint, [])

    def get_best_vector(self, endpoint: str, vuln_type: str) -> SuccessfulRequestVector | None:
        """获取最适合指定漏洞类型的成功向量"""
        vectors = self.get_successful_vectors(endpoint)
        if not vectors:
            return None
        # 优先：payload_class 匹配的 + 最大差异
        matching = [v for v in vectors if v.payload_class == vuln_type]
        candidates = matching or vectors
        return max(candidates, key=lambda v: v.length_diff)

    def format_agent_hints(self, endpoint: str, max_hints: int = 3) -> str:
        """格式化跨Agent发现提示 (供Agent prompt注入)"""
        vectors = self.get_successful_vectors(endpoint)
        if not vectors:
            return ""
        hints = []
        for v in vectors[-max_hints:]:
            extra = ""
            if v.form_fields:
                extra = f"(含附加字段: {','.join(v.form_fields)})"
            hints.append(
                f"  {v.method} {v.param} {extra} → {v.length_diff}字节差异 ({v.evidence[:60]})"
            )
        if hints:
            return (
                "【跨Agent发现】同一端点上其他Agent成功触发了响应差异:\n"
                + "\n".join(hints)
                + "\n请优先使用上述参数/方法组合来测试你的payload。"
            )
        return ""
