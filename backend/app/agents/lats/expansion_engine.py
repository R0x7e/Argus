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
    new_endpoint_per_cycle: int = 3       # 每周期最多基于新端点创建 3 个分支
    new_endpoint_total: int = 20          # 累计不超过 20 个
    new_param_per_endpoint: int = 5       # 每端点最多 5 个参数节点
    waf_bypass_assoc_nodes: int = 5       # 每种 bypass 技术最多关联 5 个节点
    tech_discovery_new_types: int = 3     # 每种技术栈最多触发 3 个新 vuln_type
    auth_context_endpoints: int = 10      # 每个新认证上下文最多测试 10 个端点
    vuln_type_clue_per_signal: int = 1    # 每个漏洞信号最多创建 1 个新子节点
    llm_suggestion_per_cycle: int = 2     # 每周期最多采纳 2 个 LLM 建议
    global_max_nodes: int = 200           # 全局节点上限

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
        """检查是否还有该类发现的创建配额"""
        # 全局上限
        if len(search_tree.nodes) >= self.global_max_nodes:
            return False

        extra = extra or {}

        if discovery_type == DiscoveryType.NEW_ENDPOINT:
            return (self.cycle_new_endpoints < self.new_endpoint_per_cycle and
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
        finding = getattr(result, 'finding', None) or {}
        if finding:
            url = finding.get('url', '') or finding.get('evidence', {}).get('url', '')
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
            if any(kw in fact_lower for kw in ("发现", "found", "端点", "endpoint", "链接", "link", "url", "api")):
                discoveries.append(Discovery(
                    discovery_type=DiscoveryType.NEW_ENDPOINT,
                    source_node_id=node.id,
                    source_cycle=cycle,
                    data={"url": fact[:200], "source": "new_facts"},
                    confidence=0.4,
                ))
            if any(kw in fact_lower for kw in ("参数", "param", "注入点", "injection")):
                discoveries.append(Discovery(
                    discovery_type=DiscoveryType.NEW_PARAM,
                    source_node_id=node.id,
                    source_cycle=cycle,
                    data={"param_name": fact[:200], "endpoint": node.state.current_endpoint},
                    confidence=0.4,
                ))

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

    def expand(
        self,
        tree: SearchTree,
        discoveries: list[Discovery],
        current_cycle: int,
        base_url: str = "",
        knowledge: Any = None,  # Phase 2: SharedKnowledge
    ) -> dict:
        """
        基于发现执行动态扩展

        Args:
            tree: 搜索树
            discoveries: 本轮所有发现
            current_cycle: 当前周期
            base_url: 目标基础 URL
            knowledge: SharedKnowledge 引用 (Phase 2)

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
            if not self.quotas.can_create(discovery.discovery_type, tree):
                continue

            created_nodes = self._create_branches_for_discovery(
                tree, root, discovery, current_cycle, base_url
            )

            if created_nodes:
                self.quotas.record_creation(discovery.discovery_type,
                                            self._get_quota_extra(discovery))
                new_branches += len(created_nodes)
                type_key = discovery.discovery_type.value
                by_type[type_key] = by_type.get(type_key, 0) + len(created_nodes)

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

    def _create_branches_for_discovery(
        self,
        tree: SearchTree,
        parent: SearchNode,
        discovery: Discovery,
        cycle: int,
        base_url: str,
    ) -> list[SearchNode]:
        """为单个发现创建搜索分支"""
        created = []

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
        endpoint = discovery.data.get("endpoint", "") or discovery.source_node_id

        if not param_name:
            return created

        from .reward import infer_vuln_types

        # v5: 独立推断, 不继承父节点的 auth_bypass
        vuln_types = infer_vuln_types(param_name, endpoint=endpoint)
        # v5: 如果没有推断出类型, 默认使用 sql_injection + xss + idor
        if not vuln_types or vuln_types == ["xss", "sql_injection"]:
            vuln_types = ["sql_injection", "xss", "idor", "auth_bypass"]

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
        """从发现中提取配额追踪所需的额外信息"""
        return {
            "endpoint": discovery.data.get("endpoint", discovery.data.get("url", "")),
            "technique": discovery.data.get("technique", discovery.data.get("filter_rules", {}).get("bypass", "unknown")),
            "tech_name": discovery.data.get("tech_name", "unknown"),
        }

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
