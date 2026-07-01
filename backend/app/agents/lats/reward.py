"""
LATS 奖励函数

将 ReAct Agent 的观察结果转化为搜索信号。
不仅漏洞确认有奖励，中间线索也有正反馈，死路有负反馈。
这让 MCTS 能有效地将搜索预算分配到最有价值的方向。
"""

from typing import Any
from .actions import Observation


def compute_reward(observation: Observation) -> float:
    """
    即时奖励函数

    设计原则：
    - 确认漏洞 → 高正奖励 (按严重性分级)
    - 发现有价值线索 → 中正奖励 (鼓励继续)
    - 无信息增益 → 微负奖励 (鼓励换方向)
    - 明确死路 → 负奖励 (鼓励回溯)
    """
    reward = 0.0

    # 确认漏洞：最高奖励
    if observation.vuln_confirmed:
        severity_bonus = {
            "critical": 1.0,
            "high": 0.85,
            "medium": 0.6,
            "low": 0.4,
        }
        return severity_bonus.get(observation.severity, 0.5)

    # 发现有价值线索
    if observation.new_info_gained:
        reward += 0.15

    if observation.error_message_leaked:
        reward += 0.2

    if observation.response_time_anomaly:
        reward += 0.2

    if observation.status_code_anomaly:
        reward += 0.1

    # 发现过滤规则也是有价值信息（可用于构造绕过）
    if observation.filter_rules:
        reward += 0.1

    # 负信号
    if observation.waf_blocked:
        reward -= 0.1

    if observation.same_as_baseline:
        reward -= 0.05

    if observation.endpoint_404:
        reward -= 0.2

    if not observation.success:
        reward -= 0.15

    # 没有任何新信息的步骤给更强负奖励 (P1-4: 从 -0.03 提高到 -0.12)
    if not observation.new_info_gained and not observation.vuln_confirmed and observation.success:
        reward -= 0.12

    return max(-0.5, min(reward, 0.5))


def compute_trajectory_reward(steps: list[dict]) -> float:
    """
    计算整条轨迹的累积奖励

    带衰减：越早的步骤衰减越多，强调最终结果。
    """
    if not steps:
        return 0.0

    total = 0.0
    for i, step in enumerate(steps):
        step_reward = step.get("reward", 0.0)
        decay = 0.95 ** (len(steps) - 1 - i)
        total += step_reward * decay

    return total


def estimate_branch_value(
    vuln_type: str,
    param_name: str,
    endpoint: str,
    tech_stack: list[str] | None = None,
    source: str = "",
    focus_vuln_types: list[str] | None = None,
) -> float:
    """:deprecated: 使用 estimate_branch_value_v2 替代。保留用于向后兼容。"""
    """
    初始价值评估（先验）

    用于搜索树初始化时估计每个分支的价值。
    基于漏洞类型严重性、参数名暗示、端点来源等因素。
    """
    # 漏洞类型基础价值
    type_value = {
        "rce": 0.9,
        "sql_injection": 0.8,
        "ssrf": 0.75,
        "auth_bypass": 0.7,
        "lfi": 0.65,
        "path_traversal": 0.65,
        "ssti": 0.65,
        "idor": 0.6,
        "xss": 0.5,
        "open_redirect": 0.35,
        "info_disclosure": 0.3,
    }
    base = type_value.get(vuln_type, 0.4)

    # 参数名匹配度加成
    param_lower = (param_name or "").lower()
    param_vuln_affinity = {
        "rce": ["cmd", "exec", "command", "ping", "shell"],
        "sql_injection": ["id", "name", "username", "query", "search", "q", "sort", "order"],
        "ssrf": ["url", "link", "callback", "redirect", "fetch", "proxy", "dest"],
        "lfi": ["file", "path", "page", "include", "template", "doc", "load"],
        "path_traversal": ["file", "path", "dir", "folder", "download"],
        "ssti": ["template", "name", "message", "content", "text"],
        "xss": ["q", "search", "query", "name", "comment", "message", "input"],
        "idor": ["id", "uid", "user_id", "account", "profile", "order_id"],
        "open_redirect": ["url", "redirect", "next", "return", "goto", "callback"],
    }

    if vuln_type in param_vuln_affinity and param_lower in param_vuln_affinity[vuln_type]:
        base += 0.1

    # 来源加成
    source_bonus = {
        "form": 0.05,
        "crawl": 0.03,
        "dir_scan": 0.0,
        "target_url": 0.08,   # v18: URL query string 直接提取, 高置信度
        "url_inferred": 0.06,
    }
    base += source_bonus.get(source, 0.0)

    # v14: 任务目标对齐 — focus bonus +0.35
    if focus_vuln_types and vuln_type in focus_vuln_types:
        base += 0.35

    # 技术栈关联
    if tech_stack:
        tech_str = " ".join(tech_stack).lower()
        if vuln_type == "sql_injection" and ("php" in tech_str or "mysql" in tech_str):
            base += 0.05
        if vuln_type == "ssti" and ("jinja" in tech_str or "flask" in tech_str or "django" in tech_str):
            base += 0.08
        if vuln_type == "rce" and ("php" in tech_str or "java" in tech_str):
            base += 0.05

    return min(1.0, base)

def infer_vuln_types(
    param_name: str,
    endpoint: dict | str,
    tech_stack: list[str] | None = None,
    capability: Any = None,  # EndpointCapability | None
) -> list[str]:
    """
    基于参数名和端点特征推断可能的漏洞类型 (v2: 集成 EndpointCapability)。

    v2/L1-P1a: 参数名推断委托给 path_semantics.infer_vuln_from_param 单一真相源,
    消除 reward.py 与 graph.py 两份关键字字典不一致的问题。
    端点路径暗示仍由 path_semantics.infer_vuln_from_path 提供。

    当 capability 提供时，结果会被 capability.allowed_vuln_types 过滤。
    """
    from app.agents.lats.path_semantics import (
        infer_vuln_from_param, infer_vuln_from_path,
    )

    p = (param_name or "").lower()
    if isinstance(endpoint, str):
        path = endpoint.lower()
    else:
        path = (endpoint.get("path", "") or "").lower()

    # 参数名暗示 — 单一真相源
    types = infer_vuln_from_param(param_name)

    # 端点路径暗示
    if "admin" in path or "manage" in path:
        if "auth_bypass" not in types:
            types.append("auth_bypass")
    if "upload" in path:
        if "file_upload" not in types:
            types.append("file_upload")
    if "api" in path and not types:
        types.extend(["idor", "auth_bypass"])

    # 默认
    if not types:
        types = ["xss", "sql_injection"]

    # v2: 应用 EndpointCapability 过滤
    if capability is not None:
        from app.agents.lats.endpoint_capability import is_vuln_type_compatible
        types = [vt for vt in types if is_vuln_type_compatible(vt, capability)]

    # 去重
    return list(dict.fromkeys(types))
