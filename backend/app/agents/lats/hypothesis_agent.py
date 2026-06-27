"""
假设驱动探索代理 (v21 — HDE 架构 Phase 3)

替代 ReAct Agent 的盲目试错循环。
HypothesisAgent 基于端点上下文和 DiagnosticProber 的反馈形成、
测试和修正漏洞假设，形成"假设→探测→诊断→修正"的闭环。
"""

import logging
from typing import Any

from app.agents.llm import LLMClient
from app.tools.base import ExecutionContext

from .actions import Observation
from .diagnostic_prober import DiagnosticProber, DiagResult

logger = logging.getLogger(__name__)

# 假设修正策略映射: 诊断结果 → 下一步行动
DIAG_ACTION_MAP: dict[str, str] = {
    "filtered_bypassable": "尝试编码绕过 (URL编码/双编码/Unicode)",
    "filtered_hard": "尝试不同分隔符 (反引号/命令替换/换行符)",
    "wrong_param": "切换到其他已知参数",
    "wrong_method": "改用 POST 方法提交",
    "blind_exec": "切换到盲检测模式 (时间盲注/布尔盲注)",
    "no_vuln": "降低此假设优先级, 尝试下一个假设",
}


class HypothesisAgent:
    """假设驱动探索代理

    职责:
    1. 基于 PerEndpointContext 形成初始假设
    2. 执行探测 payload
    3. 接收 DiagnosticProber 反馈修正假设
    4. 循环直到假设确认或否定
    """

    def __init__(self, llm: LLMClient):
        self.llm = llm
        self.diagnostic_prober = DiagnosticProber()
        self.max_hypotheses_per_endpoint = 4

    def form_initial_hypothesis(
        self,
        endpoint_path: str,
        path_hints: list[str],
        known_params: list[str],
        baseline_status: int,
    ) -> dict:
        """基于端点特征形成初始假设

        Args:
            endpoint_path: 端点路径
            path_hints: URL路径暗示的漏洞类型
            known_params: 已知参数名
            baseline_status: 基线响应状态码

        Returns:
            {"vuln_type": str, "param": str | None, "confidence": float,
             "reasoning": str, "suggested_actions": [str]}
        """
        # 优先级: path_hints > 参数名暗示 > 通用探测
        vuln_type = path_hints[0] if path_hints else "info_disclosure"

        # 选择最相关的参数
        param = None
        param_vuln_map = {
            "rce": ["cmd", "exec", "command", "ping", "ipaddress"],
            "sql_injection": ["id", "q", "query", "search", "name", "username"],
            "xss": ["q", "search", "name", "message", "comment"],
            "lfi": ["file", "path", "page", "include", "template"],
            "ssrf": ["url", "link", "callback", "redirect", "fetch"],
            "idor": ["id", "uid", "user_id", "account"],
            "auth_bypass": [],  # 无参探测
        }
        preferred = param_vuln_map.get(vuln_type, [])
        for p in preferred:
            if p in known_params:
                param = p
                break
        if not param and known_params:
            param = known_params[0]

        confidence = 0.6 if vuln_type in path_hints else 0.3
        if param:
            confidence += 0.1

        return {
            "vuln_type": vuln_type,
            "param": param,
            "confidence": confidence,
            "reasoning": f"路径暗示 {vuln_type}, 参数 {param or '无'}",
            "suggested_actions": ["batch_inject"] if param else ["discover_params"],
        }

    def adjust_hypothesis(
        self,
        current_hypothesis: dict,
        diag_result: str,
        known_params: list[str],
        tried_params: list[str],
    ) -> dict | None:
        """基于诊断结果修正假设

        Args:
            current_hypothesis: 当前假设
            diag_result: DiagnosticProber 返回的分类
            known_params: 已知参数列表
            tried_params: 已尝试的参数列表

        Returns:
            修正后的假设, 或 None (放弃此方向)
        """
        action = DIAG_ACTION_MAP.get(diag_result, "尝试其他方法")

        if diag_result == DiagResult.WRONG_PARAM.value:
            # 尝试其他参数
            unattempted = [p for p in known_params if p not in tried_params]
            if unattempted:
                current_hypothesis["param"] = unattempted[0]
                current_hypothesis["confidence"] -= 0.1
                current_hypothesis["reasoning"] = f"切换到参数 {unattempted[0]}"
                return current_hypothesis

        elif diag_result == DiagResult.WRONG_METHOD.value:
            # 保持参数, 切换方法
            current_hypothesis["confidence"] -= 0.05
            current_hypothesis["reasoning"] = "切换到 POST 方法"
            return current_hypothesis

        elif diag_result == DiagResult.BLIND_EXEC.value:
            # 命令执行但无回显 → 时间盲注
            current_hypothesis["confidence"] = 0.8
            current_hypothesis["reasoning"] = "命令执行但无回显, 切换时间盲注"
            current_hypothesis["suggested_actions"] = ["inject_payload"]
            return current_hypothesis

        elif diag_result == DiagResult.FILTERED_BYPASSABLE.value:
            # 过滤可绕过
            current_hypothesis["confidence"] -= 0.05
            current_hypothesis["reasoning"] = "过滤可绕过, 尝试编码payload"
            return current_hypothesis

        elif diag_result == DiagResult.NO_VULN.value:
            # 降低置信度, 如果还高就再试一次
            current_hypothesis["confidence"] -= 0.3
            if current_hypothesis["confidence"] <= 0.1:
                return None  # 放弃
            return current_hypothesis

        # 默认: 降低置信度但继续
        current_hypothesis["confidence"] -= 0.1
        if current_hypothesis["confidence"] <= 0.1:
            return None
        return current_hypothesis

    def get_exploration_summary(
        self,
        endpoint_path: str,
        hypotheses: list[dict],
        diagnostic_history: list[str],
    ) -> str:
        """生成探索摘要 (供 LLM 使用)"""
        lines = [f"端点: {endpoint_path}"]
        for i, h in enumerate(hypotheses[-3:]):
            lines.append(
                f"  假设{i+1}: {h.get('vuln_type','')} param={h.get('param','')} "
                f"confidence={h.get('confidence',0):.2f}"
            )
        if diagnostic_history:
            lines.append(f"  诊断历史: {diagnostic_history[-3:]}")
        return "\n".join(lines)
