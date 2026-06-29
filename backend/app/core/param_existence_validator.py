"""
参数存在性预验证器 (v3)

在 MultiLevelProber Level 0 之前，验证猜测的参数名是否被后端实际处理。
使用零LLM调用的纯HTTP探测。

解决根本问题: MultiLevelProber 将错误参数(cmd)的错误结果误判为LOW_SIGNAL
"""
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ExistenceResult:
    """参数存在性验证结果"""
    param_name: str
    exists: bool
    confidence: float          # 0.0-1.0
    evidence: str = ""         # 判断依据
    recommended_alternatives: list[str] = field(default_factory=list)
    response_diffs: list[dict] = field(default_factory=list)


class ParamExistenceValidator:
    """
    参数存在性预验证器

    三步验证:
    1. 空值 vs 随机垃圾值 → 观察响应差异
    2. 极端长值 vs 正常值 → 观察截断/错误
    3. 如果参数可能不存在，从响应中提取暗示

    验证规则:
    - 任何响应差异(length/status/time/body_pattern) → exists=true
    - 如果3步全部无差异:
        → exists=false, 尝试从页面HTML中建议替代参数名
    """

    # 验证用的随机垃圾值(低碰撞概率)
    TRASH_VALUE = "z9x8c7v6b5_ARGUS_PROBE_n4m3t2w1q0"

    # 用于检测"参数存在但被忽略"的错误模式
    PARAM_EXISTS_INDICATORS = [
        r"invalid.*" + "param",
        r"unknown.*" + "param",
        r"missing.*" + "param",
        r"required.*" + "param",
        r"bad.*" + "param",
    ]

    def __init__(self, timeout: int = 10):
        self._timeout = timeout

    async def validate(
        self,
        url: str,
        param_name: str,
        method: str = "GET",
        base_response: dict | None = None,
        html: str = "",
        headers: dict[str, str] | None = None,
        context: Any = None,
    ) -> ExistenceResult:
        """
        验证参数是否存在。

        Args:
            url: 端点URL
            param_name: 待验证的参数名
            method: HTTP方法
            base_response: 基线响应 (可选, 如不提供则发送空参数)
            html: 页面HTML (用于提取替代参数建议)
            headers: 请求头
            context: 执行上下文

        Returns:
            ExistenceResult
        """
        import httpx
        import hashlib
        import time

        # 1. 发送空值请求(基线)
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                if base_response is None:
                    if method.upper() == "POST":
                        resp_base = await client.post(url, data={param_name: ""}, headers=headers or {})
                    else:
                        resp_base = await client.get(url, params={param_name: ""}, headers=headers or {})
                    base_status = resp_base.status_code
                    base_len = len(resp_base.text)
                    base_time = resp_base.elapsed.total_seconds() * 1000
                    base_body = resp_base.text
                else:
                    base_status = base_response.get("status", 200)
                    base_len = base_response.get("len", 0)
                    base_time = base_response.get("time_ms", 0)
                    base_body = base_response.get("body", "")
        except Exception as e:
            return ExistenceResult(
                param_name=param_name,
                exists=False,
                confidence=0.0,
                evidence=f"连接失败: {e}",
            )

        diffs = []

        # 2. 发送随机垃圾值
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                if method.upper() == "POST":
                    resp_trash = await client.post(url, data={param_name: self.TRASH_VALUE}, headers=headers or {})
                else:
                    resp_trash = await client.get(url, params={param_name: self.TRASH_VALUE}, headers=headers or {})

                trash_status = resp_trash.status_code
                trash_len = len(resp_trash.text)
                trash_time = resp_trash.elapsed.total_seconds() * 1000
                trash_body = resp_trash.text

                diff_trash = {
                    "status_diff": trash_status != base_status,
                    "len_diff": abs(trash_len - base_len),
                    "time_diff_ms": abs(trash_time - base_time),
                }
                diffs.append(diff_trash)

                # 状态码差异 → 参数存在
                if trash_status != base_status:
                    return ExistenceResult(
                        param_name=param_name, exists=True, confidence=0.9,
                        evidence=f"状态码差异: {base_status}→{trash_status}",
                        response_diffs=diffs,
                    )

                # 长度显著差异 (>2% 或 >50字节)
                if base_len > 0 and abs(trash_len - base_len) > max(50, base_len * 0.02):
                    return ExistenceResult(
                        param_name=param_name, exists=True, confidence=0.8,
                        evidence=f"响应长度差异: {base_len}→{trash_len}",
                        response_diffs=diffs,
                    )

                # 时间显著差异 (>500ms)
                if abs(trash_time - base_time) > 500:
                    return ExistenceResult(
                        param_name=param_name, exists=True, confidence=0.7,
                        evidence=f"响应时间差异: {base_time:.0f}→{trash_time:.0f}ms",
                        response_diffs=diffs,
                    )

                # 响应体包含参数相关错误 → 参数存在但因值无效而报错
                for indicator in self.PARAM_EXISTS_INDICATORS:
                    if re.search(indicator.replace("param", param_name), trash_body, re.IGNORECASE):
                        return ExistenceResult(
                            param_name=param_name, exists=True, confidence=0.7,
                            evidence=f"错误响应提及参数 {param_name}",
                            response_diffs=diffs,
                        )

        except Exception:
            pass

        # 3. 发送极端长值 (检测截断)
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                long_value = "A" * 5000
                if method.upper() == "POST":
                    resp_long = await client.post(url, data={param_name: long_value}, headers=headers or {})
                else:
                    resp_long = await client.get(url, params={param_name: long_value}, headers=headers or {})

                long_len = len(resp_long.text)
                diff_long = {
                    "status_diff": resp_long.status_code != base_status,
                    "len_diff": abs(long_len - base_len),
                }
                diffs.append(diff_long)

                if abs(long_len - base_len) > max(50, base_len * 0.02):
                    return ExistenceResult(
                        param_name=param_name, exists=True, confidence=0.6,
                        evidence=f"长值→长度变化: {base_len}→{long_len}",
                        response_diffs=diffs,
                    )

        except Exception:
            pass

        # 4. 参数不存在 → 尝试从HTML中建议替代参数名
        alternatives = []
        if html:
            alternatives = self._suggest_from_html(html, param_name)

        return ExistenceResult(
            param_name=param_name,
            exists=False,
            confidence=0.85,
            evidence="3步验证均无差异 → 参数不存在",
            recommended_alternatives=alternatives,
            response_diffs=diffs,
        )

    def _suggest_from_html(self, html: str, failed_param: str) -> list[str]:
        """
        从HTML中提取可能的替代参数名。
        当参数被判定为不存在时，给出实际页面中存在的参数名。
        """
        suggestions = set()
        # 提取所有input/select/textarea的name
        for m in re.finditer(
            r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\']',
            html, re.IGNORECASE,
        ):
            name = m.group(1)
            if name and name != failed_param:
                suggestions.add(name)

        # 提取URL query参数
        for m in re.finditer(r'[?&]([^=&]+)=', html):
            suggestions.add(m.group(1))

        return sorted(suggestions)[:10]
