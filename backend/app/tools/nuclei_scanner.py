"""
Nuclei 模板扫描工具模块

使用 Nuclei 漏洞扫描引擎的已知漏洞模板检测目标。
Nuclei 未安装时返回空结果和警告信息。
"""

import json
import logging
import time
from typing import Any

from .base import BaseTool, ExecutionContext, RiskLevel
from .sandbox import SandboxExecutor

logger = logging.getLogger(__name__)


class NucleiScannerTool(BaseTool):
    """
    Nuclei 模板扫描工具

    调用 Nuclei 引擎使用已知漏洞模板对目标进行扫描。
    风险等级 L1（主动探测，可能触发漏洞检测规则）。
    """

    name = "nuclei_scan"
    description = "Nuclei 模板扫描 - 使用已知漏洞模板检测目标"
    risk_level = RiskLevel.L1

    def __init__(self):
        self._sandbox = SandboxExecutor()

    def get_schema(self) -> dict:
        """返回 Nuclei 扫描工具的参数 JSON Schema"""
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "目标 URL 或主机地址",
                },
                "templates": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "指定模板 ID 或路径列表（为空时使用全部模板）",
                    "default": None,
                },
                "severity": {
                    "type": "string",
                    "description": "严重级别过滤（逗号分隔，如 medium,high,critical）",
                    "default": "medium,high,critical",
                },
                "timeout": {
                    "type": "integer",
                    "description": "超时时间（秒）",
                    "default": 120,
                },
            },
            "required": ["target"],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        """
        执行 Nuclei 模板扫描

        Args:
            params: {target, templates, severity, timeout}
            context: 执行上下文

        Returns:
            {
                success: bool,
                findings: list[{template_id, name, severity, matched_at, description}],
                count: int,
                scan_time_ms: int,
            }
        """
        target = params.get("target", "")
        templates = params.get("templates")
        severity = params.get("severity", "medium,high,critical")
        timeout = params.get("timeout", 120)

        # 参数校验
        if not target:
            return self._make_error_result("target 参数不能为空")

        # 目标白名单校验（如果是 URL 形式）
        if target.startswith(("http://", "https://")):
            if not self._validate_target(target, context):
                return self._make_error_result(
                    f"目标不在允许的主机白名单内: {target}"
                )

        start_time = time.monotonic()

        # 构建 nuclei 命令
        cmd = ["nuclei", "-u", target, "-jsonl", "-silent"]

        # 添加严重级别过滤
        if severity:
            cmd.extend(["-severity", severity])

        # 添加指定模板
        if templates:
            for template in templates:
                cmd.extend(["-t", template])

        # 执行 nuclei
        result = await self._sandbox.execute_command(cmd, timeout=timeout)
        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        # nuclei 未安装
        if not result["success"] and "命令未找到" in result.get("stderr", ""):
            logger.warning("nuclei 未安装，无法执行扫描")
            return {
                "success": True,
                "findings": [],
                "count": 0,
                "scan_time_ms": elapsed_ms,
                "warning": "nuclei 未安装，请先安装: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            }

        # 解析 JSONL 输出
        findings = self._parse_nuclei_output(result.get("stdout", ""))

        return {
            "success": True,
            "findings": findings,
            "count": len(findings),
            "scan_time_ms": elapsed_ms,
        }

    @staticmethod
    def _parse_nuclei_output(output: str) -> list[dict]:
        """
        解析 Nuclei JSONL 格式输出

        Args:
            output: nuclei -jsonl 的标准输出

        Returns:
            漏洞发现列表
        """
        findings = []
        if not output or not output.strip():
            return findings

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                finding = {
                    "template_id": data.get("template-id", data.get("templateID", "")),
                    "name": data.get("info", {}).get("name", ""),
                    "severity": data.get("info", {}).get("severity", "unknown"),
                    "matched_at": data.get("matched-at", data.get("matched", "")),
                    "description": data.get("info", {}).get("description", ""),
                }
                findings.append(finding)
            except json.JSONDecodeError:
                logger.warning("Nuclei 输出行解析失败: %s", line[:200])
                continue

        return findings
