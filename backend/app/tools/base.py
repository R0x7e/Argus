"""
工具基础设施模块

定义工具风险等级、执行上下文、工具基类和工具注册中心。
所有漏洞挖掘工具均继承 BaseTool 并通过 ToolRegistry 注册。
"""

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class RiskLevel(IntEnum):
    """
    工具风险等级

    L0: 只读、被动扫描（如 HTTP 请求、子域名枚举）
    L1: 主动探测、有限写（如 SQL 注入检测、SSRF 检测）
    L2: 真实漏洞利用（如漏洞验证、PoC 执行）
    L3: 高危破坏性操作（如远程代码执行、数据修改）
    """

    L0 = 0  # 只读、被动扫描
    L1 = 1  # 主动探测、有限写
    L2 = 2  # 真实漏洞利用
    L3 = 3  # 高危破坏性操作


@dataclass
class ExecutionContext:
    """
    工具执行上下文

    携带任务信息、目标主机、超时配置和授权白名单等运行时参数。
    每次工具调用都需要传入上下文以确保安全约束。
    """

    task_id: str                                    # 关联任务 ID
    target_host: str                                # 主要目标主机
    timeout: int = 30                               # 默认超时秒数
    max_retries: int = 2                            # 最大重试次数
    allowed_hosts: list[str] = field(default_factory=list)  # 允许访问的主机白名单


class BaseTool:
    """
    工具基类

    所有漏洞挖掘工具必须继承此类并实现 execute() 和 get_schema() 方法。
    基类提供目标验证、错误处理等通用能力。
    """

    name: str = ""                     # 工具名称（唯一标识）
    description: str = ""              # 工具描述（供 LLM 理解工具用途）
    risk_level: RiskLevel = RiskLevel.L0  # 工具风险等级

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        """
        执行工具，子类必须实现此方法

        Args:
            params: 工具参数字典
            context: 执行上下文

        Returns:
            包含执行结果的字典
        """
        raise NotImplementedError("子类必须实现 execute 方法")

    def get_schema(self) -> dict:
        """
        返回 JSON Schema 供 LLM 调用

        Returns:
            符合 JSON Schema 规范的参数描述字典
        """
        raise NotImplementedError("子类必须实现 get_schema 方法")

    def _validate_target(self, url: str, context: ExecutionContext) -> bool:
        """
        验证目标 URL 是否在白名单内

        当 context.allowed_hosts 非空时，只允许访问白名单中的主机。
        白名单为空时默认允许所有目标。

        Args:
            url: 待验证的目标 URL
            context: 执行上下文（包含白名单）

        Returns:
            True 表示目标合法，False 表示目标被禁止
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False
            if context.allowed_hosts and hostname not in context.allowed_hosts:
                logger.warning(
                    "目标主机 %s 不在白名单内，已拒绝访问 (task_id=%s)",
                    hostname,
                    context.task_id,
                )
                return False
            return True
        except Exception:
            return False

    def _make_error_result(self, error_msg: str) -> dict:
        """
        生成标准错误结果字典

        Args:
            error_msg: 错误描述信息

        Returns:
            包含 error 和 success 字段的结果字典
        """
        return {"success": False, "error": error_msg}


class ToolRegistry:
    """
    工具注册中心

    管理所有可用工具的注册、查询和转换。
    支持按风险等级过滤和转换为 LangChain StructuredTool 格式。
    """

    def __init__(self):
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """
        注册一个工具

        Args:
            tool: 工具实例（必须有唯一的 name）

        Raises:
            ValueError: 工具名称为空或已被注册
        """
        if not tool.name:
            raise ValueError("工具名称不能为空")
        if tool.name in self._tools:
            raise ValueError(f"工具 '{tool.name}' 已被注册")
        self._tools[tool.name] = tool
        logger.info("已注册工具: %s (风险等级: L%d)", tool.name, tool.risk_level)

    def get(self, name: str) -> BaseTool:
        """
        按名称获取工具

        Args:
            name: 工具名称

        Returns:
            对应的工具实例

        Raises:
            KeyError: 工具未注册
        """
        if name not in self._tools:
            raise KeyError(f"工具 '{name}' 未注册")
        return self._tools[name]

    def list_tools(self, max_risk: RiskLevel = RiskLevel.L3) -> list[BaseTool]:
        """
        列出所有风险等级不超过指定级别的工具

        Args:
            max_risk: 最大允许风险等级（默认 L3，即全部）

        Returns:
            符合风险约束的工具列表
        """
        return [
            tool for tool in self._tools.values()
            if tool.risk_level <= max_risk
        ]

    def get_langchain_tools(self, context: ExecutionContext) -> list:
        """
        转换为 LangChain StructuredTool 列表

        将所有已注册工具包装成 LangChain 兼容的 StructuredTool，
        使 LLM Agent 可以直接调用。

        Args:
            context: 执行上下文（绑定到每个工具的调用闭包中）

        Returns:
            LangChain StructuredTool 实例列表
        """
        try:
            from langchain_core.tools import StructuredTool
        except ImportError:
            logger.error("langchain_core 未安装，无法生成 LangChain 工具列表")
            return []

        langchain_tools = []
        for tool in self._tools.values():
            # 为每个工具创建绑定上下文的异步调用函数
            async def _make_func(t=tool, ctx=context):
                async def _invoke(**kwargs) -> dict:
                    return await t.execute(kwargs, ctx)
                return _invoke

            import asyncio

            async def _bound_invoke(_tool=tool, _ctx=context, **kwargs) -> dict:
                """绑定上下文的工具调用函数"""
                return await _tool.execute(kwargs, _ctx)

            lc_tool = StructuredTool.from_function(
                coroutine=_bound_invoke,
                name=tool.name,
                description=tool.description,
                args_schema=None,  # 使用工具自身的 schema 描述
            )
            langchain_tools.append(lc_tool)

        return langchain_tools
