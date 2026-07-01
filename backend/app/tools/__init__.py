"""
Argus 工具层 - 漏洞挖掘工具集

提供漏洞发现和验证所需的全部工具，包括：
- HTTP 请求、子域名枚举、端口扫描、目录扫描（被动侦察）
- Nuclei 模板扫描、SQL 注入检测、SSRF 检测、越权检测（主动探测）
- Payload 变异器（辅助工具）
- 沙箱执行器（基础设施）

所有工具通过 tool_registry（ToolRegistry 实例）统一注册和管理。
"""

import logging

from .base import BaseTool, ExecutionContext, RiskLevel, ToolRegistry
from .sandbox import SandboxExecutor

# 导入所有工具类
from .http_requester import HTTPRequesterTool
from .subdomain_enum import SubdomainEnumTool
from .port_scanner import PortScannerTool
from .dir_scanner import DirScannerTool
from .nuclei_scanner import NucleiScannerTool
from .payload_mutator import PayloadMutatorTool
from .sql_injection import SQLInjectionTool
from .ssrf_detector import SSRFDetectorTool
from .auth_tester import AuthTesterTool
from .browser_request import BrowserRequestTool
from .browser_interact import BrowserInteractTool
from .proxy_flows import ProxyFlowsTool
from .deep_crawl import DeepCrawlTool
from .run_poc import RunPocTool
from .katana_crawler import KatanaCrawlerTool

logger = logging.getLogger(__name__)

# 全局工具注册中心实例
tool_registry = ToolRegistry()


def _register_all_tools() -> None:
    """注册所有内置工具到全局注册中心"""
    tools = [
        HTTPRequesterTool(),      # L0: HTTP 请求
        SubdomainEnumTool(),      # L0: 子域名枚举
        PortScannerTool(),        # L0: 端口扫描
        DirScannerTool(),         # L0: 目录扫描
        PayloadMutatorTool(),     # L0: Payload 变异器
        NucleiScannerTool(),      # L1: Nuclei 模板扫描
        SQLInjectionTool(),       # L1: SQL 注入检测
        SSRFDetectorTool(),       # L1: SSRF 检测
        AuthTesterTool(),         # L1: 越权检测
        BrowserRequestTool(),    # L1: 浏览器渲染
        BrowserInteractTool(),   # L2: 浏览器交互
        ProxyFlowsTool(),        # L0: 代理流量查询
        DeepCrawlTool(),         # L0: 深度爬虫
        KatanaCrawlerTool(),     # L0: Katana 端点头less爬虫
        RunPocTool(),            # L2: PoC 沙箱执行
    ]

    for tool in tools:
        try:
            tool_registry.register(tool)
        except ValueError as e:
            logger.warning("工具注册失败: %s", str(e))


# 模块加载时自动注册所有工具
_register_all_tools()

# 公开导出
__all__ = [
    # 基础设施
    "BaseTool",
    "ExecutionContext",
    "RiskLevel",
    "ToolRegistry",
    "SandboxExecutor",
    # 工具类
    "HTTPRequesterTool",
    "SubdomainEnumTool",
    "PortScannerTool",
    "DirScannerTool",
    "NucleiScannerTool",
    "PayloadMutatorTool",
    "SQLInjectionTool",
    "SSRFDetectorTool",
    "AuthTesterTool",
    "BrowserRequestTool",
    "BrowserInteractTool",
    "ProxyFlowsTool",
    "DeepCrawlTool",
    "RunPocTool",
    # 全局注册中心
    "tool_registry",
]
