"""
子域名枚举工具模块

发现目标域名的子域名，支持 subfinder 外部工具和内置 DNS 查询两种模式。
当 subfinder 不可用时自动回退到内置常见子域名字典探测。
"""

import asyncio
import logging
import socket
import time
from typing import Any

from .base import BaseTool, ExecutionContext, RiskLevel
from .sandbox import SandboxExecutor

logger = logging.getLogger(__name__)

# 常见子域名字典（内置回退方案使用）
DEFAULT_SUBDOMAIN_WORDLIST = [
    "admin", "api", "app", "auth", "beta", "blog", "cdn",
    "cms", "dashboard", "db", "demo", "dev", "docs", "email",
    "ftp", "git", "gitlab", "grafana", "help", "internal",
    "jenkins", "jira", "kibana", "login", "mail", "manage",
    "monitor", "mysql", "ns1", "ns2", "portal", "redis",
    "register", "remote", "shop", "smtp", "staging", "static",
    "status", "store", "test", "vpn", "wiki", "www",
]


class SubdomainEnumTool(BaseTool):
    """
    子域名枚举工具

    通过外部工具（subfinder）或内置 DNS 查询发现目标域名的子域名。
    风险等级 L0（只读、被动扫描）。
    """

    name = "subdomain_enum"
    description = "子域名枚举 - 发现目标域名的子域名"
    risk_level = RiskLevel.L0

    def __init__(self):
        self._sandbox = SandboxExecutor()

    def get_schema(self) -> dict:
        """返回子域名枚举工具的参数 JSON Schema"""
        return {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "目标域名（如 example.com）",
                },
                "timeout": {
                    "type": "integer",
                    "description": "超时时间（秒）",
                    "default": 60,
                },
            },
            "required": ["domain"],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        """
        执行子域名枚举

        优先尝试 subfinder，失败则回退到内置 DNS 查询。

        Args:
            params: {domain: str, timeout: int}
            context: 执行上下文

        Returns:
            {
                success: bool,
                subdomains: list[str],
                count: int,
                source: "subfinder" | "builtin",
            }
        """
        domain = params.get("domain", "")
        timeout = params.get("timeout", 60)

        # 参数校验
        if not domain:
            return self._make_error_result("domain 参数不能为空")

        # IP 地址不适用子域名枚举，直接返回空结果
        if self._is_ip_address(domain):
            return {
                "success": True,
                "subdomains": [],
                "count": 0,
                "source": "skipped",
                "scan_time_ms": 0,
            }

        # 域名基本格式校验
        if not self._is_valid_domain(domain):
            return self._make_error_result(f"无效的域名格式: {domain}")

        start_time = time.monotonic()

        # 尝试使用 subfinder
        subfinder_result = await self._try_subfinder(domain, timeout)
        if subfinder_result is not None:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            return {
                "success": True,
                "subdomains": subfinder_result,
                "count": len(subfinder_result),
                "source": "subfinder",
                "scan_time_ms": elapsed_ms,
            }

        # 回退到内置 DNS 查询
        logger.info("subfinder 不可用，使用内置 DNS 查询枚举子域名: %s", domain)
        builtin_result = await self._builtin_enum(domain, timeout)
        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        return {
            "success": True,
            "subdomains": builtin_result,
            "count": len(builtin_result),
            "source": "builtin",
            "scan_time_ms": elapsed_ms,
        }

    async def _try_subfinder(self, domain: str, timeout: int) -> list[str] | None:
        """
        尝试使用 subfinder 进行子域名枚举

        Args:
            domain: 目标域名
            timeout: 超时秒数

        Returns:
            子域名列表，如果 subfinder 不可用则返回 None
        """
        try:
            result = await self._sandbox.execute_command(
                ["subfinder", "-d", domain, "-silent"],
                timeout=timeout,
            )

            if not result["success"]:
                # subfinder 未安装或执行失败
                return None

            # 解析 subfinder 输出（每行一个子域名）
            subdomains = [
                line.strip()
                for line in result["stdout"].strip().split("\n")
                if line.strip()
            ]
            return sorted(set(subdomains))

        except Exception as e:
            logger.warning("subfinder 执行异常: %s", str(e))
            return None

    async def _builtin_enum(self, domain: str, timeout: int) -> list[str]:
        """
        内置 DNS 查询枚举子域名

        使用常见子域名字典逐一进行 DNS 解析，发现存在的子域名。

        Args:
            domain: 目标域名
            timeout: 超时秒数

        Returns:
            发现的子域名列表
        """
        found = []

        async def _check_subdomain(subdomain: str) -> str | None:
            """检查单个子域名是否存在"""
            full_domain = f"{subdomain}.{domain}"
            try:
                # 使用线程池执行阻塞的 DNS 查询
                loop = asyncio.get_event_loop()
                await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, full_domain),
                    timeout=5,  # 单个查询超时 5 秒
                )
                return full_domain
            except (socket.gaierror, asyncio.TimeoutError, OSError):
                return None

        # 并发检查所有子域名（限制并发数量）
        semaphore = asyncio.Semaphore(20)

        async def _limited_check(subdomain: str) -> str | None:
            async with semaphore:
                return await _check_subdomain(subdomain)

        try:
            tasks = [_limited_check(sub) for sub in DEFAULT_SUBDOMAIN_WORDLIST]
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=timeout,
            )

            for result in results:
                if isinstance(result, str):
                    found.append(result)

        except asyncio.TimeoutError:
            logger.warning("内置子域名枚举超时: %s", domain)

        return sorted(found)

    @staticmethod
    def _is_ip_address(value: str) -> bool:
        """检查是否为 IP 地址"""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        """
        基本域名格式校验

        Args:
            domain: 待校验的域名

        Returns:
            是否为合法域名格式
        """
        # 简单校验：至少有一个点，不含空格和特殊字符
        if not domain or " " in domain:
            return False
        parts = domain.split(".")
        if len(parts) < 2:
            return False
        for part in parts:
            if not part or not all(c.isalnum() or c == "-" for c in part):
                return False
        return True
