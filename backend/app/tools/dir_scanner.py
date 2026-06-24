"""
目录扫描工具模块

发现目标 Web 应用的隐藏路径和敏感文件。
使用并发 HTTP 请求探测常见的管理后台、配置文件、API 文档等路径。
"""

import asyncio
import logging
import time
from typing import Any

import httpx

from .base import BaseTool, ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)

# 默认路径字典 v2-fix: 从 59 条扩展到 ~140 条
DEFAULT_WORDLIST = [
    # ── 版本控制 & 配置文件 ──
    ".git", ".git/config", ".git/HEAD", ".svn/entries", ".hg/",
    ".env", ".env.backup", ".env.local", ".env.production",
    ".DS_Store", ".htaccess", ".htpasswd",
    "web.config", "config.yml", "config.yaml", "config.json",
    "docker-compose.yml", "Dockerfile", ".dockerignore",
    ".gitlab-ci.yml", "Jenkinsfile", ".travis.yml",
    # ── 通用入口 ──
    "robots.txt", "sitemap.xml",
    "admin", "api", "login", "register", "signup", "signin",
    "dashboard", "config", "backup", "backups", "old",
    "debug", "console", "status", "health", "ping",
    ".well-known", ".well-known/security.txt",
    # ── 备份文件后缀 ──
    ".bak", "index.php.bak", "index.html.bak", ".old", ".swp", ".save", ".orig",
    "~", "index.php~", "index.html~",
    # ── Swagger / API 文档 ──
    "swagger", "swagger-ui.html", "swagger.json",
    "swagger/v1/swagger.json", "swagger/v2/swagger.json",
    "openapi.json", "openapi.yaml",
    "docs", "api/docs", "api-docs",
    "api/v1", "api/v2", "api/v3",
    "api/swagger.json", "api/openapi.json",
    "v1", "v2", "v3",
    # ── GraphQL ──
    "graphql", "graphiql", "playground",
    # ── Spring / Java ──
    "actuator", "actuator/health", "actuator/env", "actuator/mappings",
    "actuator/info", "actuator/metrics", "actuator/beans",
    "invoker/JMXInvokerServlet", "jmx-console", "web-console",
    # ── PHP ──
    "phpinfo.php", "phpmyadmin", "info.php", "test.php",
    "wp-admin", "wp-login.php", "wp-content", "wp-json",
    "wp-config.php", "wp-config.php.bak", "wp-config.bak",
    # ── 常见框架路径 ──
    "api/users", "api/auth", "api/login", "api/admin",
    "/api/user", "/api/account",
    "admin/login", "admin/users",
    # ── 服务器信息 ──
    "server-status", "server-info",
    "elmah.axd", "trace.axd",
    # ── 常见文件 ──
    "crossdomain.xml", "clientaccesspolicy.xml",
    "sitemap.xml.gz", "favicon.ico",
    "README.md", "CHANGELOG.md", "LICENSE",
    # ── 静态资源探测 ──
    "static", "assets", "public", "uploads", "files", "downloads",
    "images", "css", "js", "img",
]


class DirScannerTool(BaseTool):
    """
    目录扫描工具

    通过 HTTP 请求探测目标 Web 应用的隐藏路径和敏感文件。
    风险等级 L0（只读、被动扫描）。
    """

    name = "dir_scan"
    description = "目录扫描 - 发现目标 Web 应用的隐藏路径和敏感文件"
    risk_level = RiskLevel.L0

    def get_schema(self) -> dict:
        """返回目录扫描工具的参数 JSON Schema"""
        return {
            "type": "object",
            "properties": {
                "base_url": {
                    "type": "string",
                    "description": "目标基础 URL（如 https://example.com）",
                },
                "wordlist": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "自定义路径字典列表（为空时使用默认字典）",
                    "default": None,
                },
                "concurrency": {
                    "type": "integer",
                    "description": "并发请求数",
                    "default": 10,
                },
                "timeout": {
                    "type": "integer",
                    "description": "总超时时间（秒）",
                    "default": 60,
                },
            },
            "required": ["base_url"],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        """
        执行目录扫描

        并发探测目标路径，返回可访问的路径列表。

        Args:
            params: {base_url, wordlist, concurrency, timeout}
            context: 执行上下文

        Returns:
            {
                success: bool,
                found_paths: list[{path, status_code, content_length}],
                total_checked: int,
                scan_time_ms: int,
            }
        """
        base_url = params.get("base_url", "").rstrip("/")
        wordlist = params.get("wordlist") or DEFAULT_WORDLIST
        concurrency = params.get("concurrency", 10)
        timeout = params.get("timeout", 60)

        # 参数校验
        if not base_url:
            return self._make_error_result("base_url 参数不能为空")

        # 目标白名单校验
        if not self._validate_target(base_url, context):
            return self._make_error_result(
                f"目标 URL 不在允许的主机白名单内: {base_url}"
            )

        # 并发数约束
        concurrency = max(1, min(concurrency, 50))

        start_time = time.monotonic()
        found_paths = []
        total_checked = 0
        semaphore = asyncio.Semaphore(concurrency)

        async def _check_path(client: httpx.AsyncClient, path: str) -> dict | None:
            """
            检查单个路径是否可访问

            Args:
                client: HTTP 客户端
                path: 待检查的路径

            Returns:
                路径信息字典，不可访问时返回 None
            """
            nonlocal total_checked
            async with semaphore:
                url = f"{base_url}/{path}"
                try:
                    response = await client.get(url)
                    total_checked += 1

                    # 过滤掉明显不存在的响应（404、405）
                    if response.status_code not in (404, 405, 502, 503):
                        content_length = len(response.content)
                        return {
                            "path": f"/{path}",
                            "status_code": response.status_code,
                            "content_length": content_length,
                        }
                    return None

                except (httpx.TimeoutException, httpx.ConnectError):
                    total_checked += 1
                    return None
                except Exception:
                    total_checked += 1
                    return None

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(min(context.timeout, 10)),  # 单个请求最多 10 秒
                follow_redirects=False,  # 不跟踪重定向，保留原始状态码
                verify=False,
            ) as client:
                tasks = [_check_path(client, path) for path in wordlist]
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=timeout,
                )

                for result in results:
                    if isinstance(result, dict):
                        found_paths.append(result)

        except asyncio.TimeoutError:
            logger.warning("目录扫描超时: %s", base_url)

        except Exception as e:
            logger.error("目录扫描异常: %s - %s", base_url, str(e))
            return self._make_error_result(f"扫描异常: {str(e)}")

        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        # 按状态码排序（200 优先）
        found_paths.sort(key=lambda x: (x["status_code"] != 200, x["status_code"]))

        return {
            "success": True,
            "found_paths": found_paths,
            "total_checked": total_checked,
            "scan_time_ms": elapsed_ms,
        }
