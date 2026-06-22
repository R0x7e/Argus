"""
端口扫描工具模块

检测目标主机开放的端口和服务信息。
支持 nmap 外部工具和内置 Python socket 扫描两种模式。
"""

import asyncio
import logging
import socket
import time
import xml.etree.ElementTree as ET
from typing import Any

from .base import BaseTool, ExecutionContext, RiskLevel
from .sandbox import SandboxExecutor

logger = logging.getLogger(__name__)

# 默认扫描端口列表
DEFAULT_PORTS = "80,443,8080,8443,3000,5000,8000,9090"

# 常见端口与服务名称映射
PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3000: "nodejs",
    3306: "mysql",
    3389: "rdp",
    5000: "flask",
    5432: "postgresql",
    5672: "amqp",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9090: "prometheus",
    9200: "elasticsearch",
    27017: "mongodb",
}


class PortScannerTool(BaseTool):
    """
    端口扫描工具

    检测目标主机的开放端口和对应服务。
    优先使用 nmap（更准确），不可用时回退到 socket 连接扫描。
    风险等级 L0（只读、被动扫描）。
    """

    name = "port_scan"
    description = "端口扫描 - 检测目标主机开放的端口和服务"
    risk_level = RiskLevel.L0

    def __init__(self):
        self._sandbox = SandboxExecutor()

    def get_schema(self) -> dict:
        """返回端口扫描工具的参数 JSON Schema"""
        return {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "目标主机地址（域名或 IP）",
                },
                "ports": {
                    "type": "string",
                    "description": "要扫描的端口列表，逗号分隔（如 80,443,8080）",
                    "default": DEFAULT_PORTS,
                },
                "timeout": {
                    "type": "integer",
                    "description": "超时时间（秒）",
                    "default": 60,
                },
            },
            "required": ["host"],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        """
        执行端口扫描

        优先尝试 nmap，失败则回退到 socket 连接扫描。

        Args:
            params: {host: str, ports: str, timeout: int}
            context: 执行上下文

        Returns:
            {
                success: bool,
                open_ports: list[{port, state, service}],
                host: str,
                scan_time_ms: int,
                source: "nmap" | "socket",
            }
        """
        host = params.get("host", "")
        ports_str = params.get("ports", DEFAULT_PORTS)
        timeout = params.get("timeout", 60)

        # 参数校验
        if not host:
            return self._make_error_result("host 参数不能为空")

        # 解析端口列表
        try:
            ports = self._parse_ports(ports_str)
        except ValueError as e:
            return self._make_error_result(f"端口格式错误: {str(e)}")

        if not ports:
            return self._make_error_result("未指定有效端口")

        start_time = time.monotonic()

        # 尝试使用 nmap
        nmap_result = await self._try_nmap(host, ports_str, timeout)
        if nmap_result is not None:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            return {
                "success": True,
                "open_ports": nmap_result,
                "host": host,
                "scan_time_ms": elapsed_ms,
                "source": "nmap",
            }

        # 回退到 socket 扫描
        logger.info("nmap 不可用，使用内置 socket 扫描: %s", host)
        socket_result = await self._socket_scan(host, ports, timeout)
        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        return {
            "success": True,
            "open_ports": socket_result,
            "host": host,
            "scan_time_ms": elapsed_ms,
            "source": "socket",
        }

    async def _try_nmap(self, host: str, ports: str, timeout: int) -> list[dict] | None:
        """
        尝试使用 nmap 进行端口扫描

        Args:
            host: 目标主机
            ports: 端口列表字符串
            timeout: 超时秒数

        Returns:
            端口信息列表，nmap 不可用时返回 None
        """
        try:
            result = await self._sandbox.execute_command(
                ["nmap", "-sT", "-p", ports, host, "-oX", "-"],
                timeout=timeout,
            )

            if not result["success"]:
                return None

            # 解析 nmap XML 输出
            return self._parse_nmap_xml(result["stdout"])

        except Exception as e:
            logger.warning("nmap 执行异常: %s", str(e))
            return None

    def _parse_nmap_xml(self, xml_output: str) -> list[dict]:
        """
        解析 nmap XML 格式输出

        Args:
            xml_output: nmap -oX 的 XML 输出

        Returns:
            端口信息列表 [{port, state, service}]
        """
        open_ports = []
        try:
            root = ET.fromstring(xml_output)
            for port_elem in root.iter("port"):
                port_id = int(port_elem.get("portid", 0))
                state_elem = port_elem.find("state")
                service_elem = port_elem.find("service")

                state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
                service = service_elem.get("name", "unknown") if service_elem is not None else "unknown"

                if state == "open":
                    open_ports.append({
                        "port": port_id,
                        "state": state,
                        "service": service,
                    })
        except ET.ParseError as e:
            logger.warning("nmap XML 解析失败: %s", str(e))

        return open_ports

    async def _socket_scan(self, host: str, ports: list[int], timeout: int) -> list[dict]:
        """
        使用 Python socket 进行端口连接扫描

        Args:
            host: 目标主机
            ports: 端口列表
            timeout: 总超时秒数

        Returns:
            开放端口列表 [{port, state, service}]
        """
        open_ports = []
        semaphore = asyncio.Semaphore(50)  # 限制并发连接数

        async def _check_port(port: int) -> dict | None:
            """检查单个端口是否开放"""
            async with semaphore:
                try:
                    loop = asyncio.get_event_loop()
                    # 创建 socket 并设置超时
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)  # 单个端口连接超时 3 秒

                    # 在线程池中执行阻塞的 connect
                    result = await asyncio.wait_for(
                        loop.run_in_executor(
                            None,
                            lambda: sock.connect_ex((host, port)),
                        ),
                        timeout=5,
                    )

                    sock.close()

                    if result == 0:
                        # 端口开放
                        service = PORT_SERVICE_MAP.get(port, "unknown")
                        return {
                            "port": port,
                            "state": "open",
                            "service": service,
                        }
                    return None

                except (asyncio.TimeoutError, OSError, Exception):
                    return None

        try:
            tasks = [_check_port(port) for port in ports]
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=timeout,
            )

            for result in results:
                if isinstance(result, dict):
                    open_ports.append(result)

        except asyncio.TimeoutError:
            logger.warning("socket 端口扫描超时: %s", host)

        # 按端口号排序
        open_ports.sort(key=lambda x: x["port"])
        return open_ports

    @staticmethod
    def _parse_ports(ports_str: str) -> list[int]:
        """
        解析端口字符串为端口列表

        支持逗号分隔的端口号（如 "80,443,8080"）。

        Args:
            ports_str: 端口字符串

        Returns:
            端口号列表

        Raises:
            ValueError: 端口格式错误
        """
        ports = []
        for part in ports_str.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"端口号超出范围: {port}")
                ports.append(port)
            except ValueError:
                raise ValueError(f"无效的端口号: {part}")
        return sorted(set(ports))
