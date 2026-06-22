"""
沙箱执行器模块

提供带超时和审计日志的子进程执行能力。
MVP 阶段使用 subprocess + timeout 方案，不涉及 Docker 容器隔离。
所有外部命令（如 nmap、subfinder、nuclei）均通过此模块执行。
"""

import asyncio
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


class SandboxExecutor:
    """
    沙箱执行器

    封装 asyncio.create_subprocess_exec，提供：
    - 命令超时强制终止
    - 执行时间统计
    - 审计日志记录（所有命令和结果均被记录）

    注意：MVP 阶段仅做进程级隔离，未使用 Docker 容器。
    """

    def __init__(self):
        # 审计日志列表，记录所有命令执行历史
        self._audit_log: list[dict] = []

    async def execute_command(
        self,
        command: list[str],
        timeout: int = 60,
        cwd: Optional[str] = None,
    ) -> dict:
        """
        执行外部命令

        Args:
            command: 命令和参数列表，例如 ["nmap", "-sT", "-p", "80", "target.com"]
            timeout: 超时秒数，超时后强制终止进程
            cwd: 工作目录，默认为 None（使用当前目录）

        Returns:
            {
                "stdout": str,           # 标准输出内容
                "stderr": str,           # 标准错误内容
                "return_code": int,      # 进程返回码
                "execution_time_ms": int, # 执行耗时（毫秒）
                "success": bool,         # 是否成功（return_code == 0）
                "timed_out": bool,       # 是否超时被终止
            }
        """
        # 参数校验
        if not command:
            return self._make_error("命令列表不能为空")

        if not isinstance(command, list):
            return self._make_error("command 必须是列表类型")

        # 记录命令开始
        cmd_str = " ".join(command)
        logger.info("沙箱执行命令: %s (timeout=%ds)", cmd_str, timeout)

        start_time = time.monotonic()
        timed_out = False

        try:
            # 创建异步子进程
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )

            try:
                # 等待进程完成（带超时）
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                # 超时：强制终止进程
                timed_out = True
                logger.warning("命令执行超时，强制终止: %s", cmd_str)
                try:
                    process.kill()
                    # 等待进程完全退出，避免僵尸进程
                    await process.wait()
                except ProcessLookupError:
                    pass  # 进程已退出
                stdout_bytes = b""
                stderr_bytes = b"Process killed due to timeout"

            # 计算执行时间
            elapsed_ms = int((time.monotonic() - start_time) * 1000)

            # 解码输出
            stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
            stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
            return_code = process.returncode if process.returncode is not None else -1

            result = {
                "stdout": stdout,
                "stderr": stderr,
                "return_code": return_code,
                "execution_time_ms": elapsed_ms,
                "success": return_code == 0 and not timed_out,
                "timed_out": timed_out,
            }

        except FileNotFoundError:
            # 命令不存在
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            logger.warning("命令未找到: %s", command[0])
            result = {
                "stdout": "",
                "stderr": f"命令未找到: {command[0]}",
                "return_code": -1,
                "execution_time_ms": elapsed_ms,
                "success": False,
                "timed_out": False,
            }

        except PermissionError:
            # 权限不足
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            logger.warning("权限不足，无法执行: %s", cmd_str)
            result = {
                "stdout": "",
                "stderr": f"权限不足，无法执行: {command[0]}",
                "return_code": -1,
                "execution_time_ms": elapsed_ms,
                "success": False,
                "timed_out": False,
            }

        except Exception as e:
            # 其他异常
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            logger.error("命令执行异常: %s, 错误: %s", cmd_str, str(e))
            result = {
                "stdout": "",
                "stderr": f"执行异常: {str(e)}",
                "return_code": -1,
                "execution_time_ms": elapsed_ms,
                "success": False,
                "timed_out": False,
            }

        # 记录审计日志
        audit_entry = {
            "command": cmd_str,
            "return_code": result["return_code"],
            "execution_time_ms": result["execution_time_ms"],
            "success": result["success"],
            "timed_out": result.get("timed_out", False),
        }
        self._audit_log.append(audit_entry)
        logger.info(
            "命令执行完成: %s (return_code=%d, time=%dms)",
            cmd_str,
            result["return_code"],
            result["execution_time_ms"],
        )

        return result

    def get_audit_log(self) -> list[dict]:
        """
        获取所有命令执行的审计日志

        Returns:
            审计日志列表，每条包含命令、返回码、执行时间等信息
        """
        return list(self._audit_log)

    def clear_audit_log(self) -> None:
        """清空审计日志"""
        self._audit_log.clear()

    @staticmethod
    def _make_error(error_msg: str) -> dict:
        """
        生成标准错误结果

        Args:
            error_msg: 错误描述

        Returns:
            错误结果字典
        """
        return {
            "stdout": "",
            "stderr": error_msg,
            "return_code": -1,
            "execution_time_ms": 0,
            "success": False,
            "timed_out": False,
        }
