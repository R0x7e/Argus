"""
Agent 运行器 - 管理 Agent 任务的异步执行生命周期

负责在后台 asyncio Task 中执行 LangGraph 图，
并管理任务的启动、暂停、恢复和终止。
"""

import asyncio
import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Optional

import structlog
from sqlalchemy.ext.asyncio import async_sessionmaker

logger = structlog.get_logger()


def _sanitize_for_db(obj):
    """递归清洗对象中的非 UTF-8 字符串，防止 PostgreSQL UntranslatableCharacterError"""
    if isinstance(obj, str):
        return obj.encode('utf-8', errors='replace').decode('utf-8')
    elif isinstance(obj, dict):
        return {str(k): _sanitize_for_db(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_sanitize_for_db(i) for i in obj]
    return obj


class AgentRunner:
    """
    Agent 运行器：在后台 asyncio Task 中执行 LangGraph 图。

    负责：
    - 启动 Agent 执行（创建后台 asyncio.Task）
    - 管理暂停/恢复（通过 asyncio.Event 在节点边界控制）
    - 管理终止（通过 Task 取消机制）
    - 将 Agent 产出的事件持久化到数据库
    - 将漏洞发现写入 findings 表
    """

    def __init__(self, session_factory: async_sessionmaker) -> None:
        """
        初始化 Agent 运行器

        Args:
            session_factory: 异步数据库会话工厂，用于在后台任务中创建独立会话
        """
        # task_id -> asyncio.Task，跟踪运行中的后台任务
        self._tasks: dict[str, asyncio.Task] = {}
        # task_id -> asyncio.Event，用于暂停/恢复控制
        self._pause_events: dict[str, asyncio.Event] = {}
        self._session_factory = session_factory
        # v2: 跟踪活跃任务的 LATSState (供 WebSocket 用户干预)
        self._active_states: dict[str, dict] = {}

    async def start_task(
        self,
        task_id: str,
        task_config: dict,
        max_iterations: int = 8,
        mode: str = "lats",
    ) -> None:
        """
        启动漏洞挖掘任务

        创建后台 asyncio.Task 执行 LangGraph 图。
        如果任务已在运行，则跳过。

        Args:
            task_id: 任务 ID
            task_config: 任务配置（目标 URL、范围等）
            max_iterations: 最大迭代次数
            mode: 执行模式 - "lats" (LATS+ReAct 搜索架构) 或 "pipeline" (旧版固定管线)
        """
        # v6: 从 task_config 深层兜底读取 max_iterations
        if max_iterations <= 8:
            nested = task_config.get("config", {}).get("max_iterations", 0)
            if nested > max_iterations:
                max_iterations = nested
            flat = int(task_config.get("max_iterations", 0))
            if flat > max_iterations:
                max_iterations = flat

        if task_id in self._tasks:
            logger.warning("task_already_running", task_id=task_id)
            return

        # 创建暂停控制事件（初始为 set 状态，表示未暂停）
        pause_event = asyncio.Event()
        pause_event.set()
        self._pause_events[task_id] = pause_event

        # 创建后台任务
        task = asyncio.create_task(
            self._run_graph(task_id, task_config, max_iterations, pause_event, mode),
            name=f"argus-task-{task_id}",
        )
        self._tasks[task_id] = task

        logger.info("agent_task_started", task_id=task_id, max_iterations=max_iterations, mode=mode)

    async def pause_task(self, task_id: str) -> None:
        """
        暂停任务（在下一个 Agent 节点边界生效）

        通过清除 asyncio.Event 使图执行在节点间等待。
        """
        if task_id in self._pause_events:
            self._pause_events[task_id].clear()
            logger.info("agent_task_paused", task_id=task_id)

    async def resume_task(self, task_id: str) -> None:
        """
        恢复已暂停的任务

        通过设置 asyncio.Event 使暂停的图执行继续。
        """
        if task_id in self._pause_events:
            self._pause_events[task_id].set()
            logger.info("agent_task_resumed", task_id=task_id)

    async def terminate_task(self, task_id: str) -> None:
        """
        终止任务

        通过取消 asyncio.Task 强制中断图执行。
        取消后的清理逻辑在 _run_graph 的 CancelledError 处理中完成。
        """
        if task_id in self._tasks:
            self._tasks[task_id].cancel()
            logger.info("agent_task_terminated", task_id=task_id)
            self._cleanup(task_id)

    def is_running(self, task_id: str) -> bool:
        """
        检查任务是否在运行

        Returns:
            True 表示任务存在且未完成
        """
        task = self._tasks.get(task_id)
        return task is not None and not task.done()

    async def _run_graph(
        self,
        task_id: str,
        task_config: dict,
        max_iterations: int,
        pause_event: asyncio.Event,
        mode: str = "lats",
    ) -> None:
        """
        执行 LangGraph 图的核心逻辑。

        整体流程：
        1. 构建图和初始状态（根据 mode 选择 LATS 或旧版管线）
        2. 发射任务开始事件
        3. 执行图（ainvoke）
        4. 持久化事件和漏洞发现
        5. 更新任务状态为完成

        异常处理：
        - CancelledError: 任务被终止，更新状态为 terminated
        - 其他异常: 任务失败，更新状态为 failed 并记录错误事件
        """
        from app.core.event_bus import event_bus
        from app.services.finding_service import FindingService
        from app.services.task_service import TaskService

        # 为当前任务创建独立的 LLM 客户端实例，避免并发任务间状态污染
        from app.agents.llm import LLMClient
        from app.agents.token_budget import TokenBudget
        from app.agents.lats.graph import register_task_llm_client, unregister_task_llm_client
        from app.config import get_settings

        # 将 str task_id 转换为 uuid.UUID，供 TaskService 数据库操作使用
        task_uuid = uuid_mod.UUID(task_id) if isinstance(task_id, str) else task_id

        task_llm = LLMClient()
        task_llm.token_budget = TokenBudget(task_id=task_id, total_budget=500_000)
        register_task_llm_client(task_id, task_llm)

        try:
            # 根据 mode 构建不同的图和初始状态
            if mode == "lats":
                from app.agents.lats.graph import build_lats_graph, create_lats_initial_state
                graph = build_lats_graph()
                # v4-fix: 确保 max_iterations 正确传递, 默认不低于 10
                effective_max = max(max_iterations, 10) if max_iterations else 15
                logger.info("lats_graph_start", task_id=task_id, max_iterations=max_iterations,
                            effective_max=effective_max, task_config_keys=list(task_config.keys())[:10])
                initial_state = create_lats_initial_state(task_id, task_config, max_cycles=effective_max)
            else:
                from app.agents.graph import build_vuln_hunt_graph, create_initial_state
                graph = build_vuln_hunt_graph()
                initial_state = create_initial_state(task_id, task_config, max_iterations)

            # 发射任务开始事件
            async with self._session_factory() as db:
                await event_bus.publish(
                    db=db,
                    task_id=task_id,
                    agent="system",
                    event_type="log",
                    data={"content": "任务开始执行", "phase": "starting"},
                )
                await db.commit()

            # 执行 LangGraph 图（带全局超时保护）
            # v2: 将初始状态注册到活跃状态表 (供 WebSocket 用户干预)
            self._active_states[task_id] = initial_state
            task_timeout = get_settings().TASK_TIMEOUT_SECONDS
            result = await asyncio.wait_for(
                graph.ainvoke(initial_state),
                timeout=task_timeout,
            )

            # 处理执行结果：持久化漏洞发现和报告
            async with self._session_factory() as db:
                # 保存漏洞发现到 findings 表
                bb = result.get("blackboard")
                if bb and bb.findings:
                    finding_svc = FindingService(db)
                    for f in bb.findings:
                        try:
                            h_id = getattr(f, "hypothesis_id", None)
                            # v4-fix: 清洗二进制数据防止 DB 编码错误
                            safe_description = _sanitize_for_db(str(getattr(f, "description", "")))[:5000]
                            safe_payload = _sanitize_for_db(str(getattr(f, "payload", "")))[:2000]
                            safe_steps = _sanitize_for_db(getattr(f, "reproduction_steps", []))
                            safe_evidence = _sanitize_for_db(getattr(f, "evidence", {}))
                            await finding_svc.create_finding(
                                task_id=uuid_mod.UUID(task_id) if isinstance(task_id, str) else task_id,
                                hypothesis_id=uuid_mod.UUID(h_id) if h_id else None,
                                type=getattr(f, "type", "unknown"),
                                severity=getattr(f, "severity", "info"),
                                title=_sanitize_for_db(str(getattr(f, "title", "未命名发现")))[:500],
                                description=safe_description,
                                trigger_path=_sanitize_for_db(getattr(f, "trigger_path", [])),
                                payload=safe_payload,
                                reproduction_steps=safe_steps,
                                evidence=safe_evidence,
                            )
                        except Exception as e:
                            logger.error("finding_persist_failed", task_id=task_id, error=str(e))

                # 保存报告
                if bb and bb.reports:
                    from app.services.report_service import ReportService
                    report_svc = ReportService(db)
                    for report in bb.reports:
                        await report_svc.create_report(
                            task_id=task_id,
                            content=_sanitize_for_db(str(report.get("content", "")))[:100000],
                            format=report.get("format", "markdown"),
                            findings_count=report.get("findings_count", 0),
                            severity_distribution=_sanitize_for_db(report.get("severity_distribution", {})),
                        )

                # 更新任务状态为完成，并记录发现数量
                task_svc = TaskService(db)
                findings_count = len(bb.findings) if bb else 0
                await task_svc.transition_status(task_uuid, "done")
                task_obj = await task_svc.get_task(task_uuid)
                iterations = result.get("iteration_count", 0) or result.get("current_cycle", 0)
                task_obj.progress = {
                    **(task_obj.progress or {}),
                    "findings_count": findings_count,
                    "iterations": iterations,
                    "mode": mode,
                }

                # 发射任务完成事件
                findings_count = len(bb.findings) if bb else 0
                await event_bus.publish(
                    db=db,
                    task_id=task_id,
                    agent="system",
                    event_type="log",
                    data={
                        "content": "任务执行完成",
                        "findings_count": findings_count,
                        "iterations": iterations,
                        "mode": mode,
                    },
                )
                await db.commit()

            logger.info(
                "agent_task_completed",
                task_id=task_id,
                findings=findings_count,
            )

        except asyncio.CancelledError:
            # 任务被外部终止
            logger.info("agent_task_cancelled", task_id=task_id)
            async with self._session_factory() as db:
                task_svc = TaskService(db)
                await task_svc.transition_status(
                    task_uuid,
                    "terminated",
                    error_info={
                        "error_type": "CancelledError",
                        "message": "任务被用户手动终止",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                )
                await db.commit()
            # 同步 Agent 执行状态
            await self._sync_agent_executions_on_failure(task_id, "任务被终止")

        except asyncio.TimeoutError:
            # 任务执行超时
            logger.error("agent_task_timeout", task_id=task_id, timeout=task_timeout)
            async with self._session_factory() as db:
                task_svc = TaskService(db)
                try:
                    await task_svc.transition_status(
                        task_uuid,
                        "failed",
                        error_info={
                            "error_type": "TimeoutError",
                            "message": f"任务执行超时 ({task_timeout}s)，已自动终止",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                    )
                    await event_bus.publish(
                        db=db,
                        task_id=task_id,
                        agent="system",
                        event_type="error",
                        data={"content": f"任务执行超时 ({task_timeout}s)，已自动终止"},
                    )
                    await db.commit()
                except Exception:
                    logger.error("failed_to_update_task_status", task_id=task_id)
            # 同步 Agent 执行状态
            await self._sync_agent_executions_on_failure(task_id, f"任务执行超时 ({task_timeout}s)")

        except Exception as e:
            # 任务执行失败
            logger.error("agent_task_failed", task_id=task_id, error=str(e))
            async with self._session_factory() as db:
                task_svc = TaskService(db)
                try:
                    await task_svc.transition_status(
                        task_uuid,
                        "failed",
                        error_info={
                            "error_type": type(e).__name__,
                            "message": str(e)[:500],
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                    )
                    await event_bus.publish(
                        db=db,
                        task_id=task_id,
                        agent="system",
                        event_type="error",
                        data={"content": f"任务执行失败: {str(e)}"},
                    )
                    await db.commit()
                except Exception:
                    # 状态更新失败也不抛异常，避免掩盖原始错误
                    logger.error("failed_to_update_task_status", task_id=task_id)
            # 同步 Agent 执行状态
            await self._sync_agent_executions_on_failure(task_id, f"任务执行失败: {str(e)[:200]}")

        finally:
            # 清理内存中的任务引用
            self._cleanup(task_id)
            # 清理任务专属的 LLM 客户端实例
            unregister_task_llm_client(task_id)

    def _cleanup(self, task_id: str) -> None:
        """
        清理任务资源

        从内存映射中移除任务、暂停事件和活跃状态的引用。
        """
        self._tasks.pop(task_id, None)
        self._pause_events.pop(task_id, None)
        self._active_states.pop(task_id, None)  # v2

    async def _sync_agent_executions_on_failure(
        self, task_id: str, failure_reason: str
    ) -> None:
        """
        任务失败/终止时，将所有关联的 Agent 执行记录状态更新为 failed/terminated

        解决任务状态与 Agent 状态不一致的问题。
        """
        from sqlalchemy import update
        from app.models.agent_execution import AgentExecution

        try:
            async with self._session_factory() as db:
                # 将所有该任务下仍在 "running" 状态的 Agent 执行记录更新为失败
                stmt = (
                    update(AgentExecution)
                    .where(
                        AgentExecution.task_id == task_id,
                        AgentExecution.status == "running",
                    )
                    .values(
                        status="failed",
                        completed_at=datetime.now(timezone.utc),
                        summary=failure_reason,
                    )
                )
                await db.execute(stmt)
                await db.commit()
                logger.info(
                    "agent_executions_synced_on_failure",
                    task_id=task_id,
                    reason=failure_reason,
                )
        except Exception as e:
            logger.error(
                "failed_to_sync_agent_executions",
                task_id=task_id,
                error=str(e),
            )


# 全局单例占位（在 main.py lifespan 中用实际的 session_factory 初始化）
agent_runner: Optional[AgentRunner] = None
