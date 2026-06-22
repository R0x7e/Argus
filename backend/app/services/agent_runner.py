"""
Agent 运行器 - 管理 Agent 任务的异步执行生命周期

负责在后台 asyncio Task 中执行 LangGraph 图，
并管理任务的启动、暂停、恢复和终止。
"""

import asyncio
import uuid as uuid_mod
from typing import Optional

import structlog
from sqlalchemy.ext.asyncio import async_sessionmaker

logger = structlog.get_logger()


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

    async def start_task(self, task_id: str, task_config: dict, max_iterations: int = 3) -> None:
        """
        启动漏洞挖掘任务

        创建后台 asyncio.Task 执行 LangGraph 图。
        如果任务已在运行，则跳过。

        Args:
            task_id: 任务 ID
            task_config: 任务配置（目标 URL、范围等）
            max_iterations: 最大迭代次数
        """
        if task_id in self._tasks:
            logger.warning("task_already_running", task_id=task_id)
            return

        # 创建暂停控制事件（初始为 set 状态，表示未暂停）
        pause_event = asyncio.Event()
        pause_event.set()
        self._pause_events[task_id] = pause_event

        # 创建后台任务
        task = asyncio.create_task(
            self._run_graph(task_id, task_config, max_iterations, pause_event),
            name=f"argus-task-{task_id}",
        )
        self._tasks[task_id] = task

        logger.info("agent_task_started", task_id=task_id, max_iterations=max_iterations)

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
    ) -> None:
        """
        执行 LangGraph 图的核心逻辑。

        整体流程：
        1. 构建图和初始状态
        2. 发射任务开始事件
        3. 执行图（ainvoke）
        4. 持久化事件和漏洞发现
        5. 更新任务状态为完成

        异常处理：
        - CancelledError: 任务被终止，更新状态为 terminated
        - 其他异常: 任务失败，更新状态为 failed 并记录错误事件
        """
        from app.agents.graph import build_vuln_hunt_graph, create_initial_state
        from app.core.event_bus import event_bus
        from app.services.finding_service import FindingService
        from app.services.task_service import TaskService

        try:
            # 构建 LangGraph 图和初始状态
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

            # 执行 LangGraph 图
            result = await graph.ainvoke(initial_state)

            # 处理执行结果：持久化漏洞发现和报告
            async with self._session_factory() as db:
                # 保存漏洞发现到 findings 表
                bb = result.get("blackboard")
                if bb and bb.findings:
                    finding_svc = FindingService(db)
                    for f in bb.findings:
                        try:
                            h_id = getattr(f, "hypothesis_id", None)
                            await finding_svc.create_finding(
                                task_id=uuid_mod.UUID(task_id) if isinstance(task_id, str) else task_id,
                                hypothesis_id=uuid_mod.UUID(h_id) if h_id else None,
                                type=getattr(f, "type", "unknown"),
                                severity=getattr(f, "severity", "info"),
                                title=getattr(f, "title", "未命名发现"),
                                description=getattr(f, "description", ""),
                                trigger_path=getattr(f, "trigger_path", []),
                                payload=getattr(f, "payload", ""),
                                reproduction_steps=getattr(f, "reproduction_steps", []),
                                evidence=getattr(f, "evidence", {}),
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
                            content=report.get("content", ""),
                            format=report.get("format", "markdown"),
                            findings_count=report.get("findings_count", 0),
                            severity_distribution=report.get("severity_distribution", {}),
                        )

                # 更新任务状态为完成，并记录发现数量
                task_svc = TaskService(db)
                findings_count = len(bb.findings) if bb else 0
                await task_svc.transition_status(task_id, "done")
                task_obj = await task_svc.get_task(task_id)
                task_obj.progress = {
                    **(task_obj.progress or {}),
                    "findings_count": findings_count,
                    "iterations": result.get("iteration_count", 0),
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
                        "iterations": result.get("iteration_count", 0),
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
                await task_svc.transition_status(task_id, "terminated")
                await db.commit()

        except Exception as e:
            # 任务执行失败
            logger.error("agent_task_failed", task_id=task_id, error=str(e))
            async with self._session_factory() as db:
                task_svc = TaskService(db)
                try:
                    await task_svc.transition_status(task_id, "failed")
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

        finally:
            # 清理内存中的任务引用
            self._cleanup(task_id)

    def _cleanup(self, task_id: str) -> None:
        """
        清理任务资源

        从内存映射中移除任务和暂停事件的引用。
        """
        self._tasks.pop(task_id, None)
        self._pause_events.pop(task_id, None)


# 全局单例占位（在 main.py lifespan 中用实际的 session_factory 初始化）
agent_runner: Optional[AgentRunner] = None
