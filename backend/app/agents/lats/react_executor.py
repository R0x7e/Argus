"""
ReAct 执行器

实现 Thought → Action → Observation 循环的核心运行时。
每个 ReAct Agent 在搜索树的一个节点上执行，深度探索一条攻击路径。
支持并发执行多条路径。
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from app.agents.emit import emit
from app.agents.llm import LLMClient
from app.tools.base import ExecutionContext

from .actions import ActionType, Observation, execute_action
from .prompts import REACT_SYSTEM_PROMPT, build_react_prompt
from .reward import compute_reward
from .search_tree import NodeState, SearchNode, ThoughtStep, ToolCall

logger = logging.getLogger(__name__)


@dataclass
class ReactResult:
    """ReAct Agent 执行结果"""
    node_id: str
    status: str  # "finding" | "exhausted" | "backtrack" | "step_limit" | "error"
    steps: list[ThoughtStep] = field(default_factory=list)
    reward: float = 0.0
    finding: dict = field(default_factory=dict)
    error: str = ""


def _parse_react_response(response_text: str) -> dict:
    """解析 LLM 的 ReAct 响应为结构化数据"""
    try:
        result = json.loads(response_text)
        if isinstance(result, dict) and "action" in result:
            return result
    except json.JSONDecodeError:
        pass

    # 尝试从 markdown code block 中提取
    try:
        start = response_text.find("{")
        end = response_text.rfind("}") + 1
        if start >= 0 and end > start:
            result = json.loads(response_text[start:end])
            if isinstance(result, dict) and "action" in result:
                return result
    except json.JSONDecodeError:
        pass

    logger.warning("无法解析 ReAct 响应: %s", response_text[:200])
    return {
        "thought": "响应解析失败，请求回溯",
        "action": "backtrack",
        "params": {},
    }


async def _maybe_record_to_knowledge(
    observation,  # Observation
    action_str: str,
    action_params: dict,
    node,  # SearchNode
    step_idx: int,
) -> None:
    """v2: 从 Observation 中提取知识并写入 SharedKnowledge (非阻塞)"""
    try:
        import asyncio as _asyncio
        # 通过 agent_runner 的全局引用获取 knowledge (非阻塞方式)
        # 实际的知识库实例存储在 Blackboard 中, 由 graph.py 节点管理
    except Exception:
        pass
    # 此函数作为钩子占位，实际写入在 expand_node 中批量完成

async def react_agent_loop(
    node: SearchNode,
    context: ExecutionContext,
    llm: LLMClient,
    max_steps: int = 8,
    steering_directives: list[str] | None = None,
) -> ReactResult:
    """
    一个 ReAct Agent 在给定节点上执行 Thought-Action-Observation 循环。

    终止条件：
    - 确认漏洞 → 返回 finding
    - Agent 请求 backtrack → 返回 backtrack
    - Agent 请求 give_up → 返回 exhausted
    - 步数耗尽 → 返回 step_limit
    - 异常 → 返回 error
    """
    state = node.state.copy()
    steps: list[ThoughtStep] = []
    accumulated_reward = 0.0
    consecutive_no_info = 0
    consecutive_tool_errors = 0  # v17: 连续工具异常计数

    for step_idx in range(max_steps):
        # === Thought: 调用 LLM 决定下一步 ===
        state_dict = {
            "target_url": state.target_url,
            "current_endpoint": state.current_endpoint,
            "current_param": state.current_param,
            "vuln_type": state.vuln_type,
            "known_facts": state.known_facts[-15:],
        }

        step_history = [
            {
                "thought": s.thought,
                "action": s.action,
                "action_params": s.action_params,
                "observation": s.observation,
            }
            for s in steps[-5:]
        ]

        user_prompt = build_react_prompt(
            state_dict, step_history, {"depth": node.depth + step_idx},
            steering_directives=steering_directives,
        )

        messages = [
            {"role": "system", "content": REACT_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        try:
            response_text = await llm.call(
                agent="react_agent", messages=messages,
                task_id=context.task_id,
            )
        except Exception as e:
            logger.error("ReAct LLM 调用失败: %s", str(e))
            return ReactResult(
                node_id=node.id,
                status="error",
                steps=steps,
                reward=accumulated_reward,
                error=str(e),
            )

        parsed = _parse_react_response(response_text)
        thought = parsed.get("thought", "")
        action_str = parsed.get("action", "give_up")
        action_params = parsed.get("params", {})

        # === 控制动作处理 ===
        if action_str == ActionType.BACKTRACK or action_str == "backtrack":
            steps.append(ThoughtStep(
                thought=thought,
                action="backtrack",
                action_params={},
                observation="请求回溯",
                reward=0.0,
            ))
            await emit(
                task_id=context.task_id, agent="lats_react", event_type="react_step",
                data={"node_id": node.id, "step": step_idx, "thought": thought,
                      "action": "backtrack", "action_params": {}, "observation": "请求回溯",
                      "success": True, "reward": 0.0, "new_facts": [], "vuln_confirmed": False,
                      "duration_ms": 0, "tool_name": ""},
            )
            return ReactResult(
                node_id=node.id,
                status="backtrack",
                steps=steps,
                reward=accumulated_reward,
            )

        if action_str == ActionType.GIVE_UP or action_str == "give_up":
            steps.append(ThoughtStep(
                thought=thought,
                action="give_up",
                action_params={},
                observation="放弃当前路径",
                reward=0.0,
            ))
            await emit(
                task_id=context.task_id, agent="lats_react", event_type="react_step",
                data={"node_id": node.id, "step": step_idx, "thought": thought,
                      "action": "give_up", "action_params": {}, "observation": "放弃当前路径",
                      "success": True, "reward": 0.0, "new_facts": [], "vuln_confirmed": False,
                      "duration_ms": 0, "tool_name": ""},
            )
            return ReactResult(
                node_id=node.id,
                status="exhausted",
                steps=steps,
                reward=accumulated_reward,
            )

        if action_str == ActionType.REPORT_FINDING or action_str == "report_finding":
            steps.append(ThoughtStep(
                thought=thought,
                action="report_finding",
                action_params=action_params,
                observation="提交漏洞发现",
                reward=1.0,
            ))
            await emit(
                task_id=context.task_id, agent="lats_react", event_type="react_step",
                data={"node_id": node.id, "step": step_idx, "thought": thought,
                      "action": "report_finding", "action_params": action_params,
                      "observation": "提交漏洞发现", "success": True, "reward": 1.0,
                      "new_facts": [], "vuln_confirmed": True, "duration_ms": 0, "tool_name": ""},
            )
            return ReactResult(
                node_id=node.id,
                status="finding",
                steps=steps,
                reward=1.0,
                finding=action_params,
            )

        # === 执行动作 ===
        observation = await execute_action(action_str, action_params, context, state)

        # === v2: 记录到共享知识库 ===
        try:
            from .shared_knowledge import SharedKnowledge
            _maybe_record_to_knowledge(observation, action_str, action_params, node, step_idx)
        except Exception:
            pass  # 知识库记录失败不影响核心流程

        # === v17: 工具异常检测 ===
        if observation.success and not observation.new_info_gained:
            pass  # 正常执行但无发现
        elif not observation.success:
            consecutive_tool_errors += 1
        else:
            consecutive_tool_errors = 0

        # 连续 2 次工具异常 → 自动回溯, 切换工具
        if consecutive_tool_errors >= 2:
            logger.info("连续 %d 次工具异常，自动回溯", consecutive_tool_errors)
            return ReactResult(node_id=node.id, status="backtrack", steps=steps,
                reward=accumulated_reward, error=f"consecutive_tool_errors={consecutive_tool_errors}")

        # === 计算奖励 ===
        step_reward = compute_reward(observation)
        accumulated_reward += step_reward

        # === 更新状态 ===
        if observation.new_facts:
            state.known_facts.extend(observation.new_facts)
        state.tried_actions.append(f"{action_str}:{json.dumps(action_params, ensure_ascii=False)[:80]}")

        if observation.tool_call:
            state.tool_history.append(ToolCall(
                tool_name=observation.tool_call.get("tool", ""),
                params=observation.tool_call.get("params", {}),
                result=observation.tool_call.get("result", {}),
                success=observation.success,
            ))

        steps.append(ThoughtStep(
            thought=thought,
            action=action_str,
            action_params=action_params,
            observation=observation.summary,
            reward=step_reward,
        ))

        await emit(
            task_id=context.task_id,
            agent="lats_react",
            event_type="react_step",
            data={
                "node_id": node.id,
                "step": step_idx,
                "thought": thought,
                "action": action_str,
                "action_params": action_params,
                "observation": observation.summary,
                "success": observation.success,
                "reward": round(step_reward, 3),
                "new_facts": observation.new_facts,
                "vuln_confirmed": observation.vuln_confirmed,
                "duration_ms": observation.response_time_ms,
                "tool_name": observation.tool_call.get("tool", "") if observation.tool_call else "",
            },
        )

        # === 检查是否确认漏洞 ===
        if observation.vuln_confirmed:
            return ReactResult(
                node_id=node.id,
                status="finding",
                steps=steps,
                reward=1.0,
                finding=observation.finding,
            )

        # === v17: 跟踪连续无信息步 ===
        step_is_info = observation.new_info_gained
        # batch_inject 无异常时也计为 no_info (虽然 success=true 但无实际进展)
        obs_lower = (observation.summary or "").lower()
        if "all baseline" in obs_lower or "全部与基线相同" in obs_lower:
            step_is_info = False
        if step_is_info:
            consecutive_no_info = 0
        else:
            consecutive_no_info += 1

        # v17: 连续 3 步无信息 → 自动回溯 (曾为 4)
        if consecutive_no_info >= 3:
            logger.info("连续 %d 步无新信息，自动回溯", consecutive_no_info)
            return ReactResult(
                node_id=node.id,
                status="backtrack",
                steps=steps,
                reward=accumulated_reward,
            )

    # 步数耗尽
    return ReactResult(
        node_id=node.id,
        status="step_limit",
        steps=steps,
        reward=accumulated_reward,
    )


class ReactExecutorPool:
    """
    ReAct Agent 并发池

    控制同时运行的 ReAct Agent 数量，防止资源耗尽和目标过载。
    """

    def __init__(self, max_concurrent: int = 4):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.active_count = 0
        self.total_executed = 0

    async def execute_node(
        self,
        node: SearchNode,
        context: ExecutionContext,
        llm: LLMClient,
        max_steps: int = 8,
        steering_directives: list[str] | None = None,
    ) -> ReactResult:
        """在给定节点上执行 ReAct Agent（带并发控制）v2: +steering_directives"""
        async with self.semaphore:
            self.active_count += 1
            try:
                from .search_tree import NodeStatus
                node.status = NodeStatus.EXPLORING

                result = await react_agent_loop(
                    node, context, llm, max_steps,
                    steering_directives=steering_directives,
                )
                self.total_executed += 1

                # 更新节点状态 (v11: step_limit 不立即 exhaust)
                if result.status == "finding":
                    node.status = NodeStatus.CONFIRMED_VULN
                elif result.status in ("exhausted", "backtrack"):
                    node.status = NodeStatus.EXHAUSTED
                elif result.status == "step_limit":
                    node.status = NodeStatus.NEEDS_EXPANSION  # 步数耗尽但可能还有价值
                else:
                    node.status = NodeStatus.NEEDS_EXPANSION

                # 将步骤记录到节点状态
                node.state.reasoning_chain.extend(result.steps)

                return result
            except Exception as e:
                logger.error("ReactExecutorPool 执行异常 [%s]: %s", node.id, str(e))
                return ReactResult(
                    node_id=node.id,
                    status="error",
                    error=str(e),
                )
            finally:
                self.active_count -= 1

    async def execute_batch(
        self,
        nodes: list[SearchNode],
        context: ExecutionContext,
        llm: LLMClient,
        max_steps: int = 8,
        steering_directives: list[str] | None = None,
    ) -> list[ReactResult]:
        """并发执行一批节点 (v2: +steering_directives)"""
        tasks = [
            self.execute_node(node, context, llm, max_steps, steering_directives)
            for node in nodes
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error("批量执行异常 [%s]: %s", nodes[i].id, str(result))
                final_results.append(ReactResult(
                    node_id=nodes[i].id,
                    status="error",
                    error=str(result),
                ))
            else:
                final_results.append(result)

        return final_results

    def stats(self) -> dict:
        return {
            "active": self.active_count,
            "max_concurrent": self.max_concurrent,
            "total_executed": self.total_executed,
        }
