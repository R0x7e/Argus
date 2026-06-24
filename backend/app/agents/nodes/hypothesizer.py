"""
Hypothesizer 节点

LangGraph 图中的假设生成节点。负责：
1. 读取黑板上的目标画像和攻击面信息
2. 调用 LLM 生成可测试的漏洞假设
3. 将假设写入黑板，更新槽位状态
"""

import json
import logging
import uuid
from datetime import datetime, timezone

from app.agents.emit import emit
from app.agents.llm import LLMClient
from app.agents.prompts.hypothesizer import HYPOTHESIZER_SYSTEM_PROMPT
from app.agents.state import Hypothesis, SlotStatus, VulnHuntState

logger = logging.getLogger(__name__)

# 模块级 LLM 客户端
_llm_client: LLMClient | None = None


def _get_llm_client() -> LLMClient:
    """获取或创建 LLM 客户端单例"""
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client


async def hypothesizer_node(state: VulnHuntState) -> dict:
    """
    假设生成节点

    基于目标画像和攻击面分析，生成一批可测试的漏洞假设。
    """
    bb = state["blackboard"]
    task_id = state["task_id"]

    logger.info("Hypothesizer 启动 - 任务 [%s]", task_id)

    events = []

    await emit(task_id, "hypothesizer", "agent_started", {"node": "hypothesizer"})

    # 构建上下文 — 使用 type+endpoint 去重而非纯 type
    existing_entries = [
        f"{h.type}@{h.trigger_path[0] if h.trigger_path else ''}" for h in bb.hypotheses
    ]
    existing_types = list(set(h.type for h in bb.hypotheses))
    rejected_types = [h.type for h in bb.rejected_hypotheses] if bb.rejected_hypotheses else []

    context = {
        "target_profile": bb.target_profile,
        "attack_surface": bb.attack_surface,
        "tech_fingerprint": bb.tech_fingerprint,
        "existing_hypotheses": existing_entries,
        "existing_hypothesis_types": existing_types,
        "rejected_hypothesis_types": rejected_types,
        "findings_so_far": len(bb.findings),
    }

    # Extract concrete params and forms for the LLM to use
    attack_surface = bb.attack_surface or {}
    available_params = attack_surface.get("parameters", [])[:30]
    available_forms = attack_surface.get("forms", [])[:15]
    available_endpoints = attack_surface.get("endpoints", [])[:30]

    messages = [
        {"role": "system", "content": HYPOTHESIZER_SYSTEM_PROMPT},
        {"role": "user", "content": (
            f"请基于以下目标信息生成漏洞假设：\n\n"
            f"目标画像: {json.dumps(bb.target_profile, ensure_ascii=False, default=str)}\n\n"
            f"已发现的可注入参数（高优先级）:\n"
            f"{json.dumps(available_params, ensure_ascii=False)}\n\n"
            f"已发现的表单（高优先级）:\n"
            f"{json.dumps(available_forms, ensure_ascii=False)}\n\n"
            f"已发现的端点:\n"
            f"{json.dumps(available_endpoints, ensure_ascii=False)}\n\n"
            f"注意：\n"
            f"- 已存在以下假设（type@endpoint）: {existing_entries[:20]}\n"
            f"- 同一漏洞类型可以对不同端点/参数生成多个假设，但不要对同一端点+参数重复\n"
            f"- 以下类型已被否决，需要更充分的证据才重新生成: {rejected_types}\n"
            f"- trigger_path[0] 必须带参数（如 /search?q=test），trigger_path[1] 为参数名\n"
            f"- 优先为上述「可注入参数」和「表单」生成假设\n"
            f"- 请输出 JSON 数组格式的假设列表。"
        )},
    ]

    await emit(task_id, "hypothesizer", "thinking", {
        "content": f"基于攻击面分析生成漏洞假设，已排除类型: {existing_types[:5]}",
    })

    # 调用 LLM
    llm = _get_llm_client()
    response_text = await llm.call(agent="hypothesizer", messages=messages, task_id=task_id)

    # 解析响应为假设列表
    raw_hypotheses = _parse_hypothesizer_response(response_text)

    # 转换为 Hypothesis 对象，按 type+endpoint 去重
    existing_keys = set(existing_entries)
    new_hypotheses = []
    for raw in raw_hypotheses:
        confidence = float(raw.get("confidence", 0.0))
        if confidence < 0.3:
            continue

        trigger_path = raw.get("trigger_path", [])
        dedup_key = f"{raw.get('type', 'unknown')}@{trigger_path[0] if trigger_path else ''}"
        if dedup_key in existing_keys:
            continue
        existing_keys.add(dedup_key)

        hyp = Hypothesis(
            id=str(uuid.uuid4()),
            type=raw.get("type", "unknown"),
            description=raw.get("description", ""),
            trigger_path=trigger_path,
            preconditions=raw.get("preconditions", []),
            expected_impact=raw.get("expected_impact", ""),
            confidence=confidence,
            supporting_evidence=raw.get("supporting_evidence", raw.get("payloads", [])),
            status="pending",
        )
        new_hypotheses.append(hyp)

    # 更新黑板
    bb.hypotheses.extend(new_hypotheses)
    bb.slot_status["hypotheses"] = SlotStatus.READY if new_hypotheses else SlotStatus.EMPTY
    bb.version += 1

    # 记录事件
    hyp_data = {
        "count": len(new_hypotheses),
        "types": [h.type for h in new_hypotheses],
        "confidences": [h.confidence for h in new_hypotheses],
    }
    await emit(task_id, "hypothesizer", "hypotheses_generated", hyp_data)
    events.append({
        "id": str(uuid.uuid4()),
        "agent": "hypothesizer",
        "type": "hypotheses_generated",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": hyp_data,
    })

    await emit(task_id, "hypothesizer", "progress", {
        "content": f"生成了 {len(new_hypotheses)} 个假设: {[h.type for h in new_hypotheses]}",
        "step": "hypothesis_generation",
    })

    logger.info(
        "Hypothesizer 生成了 %d 个假设 (类型: %s)",
        len(new_hypotheses),
        [h.type for h in new_hypotheses],
    )

    await emit(task_id, "hypothesizer", "agent_stopped", {"node": "hypothesizer"})

    return {
        "blackboard": bb,
        "current_phase": "verifying",
        "events": events,
    }


def _parse_hypothesizer_response(response_text: str) -> list[dict]:
    """
    解析 Hypothesizer LLM 响应为假设列表

    尝试从响应文本中提取 JSON 数组。如果解析失败，返回空列表。

    Args:
        response_text: LLM 原始响应文本

    Returns:
        假设字典列表
    """
    # 尝试直接解析为 JSON 数组
    try:
        result = json.loads(response_text)
        if isinstance(result, list):
            return result
        # 如果是单个对象，包装成列表
        if isinstance(result, dict):
            return [result]
    except json.JSONDecodeError:
        pass

    # 尝试从文本中提取 JSON 数组（处理 markdown 代码块）
    try:
        start = response_text.find("[")
        end = response_text.rfind("]") + 1
        if start >= 0 and end > start:
            result = json.loads(response_text[start:end])
            if isinstance(result, list):
                return result
    except json.JSONDecodeError:
        pass

    logger.warning("无法解析 Hypothesizer 响应，返回空列表: %s", response_text[:200])
    return []
