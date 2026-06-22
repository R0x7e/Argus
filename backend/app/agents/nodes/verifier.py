"""
Verifier 节点

LangGraph 图中的漏洞验证节点。负责：
1. 读取黑板上的待验证假设
2. 使用实际安全工具（HTTP请求、SQLi检测、SSRF检测等）验证假设
3. 将 LLM 分析 + 工具验证结果结合，判断漏洞是否真实存在
4. 记录验证结果，更新黑板上的 findings 和 false_positives
5. 作为风控守门员，拒绝高危操作
"""

import json
import logging
import uuid
from datetime import datetime, timezone

from app.agents.emit import emit
from app.agents.llm import LLMClient
from app.agents.prompts.verifier import VERIFIER_SYSTEM_PROMPT
from app.agents.state import SlotStatus, VulnFinding, VulnHuntState
from app.tools.base import ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)

_llm_client: LLMClient | None = None


def _get_llm_client() -> LLMClient:
    """获取或创建 LLM 客户端单例"""
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client


def _build_execution_context(state: VulnHuntState) -> ExecutionContext:
    """从黑板状态构建工具执行上下文"""
    bb = state["blackboard"]
    target_profile = bb.target_profile or {}
    base_url = target_profile.get("base_url", "")

    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    host = parsed.hostname or "localhost"
    port = parsed.port

    # 构建允许的主机列表：主域名（含端口变体）
    allowed = [host]
    if port and port not in (80, 443):
        allowed.append(f"{host}:{port}")

    return ExecutionContext(
        task_id=state["task_id"],
        target_host=host,
        timeout=30,
        max_retries=2,
        allowed_hosts=allowed,
    )


async def _run_tool(tool_name: str, params: dict, context: ExecutionContext) -> dict:
    """
    安全地执行工具，捕获异常避免中断整体流程

    Returns:
        工具执行结果字典，失败时返回 {success: False, error: ...}
    """
    from app.tools import tool_registry

    tool = tool_registry.get(tool_name)
    if tool is None:
        return {"success": False, "error": f"工具 {tool_name} 未注册"}

    # MVP 阶段只允许 L0/L1 工具
    if tool.risk_level > RiskLevel.L1:
        return {"success": False, "error": f"工具 {tool_name} 风险等级 {tool.risk_level.name} 超出 MVP 允许范围"}

    try:
        result = await tool.execute(params, context)
        return result
    except Exception as e:
        logger.warning("工具 %s 执行异常: %s", tool_name, str(e))
        return {"success": False, "error": str(e)}


# 假设类型 → 推荐验证工具的映射
VERIFICATION_TOOLS: dict[str, list[dict]] = {
    "sql_injection": [
        {"tool": "sqli_detect", "param_key": "url"},
    ],
    "ssrf": [
        {"tool": "ssrf_detect", "param_key": "url"},
    ],
    "auth_bypass": [
        {"tool": "auth_test", "param_key": "url"},
    ],
    "xss": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "lfi": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "rce": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "idor": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "ssti": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "info_disclosure": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "open_redirect": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "path_traversal": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "file_upload": [
        {"tool": "http_request", "param_key": "url"},
    ],
}


async def _verify_with_tools(hyp, context: ExecutionContext, state: VulnHuntState) -> dict:
    """
    使用工具对假设进行实际验证

    根据假设类型选择合适的工具执行，返回工具验证结果。
    对于使用 http_request 的通用类型，构造特定 payload 探测。

    Returns:
        {tool_used: str, tool_result: dict, tool_verified: bool}
    """
    vuln_type = hyp.type.lower()
    tool_configs = VERIFICATION_TOOLS.get(vuln_type, [])

    # 获取目标 base URL（含端口）
    bb = state["blackboard"]
    target_profile = bb.target_profile or {}
    base_url = target_profile.get("base_url", f"http://{context.target_host}")

    # 从 trigger_path 提取目标 URL
    target_url = ""
    if hyp.trigger_path:
        target_url = hyp.trigger_path[0]
        if not target_url.startswith("http"):
            target_url = f"{base_url.rstrip('/')}{target_url if target_url.startswith('/') else '/' + target_url}"

    # 没有目标 URL 时，尝试从 supporting_evidence 提取
    if not target_url and hyp.supporting_evidence:
        for evidence in hyp.supporting_evidence:
            if isinstance(evidence, str) and ("http://" in evidence or "/" in evidence):
                candidate = evidence.strip()
                if not candidate.startswith("http"):
                    candidate = f"{base_url.rstrip('/')}{candidate if candidate.startswith('/') else '/' + candidate}"
                target_url = candidate
                break

    if not target_url:
        target_url = base_url

    if not tool_configs:
        tool_configs = [{"tool": "http_request", "param_key": "url"}]

    # 依次尝试推荐的工具
    for cfg in tool_configs:
        tool_name = cfg["tool"]
        params = {cfg["param_key"]: target_url}

        # 为专用工具添加额外参数
        if tool_name == "sqli_detect" and hyp.trigger_path and len(hyp.trigger_path) > 1:
            params["parameter"] = hyp.trigger_path[1]

        # 为 http_request 构造类型特定的探测请求
        if tool_name == "http_request":
            params = _build_http_probe_params(vuln_type, target_url, hyp)

        result = await _run_tool(tool_name, params, context)

        if result.get("success"):
            vulnerable = _evaluate_tool_result(vuln_type, tool_name, result)
            return {
                "tool_used": tool_name,
                "tool_result": result,
                "tool_verified": vulnerable,
            }

    return {"tool_used": None, "tool_result": None, "tool_verified": False}


def _build_http_probe_params(vuln_type: str, target_url: str, hyp) -> dict:
    """为 http_request 工具构造针对特定漏洞类型的探测参数"""
    params = {"url": target_url, "method": "GET", "follow_redirects": False}

    if vuln_type == "lfi" or vuln_type == "path_traversal":
        separator = "&" if "?" in target_url else "?"
        if "=" in target_url:
            base, _ = target_url.rsplit("=", 1)
            params["url"] = f"{base}=....//....//....//etc/passwd"
        else:
            params["url"] = f"{target_url}{separator}file=....//....//....//etc/passwd"

    elif vuln_type == "xss":
        separator = "&" if "?" in target_url else "?"
        if "=" in target_url:
            base, _ = target_url.rsplit("=", 1)
            params["url"] = f"{base}=<script>alert(1)</script>"
        else:
            params["url"] = f"{target_url}{separator}q=<script>alert(1)</script>"

    elif vuln_type == "ssti":
        separator = "&" if "?" in target_url else "?"
        if "=" in target_url:
            base, _ = target_url.rsplit("=", 1)
            params["url"] = f"{base}=${{7*7}}"
        else:
            params["url"] = f"{target_url}{separator}name=${{7*7}}"

    elif vuln_type == "open_redirect":
        separator = "&" if "?" in target_url else "?"
        params["url"] = f"{target_url}{separator}redirect=https://evil.com"

    elif vuln_type == "info_disclosure":
        pass

    elif vuln_type == "rce":
        separator = "&" if "?" in target_url else "?"
        if "=" in target_url:
            base, _ = target_url.rsplit("=", 1)
            params["url"] = f"{base}=;id"
        else:
            params["url"] = f"{target_url}{separator}cmd=id"

    return params


def _evaluate_tool_result(vuln_type: str, tool_name: str, result: dict) -> bool:
    """根据漏洞类型和工具结果判断是否确认漏洞"""
    if tool_name != "http_request":
        return result.get("vulnerable", False) or result.get("found", False)

    body = result.get("body", "") or ""
    status = result.get("status_code", 0)
    headers = result.get("headers", {}) or {}

    if vuln_type in ("lfi", "path_traversal"):
        indicators = ["root:", "/bin/bash", "/bin/sh", "daemon:", "[boot loader]", "[extensions]"]
        return any(ind in body for ind in indicators)

    elif vuln_type == "xss":
        return "<script>alert(1)</script>" in body

    elif vuln_type == "ssti":
        return "49" in body and "${7*7}" not in body

    elif vuln_type == "open_redirect":
        location = headers.get("location", "") or headers.get("Location", "")
        return "evil.com" in location or (status in (301, 302, 303, 307, 308) and "evil.com" in body)

    elif vuln_type == "rce":
        return "uid=" in body and "gid=" in body

    elif vuln_type == "info_disclosure":
        sensitive_patterns = ["password", "secret", "api_key", "token", "private_key",
                            "phpinfo()", "DOCUMENT_ROOT", "SERVER_ADDR"]
        return any(p.lower() in body.lower() for p in sensitive_patterns)

    return False


async def verifier_node(state: VulnHuntState) -> dict:
    """
    验证节点

    对黑板上所有 pending 状态的假设进行验证：
    1. 先用工具做实际验证
    2. 再用 LLM 综合工具结果和上下文做最终判断
    3. 将确认的漏洞写入 findings，误报写入 false_positives
    """
    bb = state["blackboard"]
    task_id = state["task_id"]
    iteration = state["iteration_count"]

    logger.info("Verifier 启动 - 任务 [%s], 迭代 %d", task_id, iteration)

    events = []
    context = _build_execution_context(state)

    await emit(task_id, "verifier", "agent_started", {"node": "verifier", "iteration": iteration})

    # 获取待验证假设
    pending = [h for h in bb.hypotheses if h.status == "pending"]

    if not pending:
        logger.info("没有待验证的假设，跳过验证阶段")
        await emit(task_id, "verifier", "no_pending", {"content": "没有待验证的假设"})
        events.append({
            "id": str(uuid.uuid4()),
            "agent": "verifier",
            "type": "no_pending",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"content": "没有待验证的假设"},
        })
        await emit(task_id, "verifier", "agent_stopped", {"node": "verifier"})
        return {
            "blackboard": bb,
            "current_phase": "verifying",
            "iteration_count": iteration + 1,
            "events": events,
        }

    logger.info("开始验证 %d 个假设", len(pending))
    start_data = {
        "pending_count": len(pending),
        "hypothesis_ids": [h.id for h in pending],
    }
    await emit(task_id, "verifier", "verification_start", start_data)
    events.append({
        "id": str(uuid.uuid4()),
        "agent": "verifier",
        "type": "verification_start",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": start_data,
    })

    llm = _get_llm_client()

    for hyp in pending:
        hyp.status = "testing"

        # === 第一步：工具验证 ===
        await emit(task_id, "verifier", "tool_call", {
            "tool_name": f"verify_{hyp.type}",
            "params": {"hypothesis_id": hyp.id, "type": hyp.type},
        })

        tool_result = await _verify_with_tools(hyp, context, state)

        tool_event_data = {
            "hypothesis_id": hyp.id,
            "tool_used": tool_result["tool_used"],
            "tool_verified": tool_result["tool_verified"],
        }
        await emit(task_id, "verifier", "tool_result", {
            "tool_name": tool_result["tool_used"] or "none",
            "success": tool_result["tool_verified"],
            "summary": f"假设 {hyp.type}: {'工具确认漏洞' if tool_result['tool_verified'] else '未确认'}",
        })
        events.append({
            "id": str(uuid.uuid4()),
            "agent": "verifier",
            "type": "tool_verification",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": tool_event_data,
        })

        # === 第二步：LLM 综合判断 ===
        await emit(task_id, "verifier", "thinking", {
            "content": f"综合分析假设 {hyp.type} 的工具验证结果...",
        })

        hyp_context = {
            "hypothesis_id": hyp.id,
            "type": hyp.type,
            "description": hyp.description,
            "trigger_path": hyp.trigger_path,
            "preconditions": hyp.preconditions,
            "expected_impact": hyp.expected_impact,
            "confidence": hyp.confidence,
            "supporting_evidence": hyp.supporting_evidence,
            "tool_verification": {
                "tool_used": tool_result["tool_used"],
                "tool_verified": tool_result["tool_verified"],
                "tool_output": tool_result["tool_result"],
            },
        }

        messages = [
            {"role": "system", "content": VERIFIER_SYSTEM_PROMPT},
            {"role": "user", "content": (
                f"请综合工具验证结果和假设信息，做出最终判断：\n\n"
                f"{json.dumps(hyp_context, ensure_ascii=False, default=str)}\n\n"
                f"注意：tool_verified=true 表示工具已实际检测到漏洞存在。\n"
                f"请输出 JSON 格式的验证结果。"
            )},
        ]

        response_text = await llm.call(agent="verifier", messages=messages)
        result = _parse_verifier_response(response_text)

        # 最终判断: 工具确认 OR LLM 判断
        verified = tool_result["tool_verified"] or result.get("verified", False)
        severity = result.get("severity", "low")

        if verified:
            hyp.status = "confirmed"
            finding = VulnFinding(
                id=str(uuid.uuid4()),
                hypothesis_id=hyp.id,
                type=hyp.type,
                severity=severity,
                title=f"[{severity.upper()}] {hyp.type} - {hyp.description[:60]}",
                description=hyp.description,
                trigger_path=hyp.trigger_path,
                payload=hyp.supporting_evidence[0] if hyp.supporting_evidence else "",
                reproduction_steps=result.get("reproduction_steps", hyp.trigger_path),
                evidence={
                    "llm_analysis": result.get("evidence", {}),
                    "tool_output": tool_result["tool_result"],
                    "tool_used": tool_result["tool_used"],
                },
                verified=True,
            )
            bb.findings.append(finding)

            confirmed_data = {
                "hypothesis_id": hyp.id,
                "finding_id": finding.id,
                "type": hyp.type,
                "severity": severity,
                "verified_by_tool": tool_result["tool_verified"],
            }
            await emit(task_id, "verifier", "finding_confirmed", confirmed_data)
            events.append({
                "id": str(uuid.uuid4()),
                "agent": "verifier",
                "type": "finding_confirmed",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": confirmed_data,
            })
            logger.info("漏洞确认: [%s] %s (严重级别: %s)", hyp.id, hyp.type, severity)
        else:
            hyp.status = "rejected"
            fp_reason = result.get("false_positive_reason", "验证未通过")
            bb.false_positives.append({
                "hypothesis_id": hyp.id,
                "reason": fp_reason,
            })
            fp_data = {"hypothesis_id": hyp.id, "reason": fp_reason}
            await emit(task_id, "verifier", "false_positive", fp_data)
            events.append({
                "id": str(uuid.uuid4()),
                "agent": "verifier",
                "type": "false_positive",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": fp_data,
            })
            logger.info("假设否决: [%s] %s", hyp.id, hyp.type)

    # 更新黑板
    bb.slot_status["findings"] = SlotStatus.READY if bb.findings else SlotStatus.EMPTY
    bb.version += 1

    complete_data = {
        "findings_count": len(bb.findings),
        "false_positives_count": len(bb.false_positives),
    }
    await emit(task_id, "verifier", "verification_complete", complete_data)
    events.append({
        "id": str(uuid.uuid4()),
        "agent": "verifier",
        "type": "verification_complete",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": complete_data,
    })

    logger.info("Verifier 完成: %d 个发现, %d 个误报", len(bb.findings), len(bb.false_positives))

    await emit(task_id, "verifier", "agent_stopped", {"node": "verifier"})

    return {
        "blackboard": bb,
        "current_phase": "verifying",
        "iteration_count": iteration + 1,
        "events": events,
    }


def _parse_verifier_response(response_text: str) -> dict:
    """解析 Verifier LLM 响应为字典，解析失败返回安全默认值"""
    try:
        result = json.loads(response_text)
        if isinstance(result, dict):
            return result
    except json.JSONDecodeError:
        pass

    try:
        start = response_text.find("{")
        end = response_text.rfind("}") + 1
        if start >= 0 and end > start:
            result = json.loads(response_text[start:end])
            if isinstance(result, dict):
                return result
    except json.JSONDecodeError:
        pass

    logger.warning("无法解析 Verifier 响应，使用默认结果: %s", response_text[:200])
    return {
        "verified": False,
        "risk_level": "L0",
        "severity": "low",
        "evidence": {},
        "reproduction_steps": [],
        "false_positive_reason": "响应解析失败",
    }
