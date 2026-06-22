"""
Reporter 节点

LangGraph 图中的报告生成节点。负责：
1. 从黑板读取所有 findings、false_positives、目标画像
2. 使用 Jinja2 模板渲染完整的 Markdown 报告
3. 让 LLM 生成修复建议和总结
4. 将报告写入黑板 reports 槽位
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.agents.emit import emit
from app.agents.llm import LLMClient
from app.agents.state import SlotStatus, VulnHuntState

logger = logging.getLogger(__name__)

_llm_client: LLMClient | None = None

TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "templates"


def _get_llm_client() -> LLMClient:
    """获取或创建 LLM 客户端单例"""
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client


def _render_template(template_name: str, context: dict) -> str:
    """
    使用 Jinja2 渲染 Markdown 模板

    Args:
        template_name: 模板文件名（如 report_full.md）
        context: 模板上下文变量

    Returns:
        渲染后的 Markdown 字符串
    """
    from jinja2 import Environment, FileSystemLoader

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(template_name)
    return template.render(**context)


async def _generate_recommendations(findings: list, target_profile: dict) -> list[str]:
    """让 LLM 基于发现生成修复建议"""
    if not findings:
        return [
            "未发现确认漏洞，建议定期进行安全扫描",
            "持续关注 OWASP Top 10 漏洞类型",
            "加强代码审计和安全测试流程",
        ]

    findings_summary = []
    for f in findings:
        findings_summary.append({
            "type": f.type,
            "severity": f.severity,
            "title": f.title,
            "description": f.description[:200],
        })

    llm = _get_llm_client()
    messages = [
        {"role": "system", "content": (
            "你是一个安全顾问，请基于漏洞发现列表生成简洁的修复建议。\n"
            "每条建议一句话，最多返回 10 条。直接输出 JSON 数组格式 [\"建议1\", \"建议2\", ...]"
        )},
        {"role": "user", "content": (
            f"目标技术栈: {json.dumps(target_profile.get('tech_stack', []), ensure_ascii=False)}\n"
            f"发现漏洞:\n{json.dumps(findings_summary, ensure_ascii=False)}"
        )},
    ]

    try:
        response_text = await llm.call(agent="orchestrator", messages=messages)
        recommendations = json.loads(response_text)
        if isinstance(recommendations, list):
            return recommendations[:10]
    except Exception as e:
        logger.warning("生成修复建议失败: %s", str(e))

    return [
        f"修复发现的 {len(findings)} 个漏洞",
        "加强输入验证和输出编码",
        "实施最小权限原则",
    ]


async def reporter_node(state: VulnHuntState) -> dict:
    """
    报告生成节点

    收集黑板上的所有分析结果，渲染 Markdown 报告：
    1. 统计各严重级别漏洞数量
    2. 调用 LLM 生成修复建议
    3. 使用 Jinja2 模板渲染完整报告
    4. 将报告存入黑板
    """
    bb = state["blackboard"]
    task_id = state["task_id"]
    iteration = state["iteration_count"]

    logger.info("Reporter 启动 - 任务 [%s], 生成最终报告", task_id)

    events = []
    now = datetime.now(timezone.utc)

    await emit(task_id, "reporter", "agent_started", {"node": "reporter", "iteration": iteration})

    # 统计严重级别分布
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in bb.findings:
        sev = f.severity.lower() if hasattr(f, "severity") else "low"
        if sev in severity_counts:
            severity_counts[sev] += 1

    await emit(task_id, "reporter", "progress", {
        "content": f"统计完成: {len(bb.findings)} 漏洞, {len(bb.false_positives)} 误报",
        "step": "statistics",
    })

    # 生成修复建议
    await emit(task_id, "reporter", "thinking", {
        "content": "正在生成修复建议...",
    })
    recommendations = await _generate_recommendations(bb.findings, bb.target_profile)

    await emit(task_id, "reporter", "progress", {
        "content": f"生成了 {len(recommendations)} 条修复建议",
        "step": "recommendations",
    })

    # 准备模板上下文
    target_profile = bb.target_profile or {}
    attack_surface = bb.attack_surface or {}
    recon_data = target_profile.get("recon_data", {})
    task_config = state.get("task_config", {}) or {}

    # 构建 findings 的模板友好格式
    findings_data = []
    for f in bb.findings:
        findings_data.append({
            "title": f.title,
            "type": f.type,
            "severity": f.severity,
            "hypothesis_id": f.hypothesis_id,
            "description": f.description,
            "trigger_path": f.trigger_path,
            "payload": f.payload,
            "reproduction_steps": f.reproduction_steps,
            "evidence": f.evidence or {},
            "tool_used": f.evidence.get("tool_used") if f.evidence else None,
        })

    # 攻击面端点
    endpoints = attack_surface.get("endpoints", [])
    endpoint_strs = []
    for ep in endpoints[:20]:
        if isinstance(ep, dict):
            endpoint_strs.append(f"{ep.get('path', '')} ({ep.get('source', '')})")
        else:
            endpoint_strs.append(str(ep))

    template_context = {
        "task_id": task_id,
        "target_url": task_config.get("target_url", target_profile.get("base_url", "未知")),
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "iteration_count": iteration,
        "findings_count": len(bb.findings),
        "tested_count": len([h for h in bb.hypotheses if h.status in ("confirmed", "rejected")]),
        "false_positive_count": len(bb.false_positives),
        "severity_critical": severity_counts["critical"],
        "severity_high": severity_counts["high"],
        "severity_medium": severity_counts["medium"],
        "severity_low": severity_counts["low"],
        "tech_stack": ", ".join(target_profile.get("tech_stack", ["未知"])),
        "attack_surface_endpoints": endpoint_strs,
        "subdomains_count": len(recon_data.get("subdomains", [])),
        "open_ports": ", ".join(str(p) for p in recon_data.get("open_ports", [])[:20]) or "无",
        "findings": findings_data,
        "false_positives": bb.false_positives,
        "recommendations": recommendations,
    }

    # 渲染报告
    await emit(task_id, "reporter", "thinking", {
        "content": "正在渲染报告模板...",
    })

    try:
        report_md = _render_template("report_full.md", template_context)
    except Exception as e:
        logger.error("模板渲染失败: %s，使用简化报告", str(e))
        report_md = _generate_fallback_report(template_context)

    # 构建报告对象
    report = {
        "id": str(uuid.uuid4()),
        "task_id": task_id,
        "format": "markdown",
        "content": report_md,
        "generated_at": now.isoformat(),
        "findings_count": len(bb.findings),
        "severity_distribution": severity_counts,
    }

    bb.reports.append(report)
    bb.slot_status["reports"] = SlotStatus.READY
    bb.version += 1

    report_data = {
        "report_id": report["id"],
        "findings_count": len(bb.findings),
        "severity_distribution": severity_counts,
        "recommendations_count": len(recommendations),
    }
    await emit(task_id, "reporter", "report_generated", report_data)
    events.append({
        "id": str(uuid.uuid4()),
        "agent": "reporter",
        "type": "report_generated",
        "timestamp": now.isoformat(),
        "data": report_data,
    })

    logger.info(
        "报告生成完成: %d 个漏洞, %d 条建议, 报告长度 %d 字符",
        len(bb.findings),
        len(recommendations),
        len(report_md),
    )

    await emit(task_id, "reporter", "agent_stopped", {"node": "reporter"})

    return {
        "blackboard": bb,
        "current_phase": "done",
        "iteration_count": iteration,
        "events": events,
    }


def _generate_fallback_report(ctx: dict) -> str:
    """当模板渲染失败时生成简化的纯文本报告"""
    lines = [
        f"# Argus 漏洞挖掘报告",
        f"",
        f"**任务 ID**: {ctx['task_id']}",
        f"**目标**: {ctx['target_url']}",
        f"**生成时间**: {ctx['timestamp']}",
        f"",
        f"## 摘要",
        f"- 发现漏洞: {ctx['findings_count']}",
        f"- 误报数: {ctx['false_positive_count']}",
        f"",
    ]

    if ctx["findings"]:
        lines.append("## 漏洞列表")
        lines.append("")
        for i, f in enumerate(ctx["findings"], 1):
            lines.append(f"{i}. [{f['severity'].upper()}] {f['title']}")
        lines.append("")

    lines.append("---")
    lines.append("*由 Argus AI 漏洞挖掘系统自动生成*")

    return "\n".join(lines)
