"""
Agent 系统提示词模块

导出所有 Agent 的系统提示词，用于 LLM 调用时的角色设定。
所有提示词使用中文撰写，符合 Argus 系统的设计规范。
"""

from app.agents.prompts.hypothesizer import HYPOTHESIZER_SYSTEM_PROMPT
from app.agents.prompts.orchestrator import ORCHESTRATOR_SYSTEM_PROMPT
from app.agents.prompts.verifier import VERIFIER_SYSTEM_PROMPT

__all__ = [
    "ORCHESTRATOR_SYSTEM_PROMPT",
    "HYPOTHESIZER_SYSTEM_PROMPT",
    "VERIFIER_SYSTEM_PROMPT",
]
