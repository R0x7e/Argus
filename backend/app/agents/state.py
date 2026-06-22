"""
Agent 状态管理模块

定义 Blackboard（黑板）数据结构和 LangGraph 状态类型。
黑板是所有 Agent 共享的中央数据结构，用于信息传递和协调。
"""

import operator
from dataclasses import dataclass, field
from enum import Enum
from typing import Annotated, TypedDict


class SlotStatus(str, Enum):
    """黑板槽位状态枚举"""

    EMPTY = "empty"      # 槽位为空，尚未填充数据
    PARTIAL = "partial"  # 槽位部分填充，数据不完整
    READY = "ready"      # 槽位数据就绪，可供下游使用
    STALE = "stale"      # 槽位数据过时，需要刷新


@dataclass
class Hypothesis:
    """
    漏洞假设

    由 Hypothesizer Agent 生成，描述一个待验证的漏洞可能性。
    包含漏洞类型、触发路径、前置条件和置信度等信息。
    """

    id: str                          # 假设唯一标识
    type: str                        # 漏洞类型: ssrf, sql_injection, xss, auth_bypass 等
    description: str                 # 假设描述
    trigger_path: list[str]          # 触发路径（请求链）
    preconditions: list[str]         # 前置条件列表
    expected_impact: str             # 预期影响描述
    confidence: float                # 置信度 (0.0 ~ 1.0)
    supporting_evidence: list[str]   # 支撑证据列表
    status: str = "pending"          # 状态: pending, testing, confirmed, rejected


@dataclass
class VulnFinding:
    """
    漏洞发现

    由 Verifier Agent 确认后生成，描述一个已验证的漏洞。
    包含复现步骤、载荷、证据等完整信息。
    """

    id: str                          # 发现唯一标识
    hypothesis_id: str               # 关联的假设 ID
    type: str                        # 漏洞类型
    severity: str                    # 严重级别: critical, high, medium, low
    title: str                       # 漏洞标题
    description: str                 # 漏洞详细描述
    trigger_path: list[str]          # 触发路径
    payload: str                     # 攻击载荷
    reproduction_steps: list[str]    # 复现步骤
    evidence: dict                   # 证据（状态码、响应差异、时序等）
    verified: bool = False           # 是否经过二次验证


@dataclass
class Blackboard:
    """
    黑板 —— Agent 间共享的中央数据结构

    所有 Agent 通过读写黑板上的槽位来协调工作。
    槽位按功能分为：侦察、假设、验证、报告、控制五大类。
    """

    task_id: str                     # 关联任务 ID
    version: int = 0                 # 黑板版本号（每次写入递增）

    # ---- 侦察槽 ----
    target_profile: dict = field(default_factory=dict)     # 目标画像（技术栈、架构等）
    attack_surface: dict = field(default_factory=dict)     # 攻击面分析（端点、参数等）
    tech_fingerprint: dict = field(default_factory=dict)   # 技术指纹识别结果

    # ---- 假设槽 ----
    hypotheses: list = field(default_factory=list)           # 待验证假设列表
    rejected_hypotheses: list = field(default_factory=list)  # 已否决假设列表

    # ---- 验证槽 ----
    findings: list = field(default_factory=list)           # 已确认漏洞列表
    false_positives: list = field(default_factory=list)    # 误报记录列表

    # ---- 报告槽 ----
    reports: list = field(default_factory=list)            # 生成的报告列表

    # ---- 控制槽 ----
    steering_directives: list = field(default_factory=list)  # 调度指令列表
    active_agents: list = field(default_factory=list)        # 当前活跃 Agent 列表

    # ---- 元信息 ----
    slot_status: dict = field(default_factory=dict)  # 各槽位状态 {slot_name: SlotStatus}
    error_log: list = field(default_factory=list)    # 错误日志


class VulnHuntState(TypedDict):
    """
    LangGraph 状态定义

    作为 LangGraph StateGraph 的状态类型，每个节点接收并返回此结构的部分更新。
    events 字段使用 Annotated[list, operator.add] 实现消息累积语义。
    """

    blackboard: Blackboard           # 共享黑板
    current_phase: str               # 当前阶段: profiling, hypothesizing, verifying, reporting, done
    iteration_count: int             # 当前迭代计数
    max_iterations: int              # 最大迭代次数
    task_id: str                     # 任务 ID
    task_config: dict                # 任务配置（target_url, task_type 等）
    events: Annotated[list, operator.add]  # 累积事件列表（每次运行自动合并）
