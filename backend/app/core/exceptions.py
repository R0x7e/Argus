"""
Argus 自定义异常模块

定义系统中所有业务异常类，统一错误处理。
"""


class ArgusBaseError(Exception):
    """Argus 系统基础异常类，所有自定义异常的父类"""

    def __init__(self, message: str = "系统内部错误", code: str = "INTERNAL_ERROR") -> None:
        self.message = message
        self.code = code
        super().__init__(self.message)


class TaskNotFoundError(ArgusBaseError):
    """任务未找到异常"""

    def __init__(self, task_id: str) -> None:
        super().__init__(
            message=f"任务不存在: {task_id}",
            code="TASK_NOT_FOUND",
        )
        self.task_id = task_id


class TaskStateError(ArgusBaseError):
    """任务状态转换异常（非法的状态变更）"""

    def __init__(self, current_state: str, target_state: str) -> None:
        super().__init__(
            message=f"任务状态转换非法: {current_state} -> {target_state}",
            code="TASK_STATE_ERROR",
        )
        self.current_state = current_state
        self.target_state = target_state


class AgentError(ArgusBaseError):
    """Agent 执行异常"""

    def __init__(self, agent_name: str, message: str = "Agent 执行失败") -> None:
        super().__init__(
            message=f"Agent [{agent_name}] 错误: {message}",
            code="AGENT_ERROR",
        )
        self.agent_name = agent_name


class BudgetExceededError(ArgusBaseError):
    """预算超限异常（API 调用费用超出限制）"""

    def __init__(self, budget_limit: float, current_cost: float) -> None:
        super().__init__(
            message=f"预算超限: 限额 ${budget_limit:.2f}, 当前消耗 ${current_cost:.2f}",
            code="BUDGET_EXCEEDED",
        )
        self.budget_limit = budget_limit
        self.current_cost = current_cost


class ToolExecutionError(ArgusBaseError):
    """工具执行异常（外部工具调用失败）"""

    def __init__(self, tool_name: str, message: str = "工具执行失败") -> None:
        super().__init__(
            message=f"工具 [{tool_name}] 执行错误: {message}",
            code="TOOL_EXECUTION_ERROR",
        )
        self.tool_name = tool_name


class SandboxError(ArgusBaseError):
    """沙箱异常（沙箱环境创建或执行失败）"""

    def __init__(self, message: str = "沙箱操作失败") -> None:
        super().__init__(
            message=f"沙箱错误: {message}",
            code="SANDBOX_ERROR",
        )
