"""
工具层单元测试

验证工具注册、风险等级、输入校验和 Payload 变异器逻辑。
"""

import pytest
from pydantic import ValidationError

from app.tools.base import BaseTool, ExecutionContext, RiskLevel, ToolRegistry
from app.tools.payload_mutator import PayloadMutatorTool


@pytest.fixture
def context():
    """创建测试用执行上下文"""
    return ExecutionContext(
        task_id="test-task",
        target_host="example.com",
        allowed_hosts=["example.com"],
    )


class TestExecutionContext:
    """ExecutionContext 类型安全测试"""

    def test_valid_construction(self):
        """合法参数应成功构造"""
        ctx = ExecutionContext(
            task_id="task-1",
            target_host="example.com",
        )
        assert ctx.task_id == "task-1"
        assert ctx.target_host == "example.com"
        assert ctx.timeout == 30
        assert ctx.max_retries == 2
        assert ctx.allowed_hosts == []

    def test_full_construction(self):
        """全参数构造"""
        ctx = ExecutionContext(
            task_id="task-1",
            target_host="example.com",
            timeout=60,
            max_retries=5,
            allowed_hosts=["example.com", "test.com"],
        )
        assert ctx.timeout == 60
        assert ctx.max_retries == 5
        assert len(ctx.allowed_hosts) == 2

    def test_rejects_unknown_field(self):
        """传入未定义字段时应抛出 ValidationError"""
        with pytest.raises(ValidationError):
            ExecutionContext(
                task_id="task-1",
                target_host="example.com",
                auth_headers={},  # 不存在的字段
            )

    def test_rejects_multiple_unknown_fields(self):
        """多个未定义字段也应被拒绝"""
        with pytest.raises(ValidationError):
            ExecutionContext(
                task_id="task-1",
                target_host="example.com",
                cookies={},
                auth_token="",
            )

    def test_missing_required_field(self):
        """缺少必填字段应抛出 ValidationError"""
        with pytest.raises(ValidationError):
            ExecutionContext(target_host="example.com")


class TestRiskLevel:
    """风险等级测试"""

    def test_risk_level_ordering(self):
        assert RiskLevel.L0 < RiskLevel.L1
        assert RiskLevel.L1 < RiskLevel.L2
        assert RiskLevel.L2 < RiskLevel.L3

    def test_risk_level_values(self):
        assert RiskLevel.L0.value == 0
        assert RiskLevel.L3.value == 3


class TestToolRegistry:
    """工具注册表测试"""

    def test_register_and_get(self):
        registry = ToolRegistry()
        tool = PayloadMutatorTool()
        registry.register(tool)
        retrieved = registry.get(tool.name)
        assert retrieved is tool

    def test_get_unknown_raises_keyerror(self):
        registry = ToolRegistry()
        with pytest.raises(KeyError):
            registry.get("nonexistent_tool")

    def test_list_tools(self):
        registry = ToolRegistry()
        tool = PayloadMutatorTool()
        registry.register(tool)
        tools = registry.list_tools()
        assert len(tools) >= 1
        assert any(t.name == "payload_mutate" for t in tools)


class TestPayloadMutator:
    """Payload 变异器测试"""

    @pytest.fixture
    def mutator(self):
        return PayloadMutatorTool()

    @pytest.mark.asyncio
    async def test_url_encode(self, mutator, context):
        result = await mutator.execute(
            {"payload": "<script>alert(1)</script>", "techniques": ["url_encode"]},
            context,
        )
        assert result["success"] is True
        assert len(result["variants"]) == 1
        assert "%3C" in result["variants"][0]["payload"]

    @pytest.mark.asyncio
    async def test_base64_encode(self, mutator, context):
        result = await mutator.execute(
            {"payload": "test_payload", "techniques": ["base64_encode"]},
            context,
        )
        assert result["success"] is True
        assert result["variants"][0]["technique"] == "base64_encode"

    @pytest.mark.asyncio
    async def test_multiple_techniques(self, mutator, context):
        result = await mutator.execute(
            {
                "payload": "' OR 1=1 --",
                "techniques": ["url_encode", "double_encode", "base64_encode"],
            },
            context,
        )
        assert result["success"] is True
        assert result["count"] == 3

    @pytest.mark.asyncio
    async def test_all_techniques(self, mutator, context):
        result = await mutator.execute(
            {"payload": "<img src=x onerror=alert(1)>"},
            context,
        )
        assert result["success"] is True
        assert result["count"] == 8

    @pytest.mark.asyncio
    async def test_empty_payload(self, mutator, context):
        result = await mutator.execute(
            {"payload": ""},
            context,
        )
        assert result["success"] is False
