"""
Agent 系统单元测试

验证黑板模型、状态图构建、路由逻辑和 Token 预算管理。
"""

import pytest

from app.agents.state import Blackboard, Hypothesis, SlotStatus, VulnFinding, VulnHuntState
from app.agents.routing import route_from_orchestrator
from app.agents.graph import create_initial_state
from app.agents.token_budget import TokenBudget
from app.agents.model_router import ModelRouter


class TestBlackboard:
    """黑板数据结构测试"""

    def test_create_empty_blackboard(self):
        bb = Blackboard(task_id="test-123")
        assert bb.task_id == "test-123"
        assert bb.version == 0
        assert bb.hypotheses == []
        assert bb.findings == []

    def test_add_hypothesis(self):
        bb = Blackboard(task_id="test-123")
        hyp = Hypothesis(
            id="h1",
            type="sql_injection",
            description="SQL注入假设",
            trigger_path=["/api/users?id=1"],
            preconditions=["参数直接拼接SQL"],
            expected_impact="数据泄露",
            confidence=0.8,
            supporting_evidence=["参数无过滤"],
        )
        bb.hypotheses.append(hyp)
        assert len(bb.hypotheses) == 1
        assert bb.hypotheses[0].type == "sql_injection"

    def test_add_finding(self):
        finding = VulnFinding(
            id="f1",
            hypothesis_id="h1",
            type="sql_injection",
            severity="high",
            title="SQL注入漏洞",
            description="用户ID参数存在SQL注入",
            trigger_path=["/api/users?id=1"],
            payload="1' OR '1'='1",
            reproduction_steps=["发送带payload的请求"],
            evidence={"status_code": 200, "time_diff": 5.2},
        )
        assert finding.verified is False
        assert finding.severity == "high"


class TestRouting:
    """路由逻辑测试"""

    def test_route_to_end_on_max_iterations(self):
        state: VulnHuntState = {
            "blackboard": Blackboard(task_id="test"),
            "current_phase": "hypothesizing",
            "iteration_count": 3,
            "max_iterations": 3,
            "task_id": "test",
            "events": [],
        }
        result = route_from_orchestrator(state)
        assert result == "reporter"

    def test_route_to_hypothesizer(self):
        state: VulnHuntState = {
            "blackboard": Blackboard(task_id="test"),
            "current_phase": "profiling",
            "iteration_count": 0,
            "max_iterations": 3,
            "task_id": "test",
            "events": [],
        }
        result = route_from_orchestrator(state)
        assert result == "hypothesizer"

    def test_route_to_end_on_reporting_phase(self):
        state: VulnHuntState = {
            "blackboard": Blackboard(task_id="test"),
            "current_phase": "reporting",
            "iteration_count": 1,
            "max_iterations": 3,
            "task_id": "test",
            "events": [],
        }
        result = route_from_orchestrator(state)
        assert result == "reporter"


class TestInitialState:
    """初始状态创建测试"""

    def test_create_initial_state(self):
        config = {
            "base_url": "https://target.com",
            "target_type": "web",
            "auth": {"type": "bearer", "token": "xxx"},
            "scope": {"include": ["/*"]},
        }
        state = create_initial_state("task-001", config, max_iterations=5)

        assert state["task_id"] == "task-001"
        assert state["max_iterations"] == 5
        assert state["iteration_count"] == 0
        assert state["current_phase"] == "initializing"
        assert state["blackboard"].target_profile["base_url"] == "https://target.com"

    def test_default_max_iterations(self):
        state = create_initial_state("task-002", {})
        assert state["max_iterations"] == 8


class TestTokenBudget:
    """Token 预算管理测试"""

    def test_initial_budget(self):
        budget = TokenBudget(task_id="t1", total_budget=100000)
        assert budget.remaining() == 100000
        assert budget.spent == 0

    def test_consume_tokens(self):
        budget = TokenBudget(task_id="t1", total_budget=100000)
        budget.consume("orchestrator", 10000, 5000)
        assert budget.spent == 15000
        assert budget.remaining() == 85000

    def test_per_agent_tracking(self):
        budget = TokenBudget(task_id="t1", total_budget=100000)
        budget.consume("orchestrator", 5000, 3000)
        budget.consume("hypothesizer", 8000, 4000)
        assert budget.per_agent["orchestrator"]["total"] == 8000
        assert budget.per_agent["hypothesizer"]["total"] == 12000

    def test_remaining_ratio(self):
        budget = TokenBudget(task_id="t1", total_budget=100000)
        budget.consume("orchestrator", 25000, 25000)
        assert budget.remaining_ratio() == 0.5

    def test_is_exceeded(self):
        budget = TokenBudget(task_id="t1", total_budget=1000)
        assert not budget.is_exceeded()
        budget.consume("orchestrator", 600, 500)
        assert budget.is_exceeded()

    def test_get_summary(self):
        budget = TokenBudget(task_id="t1", total_budget=100000)
        budget.consume("orchestrator", 10000, 5000)
        summary = budget.get_summary()
        assert summary["task_id"] == "t1"
        assert summary["spent"] == 15000
        assert summary["remaining"] == 85000


class TestModelRouter:
    """模型路由测试"""

    def test_default_model_is_sonnet(self):
        router = ModelRouter()
        model = router.select_model("orchestrator")
        assert "sonnet" in model

    def test_fallback_on_low_budget(self):
        router = ModelRouter()
        model = router.select_model("hypothesizer", budget_remaining_ratio=0.1)
        assert "haiku" in model

    def test_primary_on_sufficient_budget(self):
        router = ModelRouter()
        model = router.select_model("verifier", budget_remaining_ratio=0.5)
        assert "sonnet" in model

    def test_unknown_agent_uses_default(self):
        router = ModelRouter()
        model = router.select_model("unknown_agent")
        assert "sonnet" in model or "haiku" in model
