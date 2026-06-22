# AI SRC 漏洞挖掘多 Agent 系统 - 完整设计文档

> 版本: v2.0  
> 最后更新: 2026-06-22  
> 适用对象: 研发团队、安全研究员、架构师  

---

## 目录

1. [项目概述](#1-项目概述)
2. [系统总体架构](#2-系统总体架构)
3. [Agent 系统设计](#3-agent-系统设计)
   - 3.1-3.9 Agent 定义与事件协议
   - 3.10 黑板模型与 Agent 协调机制
   - 3.11 Temporal 工作流定义
   - 3.12 LLM 调用策略
   - 3.13 错误处理与恢复机制
   - 3.14 Agent 事件协议
4. [工具与集成层](#4-工具与集成层)
5. [知识库与记忆层](#5-知识库与记忆层)
   - 5.1-5.4 存储设计
   - 5.5 知识库冷启动与数据治理
6. [Web 控制端设计](#6-web-控制端设计)
   - 6.1-6.6 核心模块、API、Schema、部署
   - 6.7 前端状态管理与实时通信
7. [安全与合规](#7-安全与合规)
   - 7.1-7.4 多层防御、风控、合规
   - 7.5 密钥与凭据管理
8. [性能与可扩展性](#8-性能与可扩展性)
   - 8.1-8.4 并发、资源、指标、扩展
   - 8.5 成本估算与控制
   - 8.6 可观测性设计
   - 8.7 数据备份与灾难恢复
   - 8.8 多租户设计
9. [实施路线](#9-实施路线)
   - 9.1-9.3 阶段规划、里程碑、团队
   - 9.4 测试策略
10. [附录](#10-附录)
    - 10.1-10.4 配置示例、Prompt、决策记录、风险
    - 10.5 并发控制设计
    - 10.6 验收清单

---

## 1. 项目概述

### 1.1 项目背景

SRC(Security Response Center,安全响应中心)是各大厂商用于接收外部安全研究员提交漏洞的渠道。传统白帽子依赖经验与手工测试,效率受限于个人能力与时间。引入多 Agent 协作系统,目标是把漏洞挖掘从"个人技艺"升级为"可规模化、可复制的工程化能力"。

### 1.2 设计目标

- **强**:在 5-8 个高价值漏洞类型上达到专家级水平(SSRF、越权、未授权访问、SQL 注入、逻辑漏洞、反序列化、客户端 RCE、LLM 应用自身漏洞)
- **灵活**:支持不同目标类型(Web / 移动 / API / 二进制 / LLM 应用),支持人工中途介入与改向
- **可观测**:全流程可视化、可重放、可复盘
- **可控**:严格的风控机制,避免对授权目标的生产环境造成破坏
- **可持续**:跨任务沉淀经验,持续进化

### 1.3 核心创新点

| 创新点                  | 说明                             |
| -------------------- | ------------------------------ |
| 黑板 + 动态小组模型          | 替代传统流水线,允许侦察、假设、验证之间形成反馈循环     |
| Hypothesizer Debate  | 两个假设器实例互相挑战,提升假设质量,过滤掉明显不靠谱的方向 |
| Adversarial Verifier | 同一角色同时承担"漏洞验证"和"风控守门员"双重职责     |
| Steering 协议          | 任意时刻人工可注入指令、改写 Agent 行为、改换方向   |
| 跨任务知识沉淀              | 每次任务结束后自动提炼经验,反例与绕过模式入库        |

### 1.4 名词定义

| 名词              | 定义                               |
| --------------- | -------------------------------- |
| Agent           | 具有独立推理与工具调用能力的智能体                |
| Task            | 一次完整的漏洞挖掘任务,包含目标、范围、配置           |
| Event           | Agent 执行过程中的原子事件(思考、工具调用、决策、发现等) |
| Sandbox         | 隔离的执行环境,运行工具调用                   |
| Knowledge Graph | 攻击面图谱,记录资产之间的关系                  |
| Hypothesis      | 漏洞假设,描述可能存在的漏洞及触发路径              |
| Payload         | 漏洞利用的测试载荷                        |
| Finding         | 已验证的漏洞发现                         |
| Report          | 漏洞报告,SRC 提交用                     |

---

## 2. 系统总体架构

### 2.1 总体架构图

```
┌────────────────────────────────────────────────────────────────┐
│                  Web 控制端 (Next.js + Tailwind)                │
│         Dashboard · 实时监控 · 图谱 · Steering · 报告          │
└────────────────────────────┬───────────────────────────────────┘
                             │ REST API + WebSocket + SSE
┌────────────────────────────▼───────────────────────────────────┐
│                       API 网关 (FastAPI)                       │
│              任务控制 · 事件分发 · 鉴权 · 限流                  │
└──┬───────────┬───────────┬───────────┬───────────┬─────────────┘
   │           │           │           │           │
   ▼           ▼           ▼           ▼           ▼
┌─────┐    ┌─────┐    ┌─────┐    ┌─────┐    ┌─────────┐
│任务 │    │事件 │    │向量 │    │对象 │    │关系图谱 │
│队列 │    │存储 │    │数据库│   │存储 │    │(Neo4j)  │
│NATS │    │Kafka│    │Qdrant│   │MinIO│    │         │
└──┬──┘    └─────┘    └─────┘    └─────┘    └─────────┘
   │
   ▼
┌────────────────────────────────────────────────────────────────┐
│                  Agent Workers (核心执行层)                     │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │Orchestr.│ │  Recon  │ │  Code   │ │Hypothe. │ │ Payload │   │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘   │
│  ┌─────────┐ ┌─────────┐ ┌──────────────────────────────┐      │
│  │Verifier │ │Reporter │ │       共享记忆层             │      │
│  └─────────┘ └─────────┘ └──────────────────────────────┘      │
└──┬─────────────────────────────────────────────────────────────┘
   │
   ▼
┌────────────────────────────────────────────────────────────────┐
│                    工具沙箱层 (隔离执行)                         │
│        Docker · Firecracker · E2B · 网络隔离 · 资源配额         │
└──┬─────────────────────────────────────────────────────────────┘
   │
   ▼
┌────────────────────────────────────────────────────────────────┐
│                      外部工具与目标                              │
│      Burp · sqlmap · nmap · nuclei · 自研 Fuzzer · 目标系统    │
└────────────────────────────────────────────────────────────────┘
```

### 2.2 核心组件说明

| 组件            | 职责            | 关键指标     |
| ------------- | ------------- | -------- |
| Web 控制端       | 用户交互、可视化、人工介入 | 实时性、UX   |
| API 网关        | 任务调度、事件分发、鉴权  | 吞吐、延迟    |
| Agent Workers | 执行漏洞挖掘逻辑      | 推理质量、稳定性 |
| 工具沙箱层         | 安全执行工具调用      | 隔离强度、性能  |
| 知识库层          | 持久化记忆、跨任务学习   | 检索效率、召回率 |
| 任务队列          | 任务编排、暂停、恢复    | 可靠性、可观测性 |

### 2.3 技术栈总览

| 层        | 选型                                | 备选                   | 理由                   |
| -------- | --------------------------------- | -------------------- | -------------------- |
| Web 前端   | Next.js 15 + Tailwind + shadcn/ui | Vite + React + MUI   | SSR、内置路由、生态成熟        |
| 图谱可视化    | React Flow                        | D3, Cytoscape        | 易上手、性能好              |
| 后端框架     | FastAPI                           | Django, Flask        | 异步、原生 WebSocket、自动文档 |
| 任务编排     | Temporal                          | 自研状态机 + Redis        | 长任务、自动重试、可观测性        |
| 消息队列     | NATS JetStream                    | Kafka, Redis Streams | 轻量、Pub/Sub + 持久化     |
| 向量数据库    | Qdrant                            | Milvus, Weaviate     | 易部署、过滤能力强            |
| 关系图谱     | Neo4j                             | Memgraph, Kùzu       | 成熟、Cypher 查询语言强      |
| 对象存储     | MinIO                             | S3                   | 兼容 S3、自部署            |
| 关系数据库    | PostgreSQL + pgvector             | MySQL                | JSON 支持、生态成熟、向量检索    |
| Agent 框架 | LangGraph                         | AutoGen, CrewAI      | 状态机原生、可观测            |
| LLM      | Claude Opus / Sonnet, GPT-4       | 开源模型                 | 推理能力强                |
| 沙箱       | Docker + Firecracker              | gVisor               | 平衡性能与安全              |
| 部署       | Docker Compose → K8s              | -                    | 平滑演进                 |

---

## 3. Agent 系统设计

### 3.1 Agent 总览

7 个核心 Agent + 1 个共享记忆层:

| Agent           | 角色    | 输入            | 输出         | 主要工具                         |
| --------------- | ----- | ------------- | ---------- | ---------------------------- |
| Orchestrator    | 总指挥   | 目标画像          | 任务计划       | 内部决策                         |
| Recon           | 侦察兵   | 目标域名/IP       | 攻击面图谱      | subfinder, nmap, katana, gau |
| Code Analyst    | 代码分析师 | 源代码/JS bundle | 危险 sink 列表 | semgrep, jadx, frida         |
| Hypothesizer    | 假设生成器 | 攻击面 + 代码分析    | 漏洞假设清单     | RAG 检索                       |
| Payload Crafter | 载荷工匠  | 假设            | Payload 样本 | 自研变异器                        |
| Verifier        | 验证器   | Payload + 假设  | 验证结果       | 安全沙箱                         |
| Reporter        | 报告员   | 验证通过的漏洞       | SRC 报告     | 模板引擎                         |

### 3.2 Orchestrator(总指挥)

**职责**

- 接收用户任务,做目标画像
- 制定挖掘策略,选择激活的 Agent 子集
- 监控整体进度,调度资源
- 处理异常和升级

**目标画像模板**

```yaml
target_profile:
  type: web | api | mobile | binary | llm_app
  tech_stack:
    language: [Java, Go, Node.js, ...]
    framework: [Spring, Gin, Express, ...]
    waf: [Cloudflare, AWS WAF, ...]
  exposure:
    domains: [...]
    ports: [...]
    apis: [...]
  value_modules:
    - payment
    - user_data
    - admin_panel
  known_vulns: [...]
```

**策略决策**

```python
class Strategy(Enum):
    WEB_BROAD   = "web_broad"     # Web 广扫
    WEB_DEEP    = "web_deep"      # Web 深挖(读代码)
    API_FOCUSED = "api_focused"   # API 重点
    MOBILE_RE   = "mobile_re"     # 移动端逆向
    BINARY_FUZZ = "binary_fuzz"   # 二进制模糊测试
    LLM_SPECIFIC = "llm_specific" # LLM 应用
```

### 3.3 Recon Agent(侦察兵)

**任务清单**

- 子域名枚举(subfinder, amass)
- 端口扫描(nmap, masscan)
- 目录扫描(feroxbuster, katana)
- JS 提取与解析(GAU, LinkFinder)
- 历史漏洞关联(基于技术栈指纹)
- 代码泄漏搜索(GitHub, GitLab)

**输出结构**

```json
{
  "subdomains": ["api.example.com", "admin.example.com"],
  "open_ports": {"example.com": [80, 443, 8080]},
  "endpoints": [
    {
      "url": "https://api.example.com/v1/user",
      "method": "GET",
      "auth_required": true,
      "params": [{"name": "id", "type": "string"}]
    }
  ],
  "tech_stack": ["Nginx 1.21", "Node.js 18", "Express"],
  "waf": "Cloudflare",
  "sensitive_paths": ["/admin", "/.git", "/.env"]
}
```

### 3.4 Code Analyst(代码分析师)

**能力**

- 静态扫描(semgrep 自定义规则)
- JS bundle 还原与解析
- APP 反编译(jadx, frida)
- 危险 sink 识别:`eval` / `exec` / SQL 拼接 / SSRF 拼接 / 模板注入 / 反序列化
- 业务流程梳理(支付、权限、订单状态机等)

**输出示例**

```json
{
  "sinks": [
    {
      "type": "sql_injection",
      "file": "src/main/java/UserDao.java:42",
      "code": "String sql = \"SELECT * FROM users WHERE id = \" + id;",
      "reachable_from": ["/api/user/{id}"],
      "severity": "high"
    }
  ],
  "business_logic": [
    {
      "name": "支付流程",
      "entry": "/api/payment/create",
      "steps": ["生成订单", "调用支付", "更新状态"]
    }
  ]
}
```

### 3.5 Vulnerability Hypothesizer(假设生成器)

**核心创新: Debate 机制**

两个 Hypothesizer 实例互相挑战:

- H1:提出假设
- H2:扮演攻击者视角找反例,或扮演防御者质疑可行性
- 最终输出:经过辩论的假设 + 信心评分

**假设数据结构**

```json
{
  "id": "hyp_001",
  "type": "ssrf",
  "description": "/api/image/proxy 接收 URL 参数,未做内网过滤",
  "trigger_path": ["GET /api/image/proxy?url=..."],
  "preconditions": ["需要登录"],
  "expected_impact": "读取云元数据,可能获取临时凭证",
  "confidence": 0.75,
  "supporting_evidence": ["code analyst 找到 URL 拼接 sink"],
  "debate_log": [...]
}
```

### 3.6 Payload Crafter(载荷工匠)

**子模块**

- 注入型载荷生成器(SQLi, XSS, SSTI, CMDi)
- 越权型载荷生成器(IDOR, 水平/垂直越权)
- 逻辑型载荷生成器(金额篡改、状态机绕过)
- 客户端型载荷生成器(CSRF, 点击劫持)
- LLM 应用载荷(Prompt 注入、数据泄露)

**变异器**

```python
class PayloadMutator:
    def mutate(self, base: str) -> List[str]:
        return [
            base,
            self.url_encode(base),
            self.double_encode(base),
            self.unicode_escape(base),
            self.case_variation(base),
            self.comment_injection(base),   # SQL: /*...*/
            self.hpp(base),                 # HTTP Parameter Pollution
        ]
```

**安全载荷包装**

所有 payload 自动生成"无害化变体":

- SQLi:`' OR '1'='1` → 改用 `AND SLEEP(0)` 等无副作用探测
- 写操作:加 IF 条件,失败回滚
- 大文件读取:限制字节数

### 3.7 Adversarial Verifier(对抗验证器)

**双重身份**

1. **漏洞验证**:在可控环境复现假设
2. **风控守门员**:防止 payload 造成破坏

**两阶段复现**

```
阶段 1: 无副作用证明
  - 只读操作
  - 返回状态码 / 响应差异即可
  - 必须满足:不写、不删、不读大量数据

阶段 2: 最小破坏复现
  - 仅在白名单目标执行
  - 必须用户二次确认(高危操作)
  - 自动生成完整复现步骤 + 影响证据
```

**危险等级判定**

| 等级  | 操作       | 默认策略    |
| --- | -------- | ------- |
| L0  | 只读、被动扫描  | 自动执行    |
| L1  | 主动探测、有限写 | 自动 + 限速 |
| L2  | 真实漏洞利用   | 二次确认    |
| L3  | 高危破坏性操作  | 必须人工审核  |

### 3.8 Reporter(报告员)

**报告结构**

```markdown
# [漏洞标题]

## 漏洞概述
简要描述漏洞性质和影响

## 漏洞等级
高 / 中 / 低

## 影响范围
哪些域名、哪些接口、哪些用户受影响

## 漏洞复现
### 环境信息
### 复现步骤
1. 步骤 1
2. 步骤 2
...
### 预期结果
### 实际结果

## 修复建议
具体可执行的修复方案

## 参考资料
```

**模板引擎**

支持多 SRC 平台格式:

- 通用 Markdown
- 漏洞盒子格式
- 补天格式
- 各厂商自定义模板

### 3.9 共享记忆层

**四类存储**

1. **Vector Store (Qdrant)**:历史漏洞、payload 模式、绕过技巧
2. **Graph Store (Neo4j)**:资产关系图、用户权限图、攻击路径
3. **Episode Memory (PostgreSQL)**:本次任务的决策链、思考过程
4. **Failure Log**:失败的假设、绕不过的 WAF,作为反例

**记忆接口**

```python
class Memory:
    async def recall(self, query: str, top_k: int = 10) -> List[MemoryItem]
    async def store(self, item: MemoryItem) -> None
    async def link(self, item_id: str, relations: List[Relation]) -> None
    async def search_similar_failures(self, context: str) -> List[Failure]
```

### 3.10 黑板模型与 Agent 协调机制

#### 3.10.1 黑板数据结构

黑板（Blackboard）是所有 Agent 共享的中心化状态空间，替代传统流水线的刚性顺序。每个 Agent 从黑板读取上下文、向黑板写入产出，Orchestrator 根据黑板状态决定下一步激活哪些 Agent。

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

class SlotStatus(Enum):
    EMPTY = "empty"
    PARTIAL = "partial"
    READY = "ready"
    STALE = "stale"

@dataclass
class Blackboard:
    task_id: str
    version: int = 0  # 每次写入递增，用于乐观锁

    # ── 侦察槽 ──
    target_profile: dict = field(default_factory=dict)      # Orchestrator 写入
    attack_surface: dict = field(default_factory=dict)      # Recon 写入
    tech_fingerprint: dict = field(default_factory=dict)    # Recon 写入

    # ── 代码分析槽 ──
    code_sinks: list = field(default_factory=list)          # Code Analyst 写入
    business_flows: list = field(default_factory=list)      # Code Analyst 写入

    # ── 假设槽 ──
    hypotheses: list = field(default_factory=list)          # Hypothesizer 写入
    rejected_hypotheses: list = field(default_factory=list) # Debate 淘汰的假设

    # ── 载荷槽 ──
    payloads: dict = field(default_factory=dict)            # Payload Crafter 写入，key=hypothesis_id

    # ── 验证槽 ──
    findings: list = field(default_factory=list)            # Verifier 写入（已确认漏洞）
    false_positives: list = field(default_factory=list)     # Verifier 写入（误报）

    # ── 报告槽 ──
    reports: list = field(default_factory=list)             # Reporter 写入

    # ── 控制槽 ──
    steering_directives: list = field(default_factory=list) # 人工注入指令
    active_agents: set = field(default_factory=set)
    blocked_agents: dict = field(default_factory=dict)      # agent -> 阻塞原因

    # ── 元信息 ──
    slot_status: dict = field(default_factory=dict)         # slot_name -> SlotStatus
    last_updated_by: dict = field(default_factory=dict)     # slot_name -> (agent, timestamp)
```

#### 3.10.2 读写协议

```python
class BlackboardProtocol:
    """Agent 与黑板的交互协议"""

    async def read(self, slot: str, version: Optional[int] = None) -> tuple[any, int]:
        """
        读取指定槽位数据，返回 (data, current_version)。
        传入 version 可检测是否有新数据（version 不变则无更新）。
        """

    async def write(self, slot: str, data: any, agent: str, merge_strategy: str = "append") -> int:
        """
        写入槽位数据，返回新 version。
        merge_strategy:
          - "append": 追加到列表槽（hypotheses, findings 等）
          - "replace": 完整替换（target_profile 等）
          - "merge_dict": 字典合并（attack_surface 等）
        使用乐观锁：写入时检查 version，冲突则重试。
        """

    async def subscribe(self, slots: list[str], callback) -> str:
        """订阅槽位变更，返回 subscription_id"""

    async def cas(self, slot: str, expected_version: int, data: any, agent: str) -> bool:
        """Compare-And-Swap，原子性条件写入"""
```

**读写权限矩阵**

| Agent           | 可读槽位                              | 可写槽位                  |
| --------------- | --------------------------------- | --------------------- |
| Orchestrator    | 全部                                | target_profile, active_agents, steering |
| Recon           | target_profile, steering          | attack_surface, tech_fingerprint |
| Code Analyst    | target_profile, attack_surface    | code_sinks, business_flows |
| Hypothesizer    | attack_surface, code_sinks, findings, false_positives | hypotheses, rejected_hypotheses |
| Payload Crafter | hypotheses                        | payloads              |
| Verifier        | hypotheses, payloads              | findings, false_positives |
| Reporter        | findings                          | reports               |

#### 3.10.3 动态小组机制

Orchestrator 根据黑板状态动态组建 Agent 小组，而非固定流水线。

```python
@dataclass
class AgentGroup:
    id: str
    name: str
    agents: list[str]
    objective: str
    trigger_condition: str     # 组建条件（基于黑板状态表达式）
    dissolution_condition: str # 解散条件
    priority: int
    created_at: float

# 预定义小组模板
GROUP_TEMPLATES = {
    "ssrf_deep_dive": {
        "agents": ["recon", "code_analyst", "hypothesizer", "payload_crafter", "verifier"],
        "trigger": "any(h.type == 'ssrf' and h.confidence > 0.6 for h in blackboard.hypotheses)",
        "dissolution": "len([f for f in blackboard.findings if f.type == 'ssrf']) > 0 or attempts > 3",
    },
    "auth_bypass_hunt": {
        "agents": ["code_analyst", "hypothesizer", "payload_crafter", "verifier"],
        "trigger": "blackboard.attack_surface.get('auth_endpoints', []) and not blackboard.code_sinks",
        "dissolution": "all hypotheses of type auth_bypass verified or rejected",
    },
    "quick_scan": {
        "agents": ["recon", "hypothesizer", "verifier"],
        "trigger": "task.strategy == 'web_broad'",
        "dissolution": "blackboard.slot_status['attack_surface'] == 'ready'",
    },
}
```

**小组调度规则**

1. **互斥约束**：同一 Agent 不能同时属于两个活跃小组
2. **优先级抢占**：高优先级小组可以从低优先级小组"借"Agent
3. **自动解散**：满足解散条件或超时后自动解散，Agent 回池
4. **反馈触发**：Verifier 确认漏洞后，Orchestrator 可组建新小组深挖同类漏洞

#### 3.10.4 与 LangGraph 状态机的映射

黑板直接作为 LangGraph 的 `State`，Agent 节点通过条件边形成反馈循环：

```python
from langgraph.graph import StateGraph, END

class VulnHuntState(TypedDict):
    blackboard: Blackboard
    current_phase: str
    iteration_count: int
    max_iterations: int

def build_graph() -> StateGraph:
    graph = StateGraph(VulnHuntState)

    # 添加 Agent 节点
    graph.add_node("orchestrator", orchestrator_node)
    graph.add_node("recon", recon_node)
    graph.add_node("code_analyst", code_analyst_node)
    graph.add_node("hypothesizer", hypothesizer_node)
    graph.add_node("payload_crafter", payload_crafter_node)
    graph.add_node("verifier", verifier_node)
    graph.add_node("reporter", reporter_node)

    # 入口
    graph.set_entry_point("orchestrator")

    # Orchestrator 根据黑板状态决定下一步
    graph.add_conditional_edges("orchestrator", route_from_orchestrator, {
        "recon": "recon",
        "code_analyst": "code_analyst",
        "hypothesizer": "hypothesizer",
        "reporter": "reporter",
        "end": END,
    })

    # 侦察完成 → 回 Orchestrator 决策
    graph.add_edge("recon", "orchestrator")

    # 代码分析完成 → 回 Orchestrator
    graph.add_edge("code_analyst", "orchestrator")

    # 假设生成 → 载荷制作
    graph.add_edge("hypothesizer", "payload_crafter")

    # 载荷完成 → 验证
    graph.add_edge("payload_crafter", "verifier")

    # 验证完成 → 回 Orchestrator（形成反馈循环）
    graph.add_edge("verifier", "orchestrator")

    # 报告完成 → 结束
    graph.add_edge("reporter", END)

    return graph.compile()


def route_from_orchestrator(state: VulnHuntState) -> str:
    bb = state["blackboard"]

    # 有 Steering 指令，优先处理
    if bb.steering_directives:
        return apply_steering(bb)

    # 攻击面为空 → 先侦察
    if bb.slot_status.get("attack_surface") != "ready":
        return "recon"

    # 有侦察结果但没有代码分析 → 分析代码
    if bb.code_sinks == [] and bb.slot_status.get("attack_surface") == "ready":
        return "code_analyst"

    # 有攻击面 + 代码分析，但假设不足 → 生成假设
    pending_hypotheses = [h for h in bb.hypotheses if h["status"] == "pending"]
    if len(pending_hypotheses) < 3:
        return "hypothesizer"

    # 有已验证漏洞且未生成报告 → 生成报告
    unreported = [f for f in bb.findings if f["status"] == "verified"]
    if unreported:
        return "reporter"

    # 达到最大迭代 → 结束
    if state["iteration_count"] >= state["max_iterations"]:
        return "reporter" if bb.findings else "end"

    # 默认：继续生成假设
    return "hypothesizer"
```

**反馈循环示例**

```
Orchestrator → Recon → Orchestrator → Code Analyst → Orchestrator
    → Hypothesizer → Payload Crafter → Verifier
    → Orchestrator (发现 SSRF，组建 ssrf_deep_dive 小组)
    → Hypothesizer (针对 SSRF 生成更多假设) → Payload Crafter → Verifier
    → Orchestrator → Reporter → END
```

### 3.11 Temporal 工作流定义

#### 3.11.1 Workflow 定义

```python
from temporalio import workflow, activity
from datetime import timedelta

@workflow.defn
class VulnHuntWorkflow:
    """主工作流：管理一次完整的漏洞挖掘任务"""

    def __init__(self):
        self.status = "initialized"
        self.paused = False
        self.steering_queue: list[str] = []
        self.checkpoints: list[dict] = []

    @workflow.run
    async def run(self, task_config: dict) -> dict:
        self.status = "running"

        # 阶段 1：目标画像
        profile = await workflow.execute_activity(
            run_orchestrator_profiling,
            task_config,
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )
        await self._checkpoint("profiling_done", profile)

        # 阶段 2：侦察（可并行多个子任务）
        recon_results = await workflow.execute_activity(
            run_recon,
            args=[profile, task_config],
            start_to_close_timeout=timedelta(minutes=30),
            heartbeat_timeout=timedelta(minutes=2),
            retry_policy=RetryPolicy(maximum_attempts=2),
        )
        await self._checkpoint("recon_done", recon_results)

        # 阶段 3：代码分析（如果启用）
        code_analysis = None
        if task_config.get("agents", {}).get("code_analyst", {}).get("enabled"):
            code_analysis = await workflow.execute_activity(
                run_code_analysis,
                args=[recon_results, task_config],
                start_to_close_timeout=timedelta(minutes=20),
                retry_policy=RetryPolicy(maximum_attempts=2),
            )
            await self._checkpoint("code_analysis_done", code_analysis)

        # 阶段 4：假设-验证循环（核心循环）
        findings = []
        iteration = 0
        max_iterations = task_config.get("max_iterations", 5)

        while iteration < max_iterations:
            await self._wait_if_paused()
            await self._process_steering()

            # 生成假设
            hypotheses = await workflow.execute_activity(
                run_hypothesizer,
                args=[recon_results, code_analysis, findings, iteration],
                start_to_close_timeout=timedelta(minutes=10),
            )

            if not hypotheses:
                break  # 无新假设，退出循环

            # 制作载荷
            payloads = await workflow.execute_activity(
                run_payload_crafter,
                args=[hypotheses, task_config],
                start_to_close_timeout=timedelta(minutes=10),
            )

            # 验证
            verified = await workflow.execute_activity(
                run_verifier,
                args=[hypotheses, payloads, task_config],
                start_to_close_timeout=timedelta(minutes=15),
            )

            findings.extend(verified)
            await self._checkpoint(f"iteration_{iteration}_done", {
                "hypotheses": len(hypotheses),
                "verified": len(verified),
            })
            iteration += 1

        # 阶段 5：生成报告
        reports = []
        if findings:
            reports = await workflow.execute_activity(
                run_reporter,
                args=[findings, task_config],
                start_to_close_timeout=timedelta(minutes=10),
            )

        self.status = "completed"
        return {"findings": findings, "reports": reports, "iterations": iteration}

    # ── Signal 处理 ──

    @workflow.signal
    async def steer(self, directive: str):
        """接收 Steering 指令"""
        self.steering_queue.append(directive)

    @workflow.signal
    async def pause(self):
        self.paused = True
        self.status = "paused"

    @workflow.signal
    async def resume(self):
        self.paused = False
        self.status = "running"

    @workflow.signal
    async def terminate_gracefully(self):
        """优雅终止：完成当前阶段后退出"""
        self.status = "terminating"

    # ── Query 处理 ──

    @workflow.query
    def get_status(self) -> dict:
        return {
            "status": self.status,
            "paused": self.paused,
            "checkpoints": self.checkpoints,
            "pending_steering": len(self.steering_queue),
        }

    # ── 内部方法 ──

    async def _wait_if_paused(self):
        await workflow.wait_condition(lambda: not self.paused)

    async def _process_steering(self):
        while self.steering_queue:
            directive = self.steering_queue.pop(0)
            await workflow.execute_activity(
                apply_steering_directive,
                directive,
                start_to_close_timeout=timedelta(minutes=2),
            )

    async def _checkpoint(self, name: str, data: dict):
        self.checkpoints.append({
            "name": name,
            "timestamp": workflow.now().isoformat(),
            "summary": data,
        })
```

#### 3.11.2 Activity 定义

```python
@activity.defn
async def run_recon(profile: dict, config: dict) -> dict:
    """侦察 Activity：运行侦察工具链"""
    # 在沙箱中执行，定期发送 heartbeat
    async with SandboxSession(config) as sandbox:
        results = {}
        for tool in ["subfinder", "nmap", "katana", "gau"]:
            activity.heartbeat(f"running_{tool}")
            results[tool] = await sandbox.run_tool(tool, profile)
        return merge_recon_results(results)

@activity.defn
async def run_hypothesizer(recon: dict, code: dict, findings: list, iteration: int) -> list:
    """假设生成 Activity：含 Debate 机制"""
    # Debate 轮次
    h1_hypotheses = await llm_generate_hypotheses(recon, code, findings, role="proposer")
    h2_challenges = await llm_challenge_hypotheses(h1_hypotheses, role="challenger")
    refined = await llm_refine_hypotheses(h1_hypotheses, h2_challenges)
    return [h for h in refined if h["confidence"] >= 0.5]

@activity.defn
async def run_verifier(hypotheses: list, payloads: dict, config: dict) -> list:
    """验证 Activity：在沙箱中执行验证"""
    findings = []
    for hyp in hypotheses:
        risk_level = assess_risk(hyp, payloads.get(hyp["id"], []))
        if risk_level >= RiskLevel.L2:
            approval = await request_human_approval(hyp, risk_level)
            if not approval:
                continue
        result = await execute_in_sandbox(hyp, payloads.get(hyp["id"], []), config)
        if result["verified"]:
            findings.append(result)
    return findings

@activity.defn
async def apply_steering_directive(directive: str) -> dict:
    """处理 Steering 指令"""
    parsed = await llm_parse_steering(directive)
    return {"action": parsed["action"], "applied": True}
```

#### 3.11.3 断点恢复机制

```python
class CheckpointManager:
    """管理任务断点，支持从任意 checkpoint 恢复"""

    async def save(self, task_id: str, checkpoint_name: str, state: dict):
        """持久化断点状态到 PostgreSQL + MinIO"""
        await self.db.execute("""
            INSERT INTO checkpoints (id, task_id, name, state, created_at)
            VALUES ($1, $2, $3, $4, NOW())
        """, uuid4(), task_id, checkpoint_name, json.dumps(state))

        # 大体积数据（如完整攻击面图谱）存 MinIO
        if len(json.dumps(state)) > 1_000_000:
            await self.minio.put_object(
                f"checkpoints/{task_id}/{checkpoint_name}.json",
                state
            )

    async def restore(self, task_id: str, checkpoint_name: str) -> dict:
        """从断点恢复"""
        row = await self.db.fetchrow("""
            SELECT state FROM checkpoints
            WHERE task_id = $1 AND name = $2
            ORDER BY created_at DESC LIMIT 1
        """, task_id, checkpoint_name)
        return json.loads(row["state"])

    async def list_checkpoints(self, task_id: str) -> list[dict]:
        """列出任务所有断点"""
        rows = await self.db.fetch("""
            SELECT name, created_at FROM checkpoints
            WHERE task_id = $1 ORDER BY created_at
        """, task_id)
        return [dict(r) for r in rows]
```

**数据库表**

```sql
CREATE TABLE checkpoints (
    id UUID PRIMARY KEY,
    task_id UUID REFERENCES tasks(id),
    name VARCHAR(100),
    state JSONB,
    large_state_ref VARCHAR(500), -- MinIO 对象路径（大状态）
    created_at TIMESTAMPTZ
);
CREATE INDEX idx_checkpoints_task ON checkpoints(task_id, created_at);
```

### 3.12 LLM 调用策略

#### 3.12.1 模型路由

不同 Agent 根据任务复杂度分配不同级别的模型：

| Agent           | 主模型             | 降级模型            | 理由                  |
| --------------- | --------------- | --------------- | ------------------- |
| Orchestrator    | Claude Opus     | Claude Sonnet   | 需要复杂推理、全局规划         |
| Recon           | Claude Haiku    | —               | 主要是工具编排，推理需求低       |
| Code Analyst    | Claude Sonnet   | Claude Haiku    | 代码理解需中等推理           |
| Hypothesizer    | Claude Opus     | Claude Sonnet   | 核心创造性推理，质量优先        |
| Payload Crafter | Claude Sonnet   | Claude Haiku    | 代码生成 + 模式匹配         |
| Verifier        | Claude Opus     | Claude Sonnet   | 关键决策点，不容误判          |
| Reporter        | Claude Sonnet   | Claude Haiku    | 文本生成，结构化输出          |

```python
class ModelRouter:
    ROUTING_TABLE = {
        "orchestrator":    {"primary": "claude-opus-4", "fallback": "claude-sonnet-4-6"},
        "recon":           {"primary": "claude-haiku-4-5", "fallback": None},
        "code_analyst":    {"primary": "claude-sonnet-4-6", "fallback": "claude-haiku-4-5"},
        "hypothesizer":    {"primary": "claude-opus-4", "fallback": "claude-sonnet-4-6"},
        "payload_crafter": {"primary": "claude-sonnet-4-6", "fallback": "claude-haiku-4-5"},
        "verifier":        {"primary": "claude-opus-4", "fallback": "claude-sonnet-4-6"},
        "reporter":        {"primary": "claude-sonnet-4-6", "fallback": "claude-haiku-4-5"},
    }

    async def select_model(self, agent: str, task_budget: "TokenBudget") -> str:
        route = self.ROUTING_TABLE[agent]
        if task_budget.remaining_ratio() < 0.2 and route["fallback"]:
            return route["fallback"]
        return route["primary"]
```

#### 3.12.2 Token 预算管理

```python
@dataclass
class TokenBudget:
    task_id: str
    total_budget: int           # 任务总预算（token 数）
    spent: int = 0
    per_agent_limits: dict = field(default_factory=dict)
    alert_thresholds: list = field(default_factory=lambda: [0.5, 0.8, 0.95])

    def remaining(self) -> int:
        return self.total_budget - self.spent

    def remaining_ratio(self) -> float:
        return self.remaining() / self.total_budget

    def consume(self, agent: str, tokens_in: int, tokens_out: int):
        total = tokens_in + tokens_out
        self.spent += total
        self.per_agent_limits.setdefault(agent, {"spent": 0})
        self.per_agent_limits[agent]["spent"] += total

        for threshold in self.alert_thresholds:
            if (self.spent - total) / self.total_budget < threshold <= self.spent / self.total_budget:
                self._emit_alert(threshold)

    def _emit_alert(self, threshold: float):
        event_bus.emit("budget_alert", {
            "task_id": self.task_id,
            "threshold": threshold,
            "spent": self.spent,
            "total": self.total_budget,
        })

# 策略预算参考
BUDGET_PRESETS = {
    "web_broad":    {"total": 500_000, "orchestrator": 50_000, "recon": 30_000, "hypothesizer": 150_000},
    "web_deep":     {"total": 1_500_000, "orchestrator": 100_000, "code_analyst": 300_000, "hypothesizer": 400_000},
    "api_focused":  {"total": 800_000, "orchestrator": 60_000, "hypothesizer": 250_000},
    "llm_specific": {"total": 1_000_000, "hypothesizer": 300_000, "payload_crafter": 200_000},
}
```

#### 3.12.3 Prompt 版本管理

```python
class PromptRegistry:
    """管理 Agent Prompt 的版本化存储"""

    async def get_prompt(self, agent: str, version: Optional[int] = None) -> "PromptVersion":
        """获取指定版本的 Prompt，默认最新版"""

    async def save_prompt(self, agent: str, content: str, changelog: str) -> "PromptVersion":
        """保存新版本，自动递增版本号"""

    async def diff(self, agent: str, v1: int, v2: int) -> str:
        """对比两个版本的差异"""

    async def rollback(self, agent: str, version: int) -> "PromptVersion":
        """回滚到指定版本"""
```

```sql
CREATE TABLE prompt_versions (
    id UUID PRIMARY KEY,
    agent VARCHAR(50) NOT NULL,
    version INT NOT NULL,
    content TEXT NOT NULL,
    variables JSONB,         -- 可插值变量定义
    changelog TEXT,
    created_by UUID,
    created_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT FALSE,
    UNIQUE(agent, version)
);
CREATE INDEX idx_prompt_active ON prompt_versions(agent, is_active) WHERE is_active = TRUE;
```

#### 3.12.4 流式输出与中断

```python
class StreamingLLMClient:
    async def stream_completion(
        self,
        agent: str,
        messages: list,
        on_token: Callable,
        cancel_event: asyncio.Event,
    ) -> str:
        """
        流式调用 LLM，支持中途取消。
        - on_token: 每个 token 回调（用于实时推送到前端）
        - cancel_event: 设置后中断当前流，返回已生成内容
        """
        model = await self.router.select_model(agent, self.budget)
        buffer = []

        async with self.client.stream(model=model, messages=messages) as stream:
            async for token in stream:
                if cancel_event.is_set():
                    break
                buffer.append(token)
                await on_token(token)
                self.budget.consume(agent, 0, 1)

        return "".join(buffer)
```

### 3.13 错误处理与恢复机制

#### 3.13.1 重试策略

```python
from dataclasses import dataclass

@dataclass
class RetryConfig:
    max_attempts: int = 3
    initial_backoff_s: float = 1.0
    max_backoff_s: float = 60.0
    backoff_multiplier: float = 2.0
    retryable_errors: tuple = (
        "rate_limit",
        "timeout",
        "transient_network",
        "llm_overloaded",
    )
    non_retryable_errors: tuple = (
        "auth_failure",
        "invalid_input",
        "budget_exceeded",
        "sandbox_security_violation",
    )

RETRY_CONFIGS = {
    "llm_call":    RetryConfig(max_attempts=3, initial_backoff_s=2.0),
    "tool_exec":   RetryConfig(max_attempts=2, initial_backoff_s=1.0),
    "sandbox":     RetryConfig(max_attempts=2, initial_backoff_s=5.0),
    "db_write":    RetryConfig(max_attempts=3, initial_backoff_s=0.5),
    "external_api": RetryConfig(max_attempts=3, initial_backoff_s=3.0, max_backoff_s=30.0),
}
```

#### 3.13.2 熔断器

```python
class CircuitBreaker:
    """
    Agent 级别熔断器：连续失败超过阈值时熔断，
    进入半开状态后尝试单个请求，成功则恢复。
    """
    CLOSED = "closed"      # 正常
    OPEN = "open"          # 熔断
    HALF_OPEN = "half_open" # 试探

    def __init__(self, failure_threshold: int = 5, recovery_timeout_s: int = 60):
        self.state = self.CLOSED
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.recovery_timeout_s = recovery_timeout_s
        self.last_failure_time = 0

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = self.OPEN

    def record_success(self):
        self.failure_count = 0
        self.state = self.CLOSED

    def allow_request(self) -> bool:
        if self.state == self.CLOSED:
            return True
        if self.state == self.OPEN:
            if time.time() - self.last_failure_time > self.recovery_timeout_s:
                self.state = self.HALF_OPEN
                return True
            return False
        return True  # HALF_OPEN: 允许一个试探请求
```

#### 3.13.3 Agent 级降级方案

| 失败场景          | 降级策略                            |
| ------------- | ------------------------------- |
| Recon 工具不可用   | 跳过该工具，用已有结果继续；记录覆盖度缺失          |
| Code Analyst 超时 | 降级为仅 JS 端点提取，跳过深度代码分析          |
| Hypothesizer 循环 | 限制最大假设数，触发报告阶段                  |
| LLM API 限流    | 自动降级到 fallback 模型；若 fallback 也不可用则暂停等待 |
| Verifier 沙箱崩溃  | 标记假设为"待人工验证"，不丢弃               |
| 整体 Token 预算耗尽 | 生成当前状态报告，标记任务为"预算耗尽-部分完成"      |

#### 3.13.4 任务状态机与异常处理

```
                    ┌─────────┐
                    │ created │
                    └────┬────┘
                         │ start
                    ┌────▼────┐    pause     ┌────────┐
                ┌──►│ running │─────────────►│ paused │
                │   └────┬────┘              └────┬───┘
                │        │                       │ resume
                │        │ ◄─────────────────────┘
     steering   │        │
                │   ┌────▼─────┐
                └───│ deciding │ (Orchestrator 决策中)
                    └────┬─────┘
                         │
              ┌──────────┼──────────┐
              │          │          │
         ┌────▼───┐ ┌───▼────┐ ┌──▼───────────┐
         │ failed │ │  done  │ │ partial_done │
         └────────┘ └────────┘ └──────────────┘
              │
              │ retry (从最近 checkpoint 恢复)
              │
         ┌────▼────┐
         │ running │
         └─────────┘
```

### 3.14 Agent 事件协议

**事件 Schema**

```typescript
interface AgentEvent {
  event_id: string;
  task_id: string;
  parent_event_id?: string;
  agent: AgentName;
  type: EventType;
  timestamp: number;
  data: any;
  tags?: string[];
  confidence?: number;
  cost?: {
    tokens_in: number;
    tokens_out: number;
    time_ms: number;
    cost_usd?: number;
  };
}

type AgentName =
  | 'orchestrator' | 'recon' | 'code_analyst'
  | 'hypothesizer' | 'payload_crafter' | 'verifier' | 'reporter';

type EventType =
  | 'thought'        // 思考过程
  | 'tool_call'      // 工具调用
  | 'tool_result'    // 工具结果
  | 'decision'       // 决策节点
  | 'hypothesis'     // 漏洞假设
  | 'payload'        // 生成的 payload
  | 'finding'        // 发现(可能是漏洞)
  | 'error'          // 错误
  | 'log'            // 普通日志
  | 'checkpoint';    // 断点(用于恢复)
```

**事件生命周期**

```
[thought] → [tool_call] → [tool_result] → [thought] → ... → [decision] → [next agent]
```

**事件存储**

- 短期:Kafka / NATS JetStream(实时消费)
- 长期:PostgreSQL(JSONB) + 对象存储(原始 payload、截图)

---

## 4. 工具与集成层

### 4.1 工具抽象层

所有工具走统一接口,LLM 不直接耦合工具:

```python
class Tool(Protocol):
    name: str
    description: str
    input_schema: Dict
    output_schema: Dict
    risk_level: RiskLevel

    async def execute(self, input: Dict, context: ExecutionContext) -> Dict:
        ...

class ToolRegistry:
    def register(self, tool: Tool) -> None
    def get(self, name: str) -> Tool
    def list(self, filter: ToolFilter) -> List[Tool]
```

### 4.2 沙箱设计

**沙箱类型**

| 类型          | 用途        | 隔离强度 |
| ----------- | --------- | ---- |
| Docker      | 一般工具调用    | 中    |
| Firecracker | 高危工具      | 强    |
| E2B         | 短生命周期代码执行 | 中    |
| 浏览器隔离       | Web 漏洞测试  | 中    |

**沙箱配置示例**

```yaml
sandbox:
  default: docker
  rules:
    - tool: sqlmap
      sandbox: docker
      network:
        egress_whitelist:
          - "*.example.com"
      resource_limits:
        cpu: "1"
        memory: "2G"
        network_bandwidth: "10Mbps"
        execution_time: 300s
```

**网络隔离**

- 默认 deny,白名单 egress
- DNS 解析控制(防止 DNS 重绑定)
- 流量监控 + 异常告警

### 4.3 工具清单

**侦察类**

- subfinder / amass(子域名)
- nmap / masscan(端口)
- feroxbuster / katana(目录)
- gau / waybackurls(历史 URL)
- linkfinder(JS 端点)

**代码分析类**

- semgrep(静态分析)
- jadx(APK 反编译)
- frida(动态 hook)
- 自研 JS 解析器

**漏洞测试类**

- sqlmap(SQL 注入)
- XSStrike(XSS)
- SSRFmap(SSRF)
- nuclei(模板化扫描)
- 自研 Fuzzer

**自研工具**

- Payload 变异器
- 业务逻辑漏洞测试器
- 越权批量检测器

---

## 5. 知识库与记忆层

### 5.1 Vector Store(Qdrant)

**Collection 设计**

```python
collections = {
    "vuln_patterns": {
        "vector_size": 1536,
        "distance": "Cosine",
        "payload_schema": {
            "type": "keyword",      # sql_injection, ssrf, ...
            "severity": "keyword",
            "description": "text",
            "example_payload": "text",
            "success_rate": "float",
            "tags": "keyword[]"
        }
    },
    "payload_templates": {
        "vector_size": 1536,
        "distance": "Cosine",
        "payload_schema": {
            "vuln_type": "keyword",
            "template": "text",
            "bypass_techniques": "keyword[]",
            "last_used": "datetime"
        }
    },
    "waf_bypasses": {
        "vector_size": 1536,
        "distance": "Cosine",
        "payload_schema": {
            "waf_vendor": "keyword",
            "bypass_payload": "text",
            "effectiveness": "float"
        }
    },
    "historical_reports": {
        "vector_size": 1536,
        "distance": "Cosine",
        "payload_schema": {
            "vendor": "keyword",
            "vuln_type": "keyword",
            "severity": "keyword",
            "report": "text",
            "reward": "float"
        }
    }
}
```

**RAG 流程**

```
用户输入(目标特征、攻击面)
    ↓
Embedding
    ↓
向量检索(top-k by similarity)
    ↓
过滤(by type, severity, tags)
    ↓
Re-rank(by confidence, recency)
    ↓
注入到 LLM Prompt
```

### 5.2 Graph Store(Neo4j)

**Schema**

```
(:Domain)-[:HAS_SUBDOMAIN]->(:Subdomain)
(:Subdomain)-[:HAS_ENDPOINT]->(:Endpoint)
(:Endpoint)-[:REQUIRES_AUTH]->(:Role)
(:Role)-[:HAS_PERMISSION]->(:Permission)
(:Endpoint)-[:CALLS]->(:Service)
(:Service)-[:ACCESSES]->(:Database)
(:Hypothesis)-[:EXPLOITS]->(:Endpoint)
(:Finding)-[:AFFECTS]->(:Endpoint)
```

**典型查询**

```cypher
// 找出所有可达 admin 接口的路径
MATCH path = (r:Role)-[:HAS_PERMISSION]->(p:Permission)-[:GRANTS_ACCESS_TO]->(e:Endpoint)
WHERE e.path CONTAINS '/admin'
RETURN path

// 找出 SSRF 风险链路
MATCH (e:Endpoint)-[:CALLS]->(s:Service)
WHERE s.type = 'http_client' AND NOT s.has_url_filter
RETURN e, s
```

### 5.3 Episode Memory

```sql
CREATE TABLE episodes (
    id UUID PRIMARY KEY,
    task_id UUID NOT NULL,
    agent VARCHAR(50),
    thought TEXT,
    action JSONB,
    observation JSONB,
    reflection TEXT,
    outcome VARCHAR(20),       -- success | failure | partial
    created_at TIMESTAMP
);

CREATE TABLE episode_chains (
    id UUID PRIMARY KEY,
    task_id UUID NOT NULL,
    chain JSONB,
    result JSONB,
    lessons_learned TEXT
);
```

### 5.4 Failure Log

```sql
CREATE TABLE failures (
    id UUID PRIMARY KEY,
    task_id UUID,
    failure_type VARCHAR(50),   -- false_positive | blocked_by_waf | no_effect
    context JSONB,
    hypothesis JSONB,
    payload TEXT,
    error_info TEXT,
    root_cause_analysis TEXT,
    created_at TIMESTAMP
);
```

**失败模式的使用**

- 同类失败模式检索 → 避免重复
- 失败根因分析 → 改进 payload 生成

### 5.5 知识库冷启动与数据治理

#### 5.5.1 冷启动数据源

系统首次部署时，知识库为空会导致 Hypothesizer 缺乏参考。需要预填充初始数据：

| 数据类型         | 来源                       | 预估规模        | 入库方式   |
| ------------ | ------------------------ | ----------- | ------ |
| 漏洞模式         | OWASP Testing Guide、CWE Top 25 | 200+ 条      | 脚本批量导入 |
| Payload 模板   | PayloadsAllTheThings、SecLists | 5000+ 条     | 脚本批量导入 |
| WAF 绕过技巧     | 公开研究论文、安全社区              | 500+ 条      | 人工审核导入 |
| 历史 SRC 报告    | 团队过往报告、公开漏洞报告（脱敏）        | 按团队积累       | 人工导入   |
| Semgrep 规则集  | semgrep-rules 官方仓库       | 2000+ 条     | 自动同步   |
| Nuclei 模板    | nuclei-templates 官方仓库    | 8000+ 条     | 自动同步   |

**冷启动脚本**

```python
class KnowledgeBootstrap:
    async def run(self):
        """一键初始化知识库"""
        await self.import_owasp_patterns()
        await self.import_payload_templates()
        await self.import_waf_bypasses()
        await self.import_semgrep_rules()
        await self.import_nuclei_templates()
        await self.build_embeddings()
        await self.validate_data_quality()

    async def import_owasp_patterns(self):
        """从 OWASP 测试指南提取漏洞模式并生成 embedding"""
        patterns = parse_owasp_testing_guide("data/owasp/")
        for p in patterns:
            embedding = await self.embed(p.description)
            await self.qdrant.upsert("vuln_patterns", {
                "id": p.id,
                "vector": embedding,
                "payload": p.to_dict(),
            })

    async def build_embeddings(self):
        """批量生成 embedding（用小模型降低成本）"""
        # 使用 text-embedding-3-small 或本地模型
```

#### 5.5.2 数据质量控制

```python
class DataQualityPipeline:
    """知识库数据质量管控"""

    async def on_agent_store(self, item: "MemoryItem") -> bool:
        """Agent 自动沉淀前的质量检查"""
        checks = [
            self.check_duplicate(item),      # 去重
            self.check_completeness(item),   # 字段完整性
            self.check_relevance(item),      # 相关性评分
            self.check_accuracy(item),       # 准确性验证（对 payload 做语法检查等）
        ]
        results = await asyncio.gather(*checks)
        return all(results)

    async def periodic_cleanup(self):
        """定期清理：过期数据、低质量数据、重复数据"""
        await self.remove_duplicates(similarity_threshold=0.95)
        await self.archive_stale_entries(max_age_days=365)
        await self.recalculate_success_rates()

    async def check_duplicate(self, item: "MemoryItem") -> bool:
        """向量近似去重：与已有数据相似度 > 0.95 视为重复"""
        similar = await self.qdrant.search(
            collection=item.collection,
            vector=item.embedding,
            limit=1,
            score_threshold=0.95,
        )
        return len(similar) == 0
```

#### 5.5.3 知识库更新策略

- **自动沉淀**：每次任务结束后，Orchestrator 提炼经验自动入库（经质量检查）
- **人工审核队列**：Agent 提交的高不确定性数据进入审核队列
- **外部同步**：Semgrep/Nuclei 规则仓库每周自动拉取增量更新
- **版本控制**：知识条目支持版本历史，可回滚

---

## 6. Web 控制端设计

### 6.1 架构

```
┌────────────────────────────────────────────────────┐
│                Web 前端 (Next.js 15)                │
│                                                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────┐ │
│  │Dashboard │ │  实时    │ │  攻击面  │ │ 报告 │ │
│  │          │ │  监控    │ │  图谱    │ │ 编辑 │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────┘ │
│                                                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────┐ │
│  │Steering  │ │ 漏洞库   │ │  知识库  │ │ 配置 │ │
│  │  面板    │ │          │ │          │ │      │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────┘ │
└────────────────────┬───────────────────────────────┘
                     │ WS + REST
┌────────────────────▼───────────────────────────────┐
│               API 网关 (FastAPI)                   │
│       Auth (JWT+RBAC) · Rate Limit · Validation    │
└──┬─────────┬─────────┬─────────┬─────────┬─────────┘
   │         │         │         │         │
   ▼         ▼         ▼         ▼         ▼
 Task     Event    Agent     Knowledge  Report
 Mgmt     Stream   Router     Service    Service
```

### 6.2 核心模块详细设计

#### 6.2.1 Dashboard

**布局**

```
┌─────────────────────────────────────────────────────┐
│ Header: 系统名 | 用户菜单 | 全局搜索 | 通知        │
├─────────────────────────────────────────────────────┤
│ Sidebar: 导航                                      │
│  - Dashboard · 任务 · 监控 · 图谱 · 漏洞 · 报告   │
│  - 知识库 · 配置                                   │
├─────────────────────────────────────────────────────┤
│ Main:                                              │
│  ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐          │
│  │运行中 │ │ 待启动│ │ 已完成│ │ 异常  │           │
│  │  12   │ │   3   │ │  45   │ │   1   │           │
│  └───────┘ └───────┘ └───────┘ └───────┘          │
│                                                     │
│  最近任务(卡片网格):                                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │任务1     │ │任务2     │ │任务3     │           │
│  │example   │ │api.target│ │app.target│           │
│  │进度 45% │ │进度 78% │ │已完成   │           │
│  │⚠️ 2个漏洞│ │✓ 1个漏洞 │ │✓ 5个漏洞│           │
│  └──────────┘ └──────────┘ └──────────┘           │
└─────────────────────────────────────────────────────┘
```

#### 6.2.2 实时监控(重头戏)

类似 IDE 的三栏布局:

```
┌─────────┬─────────────────────────────┬─────────────┐
│ 任务树  │ Agent 输出流                 │ 上下文      │
│         │                              │             │
│▼ Task 1 │ [10:31:23] Orchestrator      │ 目标信息    │
│  ▼ Recon│   目标画像:Web 应用 + Node   │ example.com │
│   • sub │   激活策略:web_deep         │             │
│   • port│                              │ 当前阶段    │
│  ▼ Hypo │ [10:31:25] Recon            │ 假设生成    │
│   • H1  │   工具调用:nmap              │             │
│   • H2  │   输入:example.com           │ 相关历史    │
│  ▶ Payl │   结果:开放端口 80,443       │ • 历史任务1 │
│  ▶ Veri │                              │ • 历史任务2 │
│         │ [10:31:30] Code Analyst      │             │
│         │   找到 sink:                 │ 关键发现    │
│         │   - UserDao.java:42          │ ⚠️ SSRF候选│
│         │                              │             │
│         │ [10:32:01] Hypothesizer      │             │
│         │   生成假设 #001:             │             │
│         │   类型:SSRF                  │             │
│         │   信心:0.78                  │             │
│         │                              │             │
├─────────┴─────────────────────────────┴─────────────┤
│ 注入栏: ✏️ 注入指令 (Steering)                     │
└─────────────────────────────────────────────────────┘
```

**技术要点**

- 虚拟滚动(react-window)处理长日志
- 事件流用 SSE,大流量日志分页加载
- 工具调用结果可点击展开
- 节点状态颜色:运行中(蓝)/ 完成(绿)/ 失败(红)/ 暂停(黄)

#### 6.2.3 攻击面图谱

```
┌─────────────────────────────────────────────────────┐
│ [筛选: 全部 | 子域 | 端点 | 漏洞 | 角色]            │
│ [布局: 力导向 | 树状 | 放射] [缩放] [全屏]           │
├─────────────────────────────────────────────────────┤
│                                                     │
│              ┌──────────────┐                       │
│              │ example.com  │                       │
│              └──────┬───────┘                       │
│          ┌──────────┼──────────┐                    │
│          ▼          ▼          ▼                    │
│    ┌──────────┐┌──────────┐┌──────────┐             │
│    │  api.*   ││ admin.*  ││ static.* │             │
│    └────┬─────┘└────┬─────┘└──────────┘             │
│         │          │                                │
│    ┌────▼────┐┌────▼─────┐                          │
│    │  /login ││ /users   │                          │
│    └─────────┘└──────────┘                          │
│                                                     │
│  节点颜色: 🟢 安全  🟡 待验证  🔴 已确认漏洞        │
│  边类型: ── 调用   ⇢ 利用   ··· 触发               │
└─────────────────────────────────────────────────────┘
```

#### 6.2.4 Steering 面板

**核心交互**

1. **注入指令**:任意时刻输入文字,改写 Agent 行为
   
   ```
   停止 SQL 注入测试,转向 SSRF 重点
   新增目标: https://api.example.com/v2
   这个假设不需要,跳过
   ```
2. **暂停/恢复**:任意 Agent 单独控制
3. **接管**:人工直接执行某个工具调用

#### 6.2.5 报告编辑器

```
┌─────────────────────────────────────────────────────┐
│ 报告标题: [编辑中] SSRF via image proxy          │
├─────────────────────────────────────────────────────┤
│ 模板: [▼ 通用 Markdown] [▼ 漏洞盒子] [▼ 补天]      │
├──────────────────┬──────────────────────────────────┤
│ Markdown 编辑器  │ 实时预览                          │
│                  │                                  │
│ # 漏洞概述       │  [渲染后的报告]                   │
│ ## 复现步骤      │                                  │
│ 1. ...           │                                  │
│                  │                                  │
├──────────────────┴──────────────────────────────────┤
│ 自动填充: ✓ 目标  ✓ Payload  ✓ 截图  ⏳ 修复建议   │
│ 状态: [草稿] [已验证] [已提交] [已修复]            │
│ 操作: [保存] [导出] [提交 SRC] [复制 Markdown]    │
└─────────────────────────────────────────────────────┘
```

#### 6.2.6 漏洞库(Vault)

- 列表视图:支持按严重等级、状态、类型筛选
- 详情视图:复现步骤、payload、截图、影响证明
- 状态机:草稿 → 待验证 → 已验证 → 已报告 → 已修复 / 被驳回
- 一键导出:Markdown / HTML / JSON

#### 6.2.7 知识库管理

- 历史漏洞、payload 库、WAF 绕过模式
- 手动导入 + Agent 自动沉淀
- 支持 RAG 检索 + 编辑
- 标签与分类管理

#### 6.2.8 系统配置

- 模型选择 / 切换(主模型 / 小模型分流)
- Agent Prompt 编辑器(支持版本管理 + diff)
- 工具配置 / 沙箱管理
- 权限管理(RBAC)
- 风控阈值(限速、危险操作白名单)

### 6.3 API 设计

#### 6.3.1 REST API 端点（可根据实际情况完善和修改）

```
# 任务管理
POST   /api/v1/tasks                    # 创建任务
GET    /api/v1/tasks                    # 列表
GET    /api/v1/tasks/{id}               # 详情
POST   /api/v1/tasks/{id}/start         # 启动
POST   /api/v1/tasks/{id}/pause         # 暂停
POST   /api/v1/tasks/{id}/resume        # 恢复
POST   /api/v1/tasks/{id}/terminate     # 终止
POST   /api/v1/tasks/{id}/clone         # 克隆
DELETE /api/v1/tasks/{id}               # 删除

# 任务模板
GET    /api/v1/task-templates
POST   /api/v1/task-templates
PUT    /api/v1/task-templates/{id}

# Agent 控制
POST   /api/v1/tasks/{id}/steer         # Steering
GET    /api/v1/tasks/{id}/agents        # 列出 Agent
POST   /api/v1/tasks/{id}/agents/{name}/pause
POST   /api/v1/tasks/{id}/agents/{name}/resume

# 事件流
GET    /api/v1/tasks/{id}/events        # 历史事件(分页)
WS     /api/v1/tasks/{id}/stream        # 实时事件流(SSE 也可)

# 漏洞
GET    /api/v1/tasks/{id}/findings
GET    /api/v1/findings/{fid}
PUT    /api/v1/findings/{fid}
POST   /api/v1/findings/{fid}/tags

# 报告
GET    /api/v1/findings/{fid}/report
PUT    /api/v1/findings/{fid}/report
POST   /api/v1/findings/{fid}/report/export?format=md|html|json

# 知识库
GET    /api/v1/knowledge/vuln-patterns?q=...
POST   /api/v1/knowledge/vuln-patterns
PUT    /api/v1/knowledge/vuln-patterns/{id}
DELETE /api/v1/knowledge/vuln-patterns/{id}

# 攻击面
GET    /api/v1/tasks/{id}/attack-surface
GET    /api/v1/tasks/{id}/attack-surface/graph

# 系统
GET    /api/v1/system/health
GET    /api/v1/system/stats
GET    /api/v1/system/config
PUT    /api/v1/system/config
```

#### 6.3.2 WebSocket 协议

**客户端 → 服务端**

```json
// 订阅
{"action": "subscribe", "task_id": "..."}
{"action": "unsubscribe", "task_id": "..."}

// Steering
{"action": "steer", "task_id": "...", "message": "停止 X,转向 Y"}
{"action": "agent_control", "task_id": "...", "agent": "recon", "action": "pause"}

// 反馈
{"action": "feedback", "event_id": "...", "feedback": "useful" | "useless"}
```

**服务端 → 客户端**

```json
// 事件流
{"type": "event", "data": {...AgentEvent}}

// 状态变更
{"type": "task_status", "task_id": "...", "status": "running"}

// 错误
{"type": "error", "code": "...", "message": "..."}

// 心跳
{"type": "ping", "ts": 1719012345}
```

### 6.4 数据库 Schema（可根据实际情况完善和修改）

```sql
-- 任务表
CREATE TABLE tasks (
    id UUID PRIMARY KEY,
    name VARCHAR(200),
    target_type VARCHAR(50),
    target_config JSONB,
    strategy VARCHAR(50),
    status VARCHAR(20),
    progress JSONB,
    config JSONB,
    created_by UUID,
    created_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_info JSONB
);

-- 任务模板
CREATE TABLE task_templates (
    id UUID PRIMARY KEY,
    name VARCHAR(200),
    target_type VARCHAR(50),
    strategy VARCHAR(50),
    config JSONB,
    created_by UUID,
    created_at TIMESTAMP,
    version INT
);

-- Agent 执行记录
CREATE TABLE agent_executions (
    id UUID PRIMARY KEY,
    task_id UUID REFERENCES tasks(id),
    agent VARCHAR(50),
    status VARCHAR(20),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    cost JSONB,
    summary TEXT
);

-- 事件
CREATE TABLE events (
    id UUID PRIMARY KEY,
    task_id UUID,
    parent_event_id UUID,
    agent VARCHAR(50),
    type VARCHAR(50),
    timestamp TIMESTAMPTZ,
    data JSONB,
    tags TEXT[]
);
CREATE INDEX idx_events_task ON events(task_id, timestamp);

-- 漏洞发现
CREATE TABLE findings (
    id UUID PRIMARY KEY,
    task_id UUID REFERENCES tasks(id),
    hypothesis_id UUID,
    type VARCHAR(50),
    severity VARCHAR(20),
    title VARCHAR(500),
    description TEXT,
    trigger_path JSONB,
    payload TEXT,
    reproduction_steps JSONB,
    evidence JSONB,
    impact_assessment TEXT,
    fix_suggestion TEXT,
    status VARCHAR(20),
    report_id UUID,
    created_at TIMESTAMP,
    verified_at TIMESTAMP
);

-- 报告
CREATE TABLE reports (
    id UUID PRIMARY KEY,
    finding_id UUID REFERENCES findings(id),
    format VARCHAR(20),
    content TEXT,
    version INT,
    created_by UUID,
    created_at TIMESTAMP,
    submitted_to JSONB
);

-- 知识库:漏洞模式
CREATE TABLE vuln_patterns (
    id UUID PRIMARY KEY,
    type VARCHAR(50),
    description TEXT,
    example_payload TEXT,
    bypass_techniques TEXT[],
    tags TEXT[],
    success_rate FLOAT,
    created_by UUID,
    created_at TIMESTAMP,
    embedding vector(1536)
);

-- 用户与权限
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(100) UNIQUE,
    email VARCHAR(200),
    password_hash VARCHAR(200),
    role VARCHAR(50),
    created_at TIMESTAMP,
    last_login_at TIMESTAMP
);

CREATE TABLE roles (
    id UUID PRIMARY KEY,
    name VARCHAR(50) UNIQUE,
    permissions TEXT[]
);

-- 操作审计
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY,
    user_id UUID,
    action VARCHAR(100),
    target_type VARCHAR(50),
    target_id UUID,
    details JSONB,
    ip_address VARCHAR(45),
    created_at TIMESTAMP
);

-- ══════════════════════════════════════
-- 补充索引设计
-- ══════════════════════════════════════

-- 任务表: 按状态 + 创建时间查询(Dashboard 列表)
CREATE INDEX idx_tasks_status ON tasks(status, created_at DESC);
CREATE INDEX idx_tasks_created_by ON tasks(created_by, created_at DESC);

-- Agent 执行记录: 按任务 + Agent 查询
CREATE INDEX idx_agent_exec_task ON agent_executions(task_id, agent);

-- 事件表: 按 Agent 类型过滤(监控页按 Agent 筛选)
CREATE INDEX idx_events_agent ON events(task_id, agent, timestamp);
CREATE INDEX idx_events_type ON events(task_id, type);

-- 漏洞发现: 按类型/严重等级/状态查询(漏洞库筛选)
CREATE INDEX idx_findings_task ON findings(task_id, created_at DESC);
CREATE INDEX idx_findings_type_severity ON findings(type, severity);
CREATE INDEX idx_findings_status ON findings(status);

-- 报告表: 按 finding 查询
CREATE INDEX idx_reports_finding ON reports(finding_id);

-- 知识库: 按类型 + 标签查询 + 向量相似度检索(HNSW)
CREATE INDEX idx_vuln_patterns_type ON vuln_patterns(type);
CREATE INDEX idx_vuln_patterns_embedding ON vuln_patterns
    USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64);

-- 审计日志: 按用户 + 时间范围查询
CREATE INDEX idx_audit_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_action ON audit_logs(action, created_at DESC);
CREATE INDEX idx_audit_target ON audit_logs(target_type, target_id);

-- 事件表分区(大表优化): 按月分区
-- 生产环境建议改为分区表
-- CREATE TABLE events (...) PARTITION BY RANGE (timestamp);
-- CREATE TABLE events_2026_06 PARTITION OF events
--     FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
```

### 6.5 鉴权与权限

**RBAC 角色**

| 角色       | 权限                 |
| -------- | ------------------ |
| Admin    | 全部                 |
| Operator | 任务启停、Steering、报告编辑 |
| Analyst  | 只读 + 打标签 + 写评论     |
| Viewer   | 只读                 |
| Auditor  | 只读 + 看审计日志         |

**实现**

- JWT + Refresh Token
- 权限中间件:基于 Casbin 或自研
- 操作审计:所有写操作进 audit_logs

### 6.6 部署架构

**单机起步(Docker Compose)**

```yaml
version: '3.8'
services:
  web:
    image: vuln-agent-web:latest
    ports: ["3000:3000"]

  api:
    image: vuln-agent-api:latest
    ports: ["8000:8000"]

  agent-worker:
    image: vuln-agent-worker:latest
    deploy:
      replicas: 3

  postgres:
    image: postgres:16
    volumes: ["pgdata:/var/lib/postgresql/data"]

  qdrant:
    image: qdrant/qdrant:latest

  neo4j:
    image: neo4j:latest

  minio:
    image: minio/minio:latest

  nats:
    image: nats:latest

  redis:
    image: redis:7
```

**生产部署(K8s)**

- Web / API：Deployment + HPA + Ingress
- Agent Workers：Deployment + HPA(基于队列长度扩缩)
- 数据库：StatefulSet + 持久化卷
- 沙箱：Node 上预装 Docker / Firecracker
- 监控：Prometheus + Grafana + Loki

### 6.7 前端状态管理与实时通信

#### 6.7.1 状态管理架构

```
┌─────────────────────────────────────────────────┐
│                   React 组件树                    │
├──────────┬──────────┬──────────┬────────────────┤
│ 全局状态  │ 服务端状态 │ 实时状态   │ UI 状态         │
│ Zustand  │ TanStack │ WebSocket│ React State   │
│          │ Query    │ Store    │               │
│ • 用户   │ • 任务列表│ • 事件流  │ • 面板展开     │
│ • 配置   │ • 漏洞库  │ • Agent  │ • 选中节点     │
│ • 权限   │ • 知识库  │   状态    │ • 过滤条件     │
│          │ • 报告   │ • 通知   │               │
└──────────┴──────────┴──────────┴────────────────┘
```

**技术选型理由**

| 分层     | 方案             | 理由                              |
| ------ | -------------- | ------------------------------- |
| 全局状态   | Zustand        | 轻量(< 1KB),无 boilerplate,支持中间件   |
| 服务端缓存  | TanStack Query | 自动缓存、重验证、乐观更新                   |
| 实时状态   | 自建 WebSocket Store | 事件流数据结构特殊,通用方案不适合               |
| UI 局部状态 | React useState | 无需共享的组件内状态                      |

#### 6.7.2 WebSocket 管理

```typescript
interface WSManagerConfig {
  url: string;
  reconnectIntervalMs: number;    // 初始重连间隔: 1000ms
  maxReconnectIntervalMs: number; // 最大重连间隔: 30000ms
  maxReconnectAttempts: number;   // 最大重连次数: 20
  heartbeatIntervalMs: number;    // 心跳间隔: 15000ms
  bufferSize: number;             // 离线消息缓冲区大小
}

class WSManager {
  private ws: WebSocket | null;
  private reconnectAttempts: number;
  private messageBuffer: QueuedMessage[];   // 断线期间缓存的发送消息
  private eventBuffer: RingBuffer<AgentEvent>; // 接收事件的环形缓冲区

  connect(taskId: string): void;
  disconnect(): void;
  send(message: WSClientMessage): void;

  // 自动重连: 指数退避 + 抖动
  private scheduleReconnect(): void {
    const delay = Math.min(
      this.config.reconnectIntervalMs * Math.pow(2, this.reconnectAttempts)
        + Math.random() * 1000,
      this.config.maxReconnectIntervalMs
    );
    setTimeout(() => this.connect(this.currentTaskId), delay);
  }

  // 重连成功后:
  // 1. 发送缓冲区中的待发消息
  // 2. 请求服务端补发断线期间的事件(基于 lastEventId)
  private onReconnected(): void;
}
```

**断线补偿协议**

```json
// 客户端重连后发送
{"action": "replay", "task_id": "...", "after_event_id": "last_known_event_id"}

// 服务端响应: 批量补发缺失事件
{"type": "replay_batch", "events": [...], "has_more": false}
```

#### 6.7.3 事件流前端缓存

```typescript
class EventStreamCache {
  private events: Map<string, RingBuffer<AgentEvent>>; // taskId -> 环形缓冲区
  private maxEventsPerTask: number = 10_000;

  // 追加事件(自动淘汰最旧事件)
  append(taskId: string, event: AgentEvent): void;

  // 按类型/Agent 过滤(前端实时过滤,无需请求服务端)
  filter(taskId: string, filters: EventFilter): AgentEvent[];

  // 历史事件分页加载(超出缓冲区的部分请求服务端)
  async loadHistory(taskId: string, before: string, limit: number): Promise<AgentEvent[]>;
}
```

---

## 7. 安全与合规

### 7.1 多层防御

```
┌─────────────────────────────────────────┐
│ L1: 鉴权层(JWT + RBAC + 操作审计)       │
├─────────────────────────────────────────┤
│ L2: API 层(输入校验、限流、熔断)         │
├─────────────────────────────────────────┤
│ L3: Agent 层(Prompt 注入防护、输出过滤) │
├─────────────────────────────────────────┤
│ L4: 沙箱层(网络隔离、资源限制、危险拦截) │
├─────────────────────────────────────────┤
│ L5: 数据层(加密存储、密钥管理)           │
└─────────────────────────────────────────┘
```

### 7.2 Prompt 注入防护

- 系统提示与用户输入严格隔离
- 工具输出做语义清洗(防止工具返回恶意指令)
- 高风险操作二次确认

### 7.3 风控规则

```yaml
risk_rules:
  - name: "禁止无授权目标"
    condition: "target.not_in_whitelist"
    action: "block"

  - name: "写操作限速"
    condition: "tool.category == 'write'"
    action: "rate_limit: 10/min"

  - name: "高危操作二次确认"
    condition: "tool.risk_level >= L2"
    action: "require_human_approval"

  - name: "禁止攻击非目标资产"
    condition: "request.host not in task.target_hosts"
    action: "block"
```

### 7.4 合规

- 所有任务必须有授权范围白名单
- 操作记录可追溯(审计日志)
- 漏洞数据加密存储,只有授权用户可访问
- 支持数据导出和删除(GDPR-like)
- 定期安全审计与渗透测试

### 7.5 密钥与凭据管理

#### 7.5.1 密钥分类

| 密钥类型          | 示例                              | 存储位置        | 访问控制      |
| ------------- | ------------------------------- | ----------- | --------- |
| LLM API Key   | Anthropic API Key, OpenAI Key   | HashiCorp Vault | 仅 Agent Worker |
| 目标认证凭据        | Bearer Token, Cookie, API Key   | Vault + 任务级隔离 | 仅关联任务的 Agent |
| 数据库凭据         | PostgreSQL, Neo4j, Qdrant 密码    | Vault       | 仅后端服务     |
| JWT 签名密钥      | HS256 / RS256 密钥                | Vault       | 仅 API 网关  |
| 第三方集成         | GitHub Token, SRC 平台凭据          | Vault       | 仅 Reporter |

#### 7.5.2 架构

```
┌──────────────────────────────────────────────────┐
│                 HashiCorp Vault                   │
│                                                   │
│  ┌─────────────┐ ┌─────────────┐ ┌────────────┐ │
│  │ KV Engine   │ │ Transit     │ │ PKI        │ │
│  │ (静态密钥)   │ │ (加密即服务)  │ │ (证书管理)  │ │
│  └──────┬──────┘ └──────┬──────┘ └─────┬──────┘ │
└─────────┼───────────────┼──────────────┼─────────┘
          │               │              │
     ┌────▼────┐    ┌─────▼────┐   ┌────▼─────┐
     │ API Key │    │ 漏洞数据  │   │ mTLS     │
     │ 读取    │    │ 字段级加密 │   │ 服务间通信│
     └─────────┘    └──────────┘   └──────────┘
```

**核心原则**

- **零信任**：密钥不写入配置文件、环境变量或代码仓库
- **最小权限**：每个服务只能访问其所需的密钥路径
- **自动轮转**：LLM API Key 和数据库密码支持自动轮转
- **审计追踪**：所有密钥访问记录可追溯

```python
class SecretManager:
    """密钥管理封装"""

    async def get_llm_key(self, provider: str) -> str:
        """从 Vault 获取 LLM API Key，带本地缓存(TTL 5min)"""
        return await self.vault.read(f"secret/llm/{provider}")

    async def get_task_credential(self, task_id: str) -> dict:
        """获取任务级目标凭据，仅该任务的 Agent 可访问"""
        return await self.vault.read(f"secret/tasks/{task_id}/credential")

    async def encrypt_field(self, plaintext: str) -> str:
        """使用 Vault Transit 加密敏感字段（漏洞详情、payload 等）"""
        return await self.vault.encrypt("transit/encrypt/vuln-data", plaintext)

    async def rotate_key(self, path: str):
        """触发密钥轮转"""
        await self.vault.rotate(path)
```

#### 7.5.3 部署简化方案

对于单机 / 小团队部署，可用轻量替代方案：

| 规模   | 方案              | 说明             |
| ---- | --------------- | -------------- |
| 单机开发 | `.env` + SOPS   | SOPS 加密 env 文件 |
| 小团队  | Docker Secrets  | Compose 内置密钥管理 |
| 生产环境 | HashiCorp Vault | 完整密钥管理         |

---

## 8. 性能与可扩展性

### 8.1 并发模型

- Agent Workers 横向扩展,基于任务队列负载
- 每个 Worker 处理 1-N 个任务(取决于资源)
- 模型推理用流式输出,降低首 token 延迟

### 8.2 资源调度

```python
class ResourceScheduler:
    async def allocate(self, task: Task) -> Resources:
        if task.strategy == "binary_fuzz":
            return Resources(cpu="4", memory="16G", gpu=False)
        elif task.strategy == "llm_specific":
            return Resources(cpu="2", memory="8G", gpu=True)
        else:
            return Resources(cpu="1", memory="4G", gpu=False)
```

### 8.3 性能指标

| 指标             | 目标             |
| -------------- | -------------- |
| 任务启动延迟         | < 5s           |
| 事件到前端延迟        | < 200ms (P95)  |
| 单任务吞吐          | 10-50 events/s |
| 并发任务数          | 100+           |
| 知识库检索          | < 100ms (P95)  |
| LLM 首 token 延迟 | < 1s (P95)     |

### 8.4 可扩展性

- 无状态服务：Web / API / Workers 全部无状态
- 数据库水平扩展：PostgreSQL 读写分离、向量库分片
- 任务分片：大任务拆分成子任务并行执行

### 8.5 成本估算与控制

#### 8.5.1 单次任务 LLM 成本估算

| 策略            | Opus Token   | Sonnet Token  | Haiku Token   | 预估成本(USD) |
| ------------- | ------------ | ------------- | ------------- | --------- |
| web_broad     | 100K         | 200K          | 200K          | $3 - $5   |
| web_deep      | 300K         | 500K          | 300K          | $12 - $18 |
| api_focused   | 200K         | 300K          | 200K          | $7 - $10  |
| mobile_re     | 150K         | 400K          | 100K          | $8 - $12  |
| llm_specific  | 250K         | 350K          | 150K          | $10 - $15 |

> 基于 Claude API 定价(Opus: $15/$75 per 1M, Sonnet: $3/$15 per 1M, Haiku: $0.25/$1.25 per 1M)。
> 含 Debate 机制的假设生成会增加约 40% 的 Hypothesizer 消耗。

#### 8.5.2 基础设施月度成本

| 组件            | 规格              | 月成本(USD) | 备注       |
| ------------- | --------------- | -------- | -------- |
| API Server    | 2C4G × 2       | $40      | 可按需扩缩    |
| Agent Worker  | 4C8G × 3       | $120     | 主要成本项    |
| PostgreSQL    | 2C4G + 100G SSD | $50      | 含 pgvector |
| Qdrant        | 2C4G + 50G SSD  | $40      |          |
| Neo4j         | 2C4G + 50G SSD  | $40      |          |
| MinIO         | 2C2G + 200G HDD | $20      |          |
| NATS + Redis  | 1C2G × 2       | $20      |          |
| 监控栈          | 2C4G            | $20      | Prometheus + Grafana |
| **小计**        |                 | **$350** | 不含 LLM API |

#### 8.5.3 成本控制机制

```python
class CostController:
    """多层成本控制"""

    # 层级 1: 任务级预算
    task_budget_usd: float = 20.0          # 单任务默认上限

    # 层级 2: 日预算
    daily_budget_usd: float = 200.0        # 每日总上限

    # 层级 3: 月预算
    monthly_budget_usd: float = 3000.0     # 月度总上限

    async def check_budget(self, task_id: str, estimated_cost: float) -> bool:
        """调用 LLM 前检查预算"""
        task_spent = await self.get_task_spent(task_id)
        daily_spent = await self.get_daily_spent()

        if task_spent + estimated_cost > self.task_budget_usd:
            await self.emit_alert("task_budget_exceeded", task_id)
            return False
        if daily_spent + estimated_cost > self.daily_budget_usd:
            await self.emit_alert("daily_budget_exceeded")
            return False
        return True

    async def on_budget_exceeded(self, task_id: str, level: str):
        """预算超限处理"""
        if level == "task":
            # 自动降级模型 + 通知用户
            await self.downgrade_models(task_id)
        elif level == "daily":
            # 暂停所有非关键任务
            await self.pause_non_critical_tasks()
```

### 8.6 可观测性设计

#### 8.6.1 三支柱架构

```
┌─────────────────────────────────────────────────┐
│                  Grafana Dashboard               │
├────────────┬────────────────┬───────────────────┤
│  Metrics   │    Traces      │     Logs          │
│ Prometheus │  OpenTelemetry │     Loki          │
│            │   + Jaeger     │                   │
│ • 系统指标  │ • 请求链路追踪  │ • 结构化日志       │
│ • 业务指标  │ • Agent 调用链  │ • 工具执行日志     │
│ • LLM 指标 │ • LLM 调用追踪  │ • 安全审计日志     │
└────────────┴────────────────┴───────────────────┘
```

#### 8.6.2 自定义 Prometheus 指标

```python
from prometheus_client import Counter, Histogram, Gauge

# ── 任务指标 ──
tasks_total = Counter("vuln_tasks_total", "Total tasks", ["strategy", "status"])
tasks_active = Gauge("vuln_tasks_active", "Currently active tasks")
task_duration = Histogram("vuln_task_duration_seconds", "Task duration",
    buckets=[60, 300, 600, 1800, 3600, 7200])

# ── Agent 指标 ──
agent_invocations = Counter("vuln_agent_invocations_total", "Agent calls", ["agent", "status"])
agent_duration = Histogram("vuln_agent_duration_seconds", "Agent execution time", ["agent"])
agent_circuit_breaker = Gauge("vuln_agent_circuit_breaker", "Circuit breaker state", ["agent"])

# ── LLM 指标 ──
llm_requests = Counter("vuln_llm_requests_total", "LLM API calls", ["model", "agent", "status"])
llm_tokens_input = Counter("vuln_llm_tokens_input_total", "Input tokens", ["model", "agent"])
llm_tokens_output = Counter("vuln_llm_tokens_output_total", "Output tokens", ["model", "agent"])
llm_cost_usd = Counter("vuln_llm_cost_usd_total", "LLM cost in USD", ["model", "agent"])
llm_latency = Histogram("vuln_llm_first_token_seconds", "Time to first token", ["model"])

# ── 漏洞指标 ──
hypotheses_generated = Counter("vuln_hypotheses_total", "Hypotheses generated", ["type", "outcome"])
findings_confirmed = Counter("vuln_findings_total", "Confirmed vulnerabilities", ["type", "severity"])
false_positive_rate = Gauge("vuln_false_positive_rate", "Current false positive rate")

# ── 工具指标 ──
tool_executions = Counter("vuln_tool_executions_total", "Tool executions", ["tool", "status"])
tool_duration = Histogram("vuln_tool_duration_seconds", "Tool execution time", ["tool"])
sandbox_violations = Counter("vuln_sandbox_violations_total", "Sandbox security violations", ["type"])
```

#### 8.6.3 OpenTelemetry 链路追踪

```python
from opentelemetry import trace

tracer = trace.get_tracer("vuln-agent")

async def run_agent_with_tracing(agent: str, input_data: dict):
    with tracer.start_as_current_span(f"agent.{agent}") as span:
        span.set_attribute("agent.name", agent)
        span.set_attribute("task.id", input_data["task_id"])

        # LLM 调用追踪
        with tracer.start_as_current_span("llm.completion") as llm_span:
            llm_span.set_attribute("llm.model", model)
            llm_span.set_attribute("llm.tokens_in", tokens_in)
            result = await call_llm(...)
            llm_span.set_attribute("llm.tokens_out", tokens_out)

        # 工具调用追踪
        with tracer.start_as_current_span("tool.execution") as tool_span:
            tool_span.set_attribute("tool.name", tool_name)
            tool_span.set_attribute("tool.risk_level", risk_level)
            output = await execute_tool(...)

        return result
```

#### 8.6.4 告警规则

```yaml
# prometheus-alerts.yml
groups:
  - name: vuln-agent-alerts
    rules:
      # LLM 成本告警
      - alert: LLMDailyCostHigh
        expr: sum(increase(vuln_llm_cost_usd_total[24h])) > 150
        labels: { severity: warning }
        annotations:
          summary: "日 LLM 开销超过 $150"

      # Agent 熔断告警
      - alert: AgentCircuitOpen
        expr: vuln_agent_circuit_breaker == 2  # OPEN state
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "Agent {{ $labels.agent }} 熔断超过 5 分钟"

      # 误报率告警
      - alert: HighFalsePositiveRate
        expr: vuln_false_positive_rate > 0.7
        for: 30m
        labels: { severity: warning }
        annotations:
          summary: "误报率超过 70%,需检查 Hypothesizer 质量"

      # 沙箱安全告警
      - alert: SandboxViolation
        expr: increase(vuln_sandbox_violations_total[5m]) > 0
        labels: { severity: critical }
        annotations:
          summary: "检测到沙箱安全违规"

      # 任务堆积告警
      - alert: TaskQueueBacklog
        expr: vuln_tasks_active > 50
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "活跃任务数超过 50,可能需要扩容"
```

#### 8.6.5 结构化日志规范

```python
import structlog

logger = structlog.get_logger()

# 所有日志统一格式
logger.info("agent_started",
    task_id=task_id,
    agent="hypothesizer",
    model="claude-opus-4",
    iteration=3,
)

logger.warning("budget_threshold",
    task_id=task_id,
    threshold=0.8,
    spent_usd=16.0,
    total_usd=20.0,
)

logger.error("tool_execution_failed",
    task_id=task_id,
    tool="sqlmap",
    error_type="timeout",
    duration_s=300,
    will_retry=True,
)
```

**日志级别策略**

| 级别      | 用途                     | 保留期限  |
| ------- | ---------------------- | ----- |
| DEBUG   | Agent 思考过程、工具原始输出      | 7 天   |
| INFO    | 状态变更、阶段完成、关键决策        | 30 天  |
| WARNING | 预算告警、重试、降级             | 90 天  |
| ERROR   | 工具失败、Agent 崩溃、沙箱违规    | 180 天 |

### 8.7 数据备份与灾难恢复

#### 8.7.1 备份策略

| 数据类型       | 备份方式             | 频率   | 保留期限 | RPO    |
| ---------- | ---------------- | ---- | ---- | ------ |
| PostgreSQL | pg_dump 全量 + WAL 增量 | 日/实时 | 30 天 | < 5 min |
| Qdrant     | Snapshot API     | 日    | 14 天 | < 24h  |
| Neo4j      | neo4j-admin dump | 日    | 14 天 | < 24h  |
| MinIO      | mc mirror 增量同步   | 每 6h | 30 天 | < 6h   |
| Vault      | Raft Snapshot    | 日    | 90 天 | < 24h  |

#### 8.7.2 灾难恢复

```
RTO 目标:
  - 核心服务(API + Agent): < 30 分钟
  - 全量数据恢复: < 4 小时
  - 完整系统恢复: < 8 小时

恢复优先级:
  1. PostgreSQL(任务状态、漏洞数据)
  2. Vault(密钥,否则其他服务无法启动)
  3. API + Agent Workers
  4. Qdrant + Neo4j(知识库,可降级运行)
  5. MinIO(历史截图等,最后恢复)
```

**自动化恢复脚本**

```yaml
# disaster-recovery.yml
recovery_steps:
  - name: "恢复 PostgreSQL"
    command: "pg_restore -d vulnagent /backup/latest/pg_dump.sql"
    verify: "SELECT count(*) FROM tasks"
    timeout: 30m

  - name: "恢复 Vault"
    command: "vault operator raft snapshot restore /backup/latest/vault.snap"
    verify: "vault status"
    timeout: 10m

  - name: "启动核心服务"
    command: "docker-compose up -d api agent-worker"
    verify: "curl -f http://localhost:8000/api/v1/system/health"
    timeout: 5m

  - name: "恢复知识库"
    command: |
      qdrant-restore /backup/latest/qdrant/
      neo4j-admin database load --from=/backup/latest/neo4j.dump
    verify: "curl -f http://localhost:6333/healthz"
    timeout: 60m
```

### 8.8 多租户设计

#### 8.8.1 隔离架构

采用**行级隔离**(Row-Level Security) + **逻辑分区**方案,平衡隔离性与运维成本：

```sql
-- 所有核心表增加 tenant_id 列
ALTER TABLE tasks ADD COLUMN tenant_id UUID NOT NULL;
ALTER TABLE findings ADD COLUMN tenant_id UUID NOT NULL;
ALTER TABLE events ADD COLUMN tenant_id UUID NOT NULL;
ALTER TABLE reports ADD COLUMN tenant_id UUID NOT NULL;

-- 租户表
CREATE TABLE tenants (
    id UUID PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    slug VARCHAR(50) UNIQUE NOT NULL,
    plan VARCHAR(50) DEFAULT 'free',     -- free | pro | enterprise
    config JSONB,                         -- 租户级配置覆盖
    quota JSONB,                          -- 配额限制
    created_at TIMESTAMPTZ
);

-- PostgreSQL RLS 策略
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tasks
    USING (tenant_id = current_setting('app.current_tenant')::UUID);
```

#### 8.8.2 资源配额

```python
@dataclass
class TenantQuota:
    max_concurrent_tasks: int        # 最大并发任务数
    max_daily_tasks: int             # 每日任务上限
    max_monthly_llm_tokens: int      # 月 LLM Token 配额
    max_monthly_cost_usd: float      # 月成本上限
    max_knowledge_entries: int       # 知识库条目上限
    max_storage_gb: float            # 存储空间上限
    allowed_strategies: list[str]    # 允许的策略类型
    allowed_tools: list[str]         # 允许的工具列表

PLAN_QUOTAS = {
    "free":       TenantQuota(max_concurrent_tasks=1,  max_daily_tasks=3,   max_monthly_llm_tokens=500_000,   max_monthly_cost_usd=50),
    "pro":        TenantQuota(max_concurrent_tasks=5,  max_daily_tasks=20,  max_monthly_llm_tokens=5_000_000, max_monthly_cost_usd=500),
    "enterprise": TenantQuota(max_concurrent_tasks=20, max_daily_tasks=100, max_monthly_llm_tokens=50_000_000, max_monthly_cost_usd=5000),
}
```

#### 8.8.3 知识库隔离

| 知识库分区   | 数据归属     | 隔离方式                 |
| ------- | -------- | -------------------- |
| 全局公共库   | 平台维护     | 所有租户只读               |
| 租户私有库   | 租户独占     | tenant_id 过滤         |
| 团队共享库   | 团队内共享    | team_id 过滤           |

- Qdrant：按 tenant_id 做 payload 过滤,检索时自动注入租户条件
- Neo4j：节点和边均携带 tenant_id 属性,查询时加 WHERE 约束

---

## 9. 实施路线

### 9.1 阶段规划

#### Phase 1: MVP(4-6 周)

- [ ] 基础架构:任务队列 + 事件存储 + Agent 框架
- [ ] 3 个核心 Agent:Orchestrator + Hypothesizer + Verifier
- [ ] Web 控制端 V0.1:Dashboard + 实时日志 + 启停
- [ ] 基础工具集成:5-10 个核心工具
- [ ] 单一目标类型支持:Web API
- [ ] 报告生成:Markdown 模板

#### Phase 2: 能力扩展(6-8 周)

- [ ] 全部 7 个 Agent 上线
- [ ] Recon Agent + Code Analyst 完整功能
- [ ] Web 控制端 V0.2:攻击面图谱
- [ ] Steering 面板
- [ ] Payload 变异器
- [ ] 知识库基础版(Vector + Graph)
- [ ] 多目标类型支持(Web + API + Mobile)

#### Phase 3: 强化(8-10 周)

- [ ] Hypothesizer Debate 机制
- [ ] 自研 Fuzzer
- [ ] LLM 应用漏洞专项
- [ ] Web 控制端 V0.3:报告编辑器 + SRC 一键提交
- [ ] 团队协作功能
- [ ] 跨任务学习(postmortem 自动提炼)

#### Phase 4: 生产化(8-10 周)

- [ ] K8s 部署
- [ ] 完整风控规则
- [ ] 多租户支持
- [ ] 完整审计与合规
- [ ] 监控告警(Prometheus + Grafana)
- [ ] 性能优化与压测

### 9.2 关键里程碑

| 里程碑        | 时间     | 验证标准                         |
| ---------- | ------ | ---------------------------- |
| M1: 闭环跑通   | 第 6 周  | 能完成一个 Web API 的端到端漏洞挖掘,产出报告  |
| M2: 真实目标验证 | 第 14 周 | 在授权目标上挖到至少 1 个有效漏洞           |
| M3: 团队可用   | 第 24 周 | 3-5 个白帽子可以同时使用,产出可提交 SRC 的报告 |
| M4: 生产化    | 第 32 周 | 通过安全审计,可对外提供服务               |

### 9.3 团队建议

最小团队配置:

- 1 后端工程师(FastAPI + Python 生态)
- 1 前端工程师(Next.js + React)
- 1 安全工程师(漏洞挖掘 + 工具集成)
- 0.5 DevOps(部署 + 监控)
- 0.5 PM / 架构

### 9.4 测试策略

#### 9.4.1 测试分层

```
┌─────────────────────────────────────────────────┐
│         E2E 测试 (端到端流程验证)                  │
│         Playwright + 靶场环境                     │
├─────────────────────────────────────────────────┤
│       集成测试 (Agent 协作 + 工具链)               │
│       pytest + Docker Compose 测试环境            │
├─────────────────────────────────────────────────┤
│     单元测试 (各模块独立验证)                       │
│     pytest + mock                               │
├─────────────────────────────────────────────────┤
│   LLM 质量评估 (Agent 输出质量)                    │
│   自定义评估框架 + 基准数据集                       │
└─────────────────────────────────────────────────┘
```

#### 9.4.2 单元测试

| 模块             | 测试重点                     | Mock 策略           |
| -------------- | ------------------------ | ----------------- |
| Blackboard     | 读写协议、乐观锁、权限矩阵            | 内存实现              |
| ModelRouter    | 路由选择、降级逻辑                | Mock LLM 返回       |
| TokenBudget    | 预算消耗、告警触发、超限处理           | 无需 Mock            |
| PayloadMutator | 变异正确性、编码完整性              | 无需 Mock            |
| CostController | 多层预算检查                   | Mock DB 查询         |
| CircuitBreaker | 状态转换、阈值判定                | 无需 Mock            |
| RiskAssessor   | 危险等级判定                   | Mock 工具输出          |

```python
# 示例: Blackboard 单元测试
class TestBlackboard:
    async def test_optimistic_lock(self):
        bb = Blackboard(task_id="test")
        await bb.write("hypotheses", [{"id": "h1"}], agent="hypothesizer")
        v1 = bb.version
        # 并发写入应触发版本冲突
        with pytest.raises(VersionConflictError):
            await bb.cas("hypotheses", expected_version=v1 - 1, data=[], agent="other")

    async def test_permission_matrix(self):
        bb = Blackboard(task_id="test")
        # Recon 不应该能写 hypotheses
        with pytest.raises(PermissionDeniedError):
            await bb.write("hypotheses", [], agent="recon")
```

#### 9.4.3 集成测试

```python
# 使用 Docker Compose 启动完整测试环境
# conftest.py
@pytest.fixture(scope="session")
async def test_env():
    """启动测试环境: PostgreSQL + Qdrant + NATS + 靶场"""
    compose = DockerCompose("tests/docker-compose.test.yml")
    compose.start()
    yield compose
    compose.stop()

@pytest.fixture
async def vulnerable_target(test_env):
    """启动已知漏洞靶场(DVWA / WebGoat / 自建靶场)"""
    return await test_env.start_service("dvwa")

class TestAgentIntegration:
    async def test_recon_to_hypothesis_flow(self, test_env, vulnerable_target):
        """测试: Recon → Hypothesizer 的数据流"""
        recon_result = await run_recon_agent(target=vulnerable_target.url)
        assert len(recon_result["endpoints"]) > 0

        hypotheses = await run_hypothesizer(recon_result)
        assert len(hypotheses) > 0
        assert all(h["confidence"] > 0 for h in hypotheses)

    async def test_full_pipeline_on_known_vuln(self, test_env, vulnerable_target):
        """测试: 对已知存在 SQLi 的靶场跑完整流程,应能发现漏洞"""
        result = await run_full_task(
            target=vulnerable_target.url,
            strategy="web_deep",
            known_vuln_type="sql_injection",
        )
        sqli_findings = [f for f in result["findings"] if f["type"] == "sql_injection"]
        assert len(sqli_findings) >= 1
```

#### 9.4.4 LLM 输出质量评估

```python
class AgentQualityBenchmark:
    """评估 Agent 输出质量的基准测试"""

    # 基准数据集: 已知漏洞的目标 + 预期输出
    BENCHMARK_CASES = [
        {
            "target": "dvwa_sqli",
            "expected_vuln_types": ["sql_injection"],
            "expected_min_confidence": 0.6,
        },
        {
            "target": "juice_shop_xss",
            "expected_vuln_types": ["xss"],
            "expected_min_confidence": 0.5,
        },
    ]

    async def evaluate_hypothesizer(self) -> dict:
        """评估假设生成器的准确率"""
        results = {"precision": 0, "recall": 0, "f1": 0}
        for case in self.BENCHMARK_CASES:
            hypotheses = await self.run_hypothesizer(case["target"])
            tp = len([h for h in hypotheses if h["type"] in case["expected_vuln_types"]])
            fp = len([h for h in hypotheses if h["type"] not in case["expected_vuln_types"]])
            fn = len(case["expected_vuln_types"]) - tp
            results["precision"] += tp / (tp + fp) if (tp + fp) > 0 else 0
            results["recall"] += tp / (tp + fn) if (tp + fn) > 0 else 0
        # 平均
        n = len(self.BENCHMARK_CASES)
        results = {k: v / n for k, v in results.items()}
        results["f1"] = 2 * results["precision"] * results["recall"] / (results["precision"] + results["recall"]) if (results["precision"] + results["recall"]) > 0 else 0
        return results

    async def evaluate_false_positive_rate(self) -> float:
        """在无漏洞靶场上跑,检查误报率"""
        clean_target = "secure_app_no_vulns"
        findings = await self.run_full_task(clean_target)
        return len(findings) / max(len(findings) + 1, 1)  # 目标: < 0.1
```

#### 9.4.5 靶场环境

| 靶场         | 用途         | 漏洞类型覆盖                   |
| ---------- | ---------- | ------------------------ |
| DVWA       | 基础 Web 漏洞  | SQLi, XSS, CSRF, LFI    |
| WebGoat    | OWASP Top 10 | 全覆盖                     |
| Juice Shop | 现代 Web 应用  | NoSQLi, JWT, SSRF        |
| 自建靶场       | 业务逻辑漏洞     | 越权、支付逻辑、状态机绕过            |
| VAmPI      | API 漏洞     | BOLA, BFLA, 注入           |

#### 9.4.6 CI/CD 集成

```yaml
# .github/workflows/test.yml
name: Test Pipeline
on: [push, pull_request]
jobs:
  unit-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -r requirements-dev.txt
      - run: pytest tests/unit/ -v --cov=src --cov-report=xml

  integration-test:
    runs-on: ubuntu-latest
    needs: unit-test
    services:
      postgres: { image: postgres:16 }
      qdrant: { image: qdrant/qdrant }
    steps:
      - run: pytest tests/integration/ -v --timeout=300

  quality-benchmark:
    runs-on: ubuntu-latest
    needs: integration-test
    # 仅在 main 分支或手动触发时执行(消耗 LLM Token)
    if: github.ref == 'refs/heads/main' || github.event_name == 'workflow_dispatch'
    steps:
      - run: pytest tests/benchmark/ -v --timeout=600
      - run: python scripts/check_quality_regression.py
```

---

## 10. 附录

### 10.1 任务配置示例

```yaml
# task_config.yaml
name: "Example API SRC Scan"
target_type: api
strategy: api_focused

target:
  base_url: "https://api.example.com"
  auth:
    type: "bearer"
    token: "${API_TOKEN}"
  scope:
    paths:
      - "/v1/users"
      - "/v1/payments"
      - "/v1/admin/*"
    excluded_paths:
      - "/v1/health"

agents:
  orchestrator:
    enabled: true
    model: "claude-opus-4"
  recon:
    enabled: true
    tools: ["katana", "linkfinder"]
    max_duration: 1800
  code_analyst:
    enabled: false
  hypothesizer:
    enabled: true
    debate_rounds: 2
    confidence_threshold: 0.6
  payload_crafter:
    enabled: true
    mutation_count: 5
  verifier:
    enabled: true
    require_approval_for: ["L2", "L3"]
  reporter:
    enabled: true
    template: "markdown_generic"

knowledge:
  vector_search:
    enabled: true
    collections: ["vuln_patterns", "payload_templates"]
  graph_search:
    enabled: true

safety:
  max_payload_attempts: 100
  pause_on_error: true
  require_human_approval_for: ["admin_writes", "data_deletion"]
```

### 10.2 Agent Prompt 示例

**Orchestrator**

```
你是漏洞挖掘任务的总指挥。你的职责是:
1. 根据目标特征做画像(技术栈、暴露面、价值模块)
2. 选择合适的挖掘策略
3. 调度其他 Agent,确保资源高效利用
4. 处理异常情况,必要时升级

输入:目标信息、历史任务数据
输出:任务计划、子任务列表、激活的 Agent

约束:
- 严格控制激活 Agent 数量,避免资源浪费
- 优先选择成功率高的策略
- 异常情况立刻上报,不擅自决定
```

**Hypothesizer**

```
你是漏洞假设生成专家。基于侦察结果和代码分析,生成可测试的漏洞假设。

输出格式:
{
  "type": "vuln_type",
  "description": "...",
  "trigger_path": [...],
  "preconditions": [...],
  "expected_impact": "...",
  "confidence": 0.0-1.0,
  "evidence": [...]
}

要求:
- 不要套用通用模板,要基于具体证据推理
- 信心分 < 0.5 的假设标注为低优先
- 跨漏洞类型联想(库历史漏洞、组合利用)
```

**Verifier**

```
你是漏洞验证专家,也是风控守门员。对每个假设进行验证:

1. 先评估 payload 风险等级(L0-L3)
2. L2 以上必须有人工确认
3. 优先使用无副作用的探测
4. 验证成功后,生成完整复现步骤

绝对禁止:
- 在没有授权的目标上测试
- 触发真实破坏性操作
- 绕过风控规则
```

### 10.3 关键技术决策记录

| 决策       | 选择                   | 备选              | 理由               |
| -------- | -------------------- | --------------- | ---------------- |
| Agent 框架 | LangGraph            | AutoGen, CrewAI | 状态机原生、可观测性好      |
| 任务编排     | Temporal             | 自研状态机           | 长任务 + 重试 + 可观测   |
| Web 框架   | Next.js              | Vite + React    | SSR、内置路由         |
| 实时通信     | WebSocket + SSE      | 纯 WebSocket     | 双向 + 大流量分离       |
| 向量数据库    | Qdrant               | Milvus          | 易部署、过滤强          |
| 图数据库     | Neo4j                | Memgraph        | 成熟、Cypher 强      |
| 消息队列     | NATS                 | Kafka, Redis    | 轻量、Pub/Sub       |
| 沙箱       | Docker + Firecracker | gVisor          | 平衡性能和安全          |
| 关系数据库    | PostgreSQL           | MySQL           | JSON 支持、pgvector |

### 10.4 风险与缓解

| 风险              | 影响  | 缓解措施                         |
| --------------- | --- | ---------------------------- |
| Agent 失控,造成生产破坏 | 高   | 多层沙箱 + 风控规则 + 人工审核           |
| Prompt 注入       | 中   | 输入清洗、工具输出过滤                  |
| 漏洞误报            | 中   | Adversarial Verifier + 多阶段验证 |
| 性能瓶颈            | 中   | 异步化、缓存、分片                    |
| 知识库污染           | 中   | 人工审核、自动去重                    |
| 合规问题            | 高   | 授权白名单、审计日志                   |
| LLM 成本失控        | 中   | 模型分级、token 限额                |

### 10.5 并发控制设计

#### 10.5.1 多 Agent 目标并发控制

多个 Agent 或多个任务可能同时对同一目标发起请求，需要全局协调防止：
- 同一 endpoint 被重复测试
- 请求频率过高触发目标 WAF/封禁
- 多个 Verifier 同时发送高危 payload

```python
class TargetRateLimiter:
    """目标级别的全局限速器(基于 Redis)"""

    async def acquire(self, target_host: str, tool: str, task_id: str) -> bool:
        """
        请求令牌。返回 True 表示可以执行,False 表示需要等待。
        基于令牌桶算法,按 (host, tool) 粒度限速。
        """
        key = f"ratelimit:{target_host}:{tool}"
        tokens = await self.redis.get(key)
        if tokens and int(tokens) <= 0:
            return False
        await self.redis.decr(key)
        return True

    async def release(self, target_host: str, tool: str):
        """归还令牌"""
        key = f"ratelimit:{target_host}:{tool}"
        await self.redis.incr(key)

# 默认限速配置
RATE_LIMITS = {
    "nmap":        {"requests_per_minute": 1,  "burst": 1},
    "sqlmap":      {"requests_per_minute": 10, "burst": 3},
    "feroxbuster": {"requests_per_minute": 50, "burst": 10},
    "nuclei":      {"requests_per_minute": 30, "burst": 5},
    "http_request": {"requests_per_minute": 60, "burst": 15},
}
```

#### 10.5.2 Endpoint 去重

```python
class EndpointDeduplicator:
    """防止多个 Agent 重复测试同一 endpoint + 同一漏洞类型"""

    async def claim(self, endpoint: str, vuln_type: str, agent: str) -> bool:
        """
        尝试认领 endpoint + vuln_type 组合。
        返回 True 表示成功认领(首次测试),False 表示已被其他 Agent 认领。
        使用 Redis SETNX 实现原子性。
        """
        key = f"claimed:{endpoint}:{vuln_type}"
        result = await self.redis.set(key, agent, nx=True, ex=3600)
        return result is not None

    async def get_untested(self, endpoints: list, vuln_type: str) -> list:
        """筛选出未被任何 Agent 测试过的 endpoints"""
        pipe = self.redis.pipeline()
        for ep in endpoints:
            pipe.exists(f"claimed:{ep}:{vuln_type}")
        results = await pipe.execute()
        return [ep for ep, exists in zip(endpoints, results) if not exists]
```

#### 10.5.3 分布式锁(高危操作)

```python
class DistributedLock:
    """基于 Redis 的分布式锁,用于高危操作的互斥执行"""

    async def acquire(self, resource: str, holder: str, ttl_s: int = 60) -> bool:
        """Redlock 算法简化版"""
        return await self.redis.set(f"lock:{resource}", holder, nx=True, ex=ttl_s)

    async def release(self, resource: str, holder: str):
        """仅持有者可释放"""
        script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("del", KEYS[1])
        else
            return 0
        end
        """
        await self.redis.eval(script, 1, f"lock:{resource}", holder)
```

### 10.6 验收清单

**功能验收**

- [ ] 能创建一个 Web API 任务并跑通完整流程
- [ ] Agent 输出实时显示在前端
- [ ] 能通过 Steering 中途介入并改变 Agent 行为
- [ ] 攻击面图谱正确显示资产关系
- [ ] 报告能导出为 Markdown 并符合 SRC 规范
- [ ] 知识库能检索并返回相关历史漏洞

**安全验收**

- [ ] 未授权目标无法被攻击
- [ ] L2 以上操作有二次确认
- [ ] 所有操作有审计日志
- [ ] Prompt 注入测试用例不能绕过防护
- [ ] 沙箱逃逸测试用例不能成功

**性能验收**

- [ ] 100 个并发任务下系统稳定
- [ ] 事件到前端延迟 P95 < 200ms
- [ ] 知识库检索 P95 < 100ms

---

## 总结

本设计文档描述了一个完整的、可落地的 AI SRC 漏洞挖掘系统,核心特点是:

1. **黑板 + 动态小组**：替代传统流水线,Agent 间通过共享黑板协调,支持反馈循环与动态组队
2. **Temporal 工作流编排**：长任务管理、Signal 驱动的 Steering、断点恢复,保障任务可靠性
3. **Adversarial Verifier**：同时承担漏洞验证和风控守门员,双阶段复现保障安全
4. **LLM 分级调度**：按 Agent 角色路由模型(Opus/Sonnet/Haiku),Token 预算管理控制成本
5. **完整的 Web 控制端**：驾驶舱级别的可视化与控制,WebSocket 实时推送 + 断线补偿
6. **多层安全防护**：从鉴权到沙箱的全链路保障,Vault 密钥管理,全量审计追踪
7. **生产级运维**：Prometheus + OpenTelemetry 可观测性,灾难恢复,多租户隔离
8. **质量保障**：四层测试体系(单元 / 集成 / E2E / LLM 质量评估),靶场基准测试
9. **渐进式落地**：4 阶段、32 周可达成生产可用

---

**文档版本**: v2.0  
**最后更新**: 2026-06-22  
**反馈渠道**: 项目仓库 Issue