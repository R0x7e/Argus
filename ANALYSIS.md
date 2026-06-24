# Argus SRC 漏洞挖掘系统 — 完整深度分析报告

> 分析日期：2026-06-23
> 范围：全项目（backend / frontend / crawlergo / mitmproxy / poc-sandbox）
> 方法：白盒代码审查 + 架构推理 + SRC 实战视角对比

---

## 目录

- [第一部分：功能架构分析](#第一部分功能架构分析)
  - [1. 项目概览](#1-项目概览)
  - [2. 服务架构](#2-服务架构)
  - [3. LATS + ReAct 核心引擎](#3-lats--react-核心引擎)
  - [4. MCTS 搜索树](#4-mcts-搜索树)
  - [5. ReAct 执行循环](#5-react-执行循环)
  - [6. 动作空间与工具系统](#6-动作空间与工具系统)
  - [7. 侦察阶段](#7-侦察阶段)
  - [8. 数据流与状态管理](#8-数据流与状态管理)
  - [9. LLM 集成架构](#9-llm-集成架构)
  - [10. PoC 沙箱安全模型](#10-poc-沙箱安全模型)
  - [11. 奖励信号设计](#11-奖励信号设计)
  - [12. 关键设计模式](#12-关键设计模式)
  - [13. 数据模型](#13-数据模型)
- [第二部分：SRC 漏洞挖掘能力缺陷分析](#第二部分src-漏洞挖掘能力缺陷分析)
  - [1. 漏洞类型覆盖严重不足](#1-漏洞类型覆盖严重不足)
  - [2. WAF/防护绕过能力极弱](#2-waf防护绕过能力极弱)
  - [3. 认证/会话管理机制薄弱](#3-认证会话管理机制薄弱)
  - [4. 业务逻辑漏洞检测完全空白](#4-业务逻辑漏洞检测完全空白)
  - [5. 侦察阶段存在严重盲区](#5-侦察阶段存在严重盲区)
  - [6. 搜索架构的设计缺陷](#6-搜索架构的设计缺陷)
  - [7. Prompt 工程严重不足](#7-prompt-工程严重不足)
  - [8. Reward 系统的严重缺陷](#8-reward-系统的严重缺陷)
  - [9. 带外检测能力为零](#9-带外oob检测能力为零)
  - [10. 反检测和速率控制缺失](#10-反检测和速率控制缺失)
  - [11. 漏洞验证与误报控制缺陷](#11-漏洞验证与误报控制的缺陷)
  - [12. 工具设计层问题](#12-工具设计层面的问题)
  - [13. 前端可视化缺陷](#13-前端的可视化缺陷)

---

# 第一部分：功能架构分析

## 1. 项目概览

**Argus** 是一个 **AI 驱动的 SRC（安全应急响应中心）漏洞挖掘多 Agent 系统**。核心目标是：用 LLM 推理能力替代传统扫描器的固定规则/签名库，模拟真实安全研究员"提出假设 → 构造 payload → 验证 → 回溯"的思维过程，实现从侦察到验证的全链路自动化漏洞挖掘。

**技术栈**：Python 3.12 + FastAPI + LangGraph（后端）、Next.js 15 + React 19 + Zustand（前端）、PostgreSQL 16 + Redis 7 + NATS（数据基础设施）、Playwright + crawlergo + mitmproxy + RestrictedPython（安全测试 Sidecar）。

## 2. 服务架构

系统由 8 个 Docker 容器组成微服务架构：

```
┌─────────────────────────────────────────────────────┐
│  frontend (Next.js 15, :3000)                       │
│  TanStack Query + Zustand + WebSocket 实时可视化      │
└────────────┬────────────────────────────────────────┘
             │ REST / WebSocket
┌────────────▼────────────────────────────────────────┐
│  backend (FastAPI, :8000)                           │
│  ┌──────────────────────────────────────────────┐   │
│  │  LATS + ReAct 混合搜索引擎 (LangGraph)        │   │
│  │  Recon → InitTree → MCTS → ReAct → Evaluate  │   │
│  └──────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────┐   │
│  │  安全工具集 (14+ 工具，ToolRegistry 管理)       │   │
│  └──────────────────────────────────────────────┘   │
└──┬──────────┬──────────┬──────────┬─────────────────┘
   │          │          │          │
┌──▼──┐  ┌───▼──┐  ┌───▼──┐  ┌───▼──────────────┐
│PG 16│  │Redis7│  │ NATS │  │ Sidecar Services  │
│:5432│  │:6379 │  │:4222 │  │                   │
└─────┘  └──────┘  └──────┘  │ ┌─────────────────┐│
                              │ │ mitmproxy :8080 ││
                              │ │ crawlergo :7777 ││
                              │ │ poc-sandbox:9090││
                              │ └─────────────────┘│
                              └────────────────────┘
```

### 各服务职责

| 服务 | 端口 | 职责 |
|------|------|------|
| **frontend** | 3000 | Next.js SPA，任务管理、搜索树可视化、报告查看 |
| **backend** | 8000 | FastAPI REST + WebSocket，LangGraph 图执行引擎，工具调度 |
| **postgres** | 5432 | 结构化持久化（任务、漏洞发现、事件、用户、LLM 供应商配置） |
| **redis** | 6379 | 缓存 + mitmproxy 流量发布订阅通道 |
| **nats** | 4222 | JetStream 消息总线（事件流、服务间解耦） |
| **mitmproxy** | 8080 | HTTP 代理 Sidecar，实时捕获 Playwright 浏览器流量推送至 Redis |
| **crawlergo** | 7777 | Chromium 深度爬虫 API（Flask wrapper），自动触发 JS 事件、填表 |
| **poc-sandbox** | 9090 | Python PoC 隔离执行器（RestrictedPython + Docker 资源限制） |

## 3. LATS + ReAct 核心引擎

这是整个系统最核心的设计，基于 LangGraph StateGraph 实现：

```
Recon → Init Tree → [MCTS Select → React Execute → Evaluate] (循环) → Reporter
                                            ↑_____________________________|
```

### 图节点定义 (`backend/app/agents/lats/graph.py:574-618`)

```
graph.add_node("recon", lats_recon_node)              # 侦察
graph.add_node("init_tree", lats_init_tree_node)       # 初始化搜索树
graph.add_node("mcts_select", lats_mcts_select_node)   # MCTS 选择
graph.add_node("react_execute", lats_react_execute_node) # ReAct 执行
graph.add_node("evaluate", lats_evaluate_node)         # 评估+剪枝
graph.add_node("pre_reporter", lats_pre_reporter_node)  # 桥接
graph.add_node("reporter", reporter_node)               # 报告生成
```

### 路由逻辑 (4 种终止条件)

1. 达到 `max_cycles`（默认 15）→ 进入 Reporter
2. 搜索树全部穷尽 → 进入 Reporter
3. 连续 3 轮无发现且最高价值 < 0.4 → 进入 Reporter
4. 已有 ≥8 个高危/严重发现 → 进入 Reporter
5. 否则 → 继续 `mcts_select`

### 双模式兼容

系统保留两套执行模式，通过 `mode` 字段选择：
- **LATS 模式**（`mode="lats"`）：MCTS + ReAct，搜索树驱动
- **Pipeline 模式**（`mode="pipeline"`）：`Orchestrator → Hypothesizer → Verifier` 固定管线（旧版保留）

## 4. MCTS 搜索树

### 数据结构 (`backend/app/agents/lats/search_tree.py`)

```
SearchNode
├── id, parent_id, depth
├── state: NodeState
│   ├── target_url, current_endpoint, current_param, vuln_type
│   ├── known_facts: list[str]
│   ├── tried_actions: list[str]
│   ├── reasoning_chain: list[ThoughtStep]
│   └── tool_history: list[ToolCall]
├── MCTS 统计: visit_count, total_reward, value_estimate
├── status: UNEXPLORED | EXPLORING | NEEDS_EXPANSION | EXHAUSTED | CONFIRMED_VULN | PRUNED
└── children: [child_id, ...]
```

### MCTS 四阶段

**Select（选择）** — `select_batch(batch_size=4)`

使用增强版 UCB1 公式选择最有价值的叶节点：
```python
# UCB1 + 先验 + 新鲜度衰减
score = (exploitation + exploration + 0.3 * value_estimate) * freshness
# freshness = 1.0 / (1.0 + 0.01 * (global_step - last_visit_step))
```

**Expand（扩展）** — `init_tree`

基于攻击面（端点 × 参数 × 推断漏洞类型）创建初始分支。每个 `(endpoint, param, vuln_type)` 组合生成一个子节点，限制最多 60 个分支。

**Execute（执行）** — ReAct Agent 在每个选中节点上执行 Thought → Action → Observation 循环。

**Backpropagate（回传）** — `backpropagate(node_id, reward)`

奖励沿父链反向传播，带 0.85 衰减因子：
```python
while current:
    current.visit_count += 1
    current.total_reward += reward * decay
    current.last_visit_step = global_step
    decay *= 0.85
    current = parent
```

### 剪枝策略 (`should_prune`)

- visit_count ≥ 5 且 total_reward ≤ 0
- depth ≥ 15（最大深度）
- 所有子节点均已穷尽/剪枝
- budget_ratio < 0.3 且 value_estimate < 0.3

### 回溯支持 (`backtrack`)

从穷尽的节点向上回溯，找到最近的有未探索子节点的祖先，优先选择 value_estimate 最高的兄弟。

## 5. ReAct 执行循环

核心运行时的循环 (`backend/app/agents/lats/react_executor.py`):

```
for step in range(max_steps):
    Thought: LLM 分析当前状态 → 决定下一步
    Action:  执行一个原子动作（inject_payload / probe_filter / crawl_page ...）
    Observation: 工具返回结果 → 计算奖励 → 更新状态
    if vuln_confirmed or backtrack or give_up:
        break
```

### 关键控制逻辑

- **步数限制动态调整**：早期轮次 10 步 → 中期 7 步 → 后期 3 步
- **连续 4 步无信息增益 → 自动回溯**
- **ReactExecutorPool**：asyncio.Semaphore 控制最大并发数 = 4

### 终止条件

- `finding`：LLM 调用 `report_finding` 或 observation 中检测到漏洞确认指标
- `backtrack`：Agent 主动请求回溯或连续 4 步无信息
- `exhausted`：Agent 调用 `give_up`
- `step_limit`：达到 max_steps 但 reward 低 → 标记穷尽
- `error`：LLM 调用或工具执行异常

## 6. 动作空间与工具系统

### 动作类型（19 种，`actions.py:19-50`）

| 类别 | 动作 | 底层工具 |
|------|------|----------|
| 侦察类 | `crawl_page`, `discover_params`, `fingerprint` | `http_request` |
| 注入测试类 | `inject_payload`, `mutate_payload`, `probe_filter` | `http_request`, `payload_mutate` |
| 认证类 | `test_no_auth`, `test_idor`, `forge_token` | `http_request`, `auth_test` |
| 深挖类 | `escalate`, `chain_vuln`, `extract_data` | `http_request` |
| 控制类 | `backtrack`, `report_finding`, `give_up` | 无（内部） |
| 浏览器/高级 | `render_page`, `interact_page`, `deep_crawl`, `analyze_traffic`, `run_poc` | Playwright, crawlergo, mitmproxy, sandbox |

### 工具系统架构

```
BaseTool (抽象基类)
├── name, description, risk_level(RiskLevel: L0-L3)
├── execute(params, context: ExecutionContext) → dict
└── get_schema() → dict

ToolRegistry (全局单例)
├── register(tool: BaseTool)
├── get(name: str) → BaseTool
├── list_tools(max_risk: RiskLevel) → list[BaseTool]
└── get_langchain_tools(context) → list[StructuredTool]

ExecutionContext (每次调用携带的运行时上下文)
├── task_id, target_host, timeout, max_retries
├── allowed_hosts: list[str]  (安全白名单)
└── auth_headers, cookies, auth_token
```

### 已注册工具（14 个）

| 工具 | 类 | 风险 | 功能 |
|------|------|------|------|
| `http_request` | HTTPRequesterTool | L0 | HTTP 请求，自动注入认证信息，白名单校验，响应体截断 5000 字符 |
| `subdomain_enum` | SubdomainEnumTool | L0 | 子域名枚举 |
| `port_scanner` | PortScannerTool | L0 | TCP 端口扫描 |
| `dir_scan` | DirScannerTool | L0 | 目录/路径爆破（59 条默认字典），并发 10 |
| `payload_mutate` | PayloadMutatorTool | L0 | Payload 变异（8 种技术：URL/Unicode/大小写/注释/HTML/Hex/Base64） |
| `nuclei_scan` | NucleiScannerTool | L1 | Nuclei 模板扫描（JSONL 输出解析） |
| `sqli_detect` | SQLInjectionTool | L1 | SQL 注入：error-based + time-based blind |
| `ssrf_detect` | SSRFDetectorTool | L1 | SSRF 检测（11 个内网/云元数据地址检测） |
| `auth_test` | AuthTesterTool | L1 | 认证绕过：水平越权 + 无认证访问（difflib 相似度） |
| `browser_request` | BrowserRequestTool | L1 | Playwright 页面渲染，提取 JS 动态链接和表单 |
| `browser_interact` | BrowserInteractTool | L2 | 浏览器表单交互 + 网络请求捕获 |
| `proxy_flows` | ProxyFlowsTool | L0 | mitmproxy 流量查询分析 |
| `deep_crawl` | DeepCrawlTool | L0 | crawlergo 深度爬虫 |
| `run_poc` | RunPocTool | L2 | PoC Sandbox 隔离执行 Python 代码 |

### 新增工具（尚未集成到注册表）

- `api_doc_parser.py` — OpenAPI 2.0/3.0 规范解析，提取端点
- `js_endpoint_extractor.py` — 从 JS 源码中正则提取 API 端点路径

## 7. 侦察阶段

### 四层递进式侦察 (`orchestrator.py:_run_reconnaissance`)

**第一层：目录扫描 + 首页探测**
```
dir_scan(base_url) + http_request(target_url)
→ 目录列表 + 首页 HTML 解析
→ 提取链接（_extract_links）、表单（_extract_forms）、参数（_extract_params_from_links）
```

**第二层：递归抓取**
```
对首页发现的链接（最多 15 个）递归 GET
→ 同域过滤（排除 js/css/png/jpg/gif/svg/ico/woff/ttf/pdf/zip）
→ 合并所有发现的参数和表单
```

**第三层：JavaScript 端点提取**
```
下载 JS 文件（最多 10 个，去重）
→ js_endpoint_extractor.extract_endpoints_from_source()
→ 6 种正则模式匹配：fetch(), axios, XMLHttpRequest.open, URL 构造, url 赋值, 路径字面量
```

**第四层：API 文档自动发现**
```
探测 12 种常见 API 文档路径
→ HTTP 200 + JSON/YAML content-type
→ api_doc_parser.parse_openapi_spec()
→ 解析 Swagger 2.0 / OpenAPI 3.0，提取端点、方法、参数
```

### LLM 画像分析

侦察完成后，LLM 根据工具结果生成结构化决策：
- `target_profile`: 技术栈、框架、服务器、WAF、高价值模块
- `attack_surface`: 端点列表、参数、认证机制
- `strategy`: 选择的挖掘策略
- `next_action`: 下一步行动

## 8. 数据流与状态管理

### Blackboard（黑板）模式

所有 Agent 通过共享的 `Blackboard` 数据结构协调：

```
Blackboard
├── 侦察槽: target_profile, attack_surface, tech_fingerprint
├── 假设槽: hypotheses, rejected_hypotheses
├── 验证槽: findings, false_positives
├── 报告槽: reports
└── 控制槽: steering_directives, dry_rounds, version
```

### 事件流（三层分发）

```
Agent Node → emit()
  ├── EventBus.publish()
  │     ├── PostgreSQL (持久化到 events 表)
  │     ├── NATS JetStream (服务间消息，subject: "events.{task_id}")
  │     └── WebSocket → 前端实时推送
```

`emit()` 在每个 Agent 节点的关键步骤被调用，前端实时看到：Agent 思考过程、工具调用和结果、搜索树状态变化（节点选择/扩展/剪枝）、漏洞确认事件。

### WebSocket 实时推送

```
客户端: ws://host:8000/api/v1/ws/tasks/{task_id}/stream?token=xxx
         ↓
服务端: EventBus.subscribe_ws(task_id, callback)
         ↓ 事件产生时
        callback(event) → websocket.send_json({"type": "event", "data": event})
```

## 9. LLM 集成架构

### 多供应商支持

```
LLMClient._ensure_initialized() [延迟初始化]
├── 优先级 1: 数据库活跃 LLMProvider（API Key 加密存储）
├── 优先级 2: ANTHROPIC_API_KEY 环境变量
└── 降级: Mock 模式（开发/测试用，返回模拟 JSON）

支持的供应商: anthropic, openai, deepseek, zhipu, qwen, custom
```

### 模型路由

```
ModelRouter.select_model(agent, budget_ratio)
├── 预算 >= 20%: primary model (默认 claude-sonnet-4-6)
└── 预算 <  20%: fallback model (默认 claude-haiku-4-5)

路由表按 Agent 角色区分: orchestrator, hypothesizer, verifier, react_agent
```

### Token 预算管理

```
TokenBudget(task_id, total_budget=500_000)
├── consume(agent, tokens_in, tokens_out)
├── 阶梯告警: 50%, 80%, 95%
├── is_exceeded() → 超限后拒绝后续 LLM 调用
└── remaining_ratio() → 供 ModelRouter 做降级决策
```

## 10. PoC 沙箱安全模型

### 五层隔离 (`poc-sandbox/sandbox_worker.py`)

| 层级 | 机制 | 作用 |
|------|------|------|
| **AST 层** | `RestrictedPython.compile_restricted()` | 编译时禁止危险语法（exec, import *, __import__ 等） |
| **Import 层** | `_safe_import()` 白名单 | 仅 15 个模块：requests, urllib3, base64, json, hashlib, re, time, socket, struct, urllib, http, collections, itertools, string, binascii, zlib |
| **运行时层** | Guard 函数 | `safer_getattr`, `guarded_unpack_sequence`, `default_guarded_getiter`, `PrintCollector` |
| **容器层** | Docker 配置 | `read_only: true`, `tmpfs: /tmp:size=50M`, `cpus: 1.0`, `memory: 512M` |
| **网络层** | `allowed_hosts` | 通过 `TARGET_HOST` 和 `ALLOWED_HOSTS` 变量传递给沙箱代码 |

### 执行流程

```
POST /execute {code, target_host, timeout, allowed_hosts}
  → RestrictedPython 编译检查（代码长度限制 10k 字符）
  → 注入 restricted_globals（safe_globals + TARGET_HOST + ALLOWED_HOSTS）
  → asyncio.wait_for(run_in_executor, timeout=req.timeout)
  → 收集 stdout（截断 10k）+ stderr（截断 2k）+ PrintCollector 输出
  → 返回 {success, output, error, execution_time_ms, exit_code}
```

## 11. 奖励信号设计

### 即时奖励 (`reward.py:compute_reward`)

```python
漏洞确认:  +0.4 (low) ~ +1.0 (critical)（按严重性分级）
错误信息泄露: +0.2
响应时间异常: +0.2
新信息增益: +0.15
发现过滤规则: +0.1
状态码异常:  +0.1
WAF 拦截:    -0.1
与基线相同:   -0.05
端点返回 404: -0.2
工具执行失败: -0.15
无信息增益:   -0.03
```

### 先验价值估计 (`estimate_branch_value`)

用于搜索树初始化时估计每个分支的潜力：

- **漏洞类型基础分**: RCE=0.9 > SQLi=0.8 > SSRF=0.75 > auth_bypass=0.7 > LFI/PathTraversal/SSTI=0.65 > IDOR=0.6 > XSS=0.5 > open_redirect=0.35 > info_disclosure=0.3
- **参数名匹配加成**: 如 `url`/`redirect`/`callback` → SSRF+0.1；`id`/`uid`/`user_id` → IDOR+0.1
- **来源加成**: form=+0.05, crawl=+0.03
- **技术栈关联**: PHP+MySQL → SQLi+0.05, Jinja2/Flask/Django → SSTI+0.08

### 漏洞类型推断 (`infer_vuln_types`)

基于参数名和端点路径启发式推断可能的漏洞类型：
- `id`/`uid`/`user_id` → IDOR
- `url`/`redirect`/`callback` → SSRF + open_redirect
- `file`/`path`/`page`/`template` → LFI + path_traversal
- `q`/`query`/`search`/`name` → XSS + SQLi
- `cmd`/`exec`/`ping` → RCE
- `admin`/`manage` 端点 → auth_bypass

## 12. 关键设计模式

| 模式 | 应用 | 说明 |
|------|------|------|
| **Blackboard** | Agent 间通信 | 通过共享 `Blackboard` 松耦合协调 |
| **Strategy** | 执行模式切换 | LATS vs Pipeline 两种图策略 |
| **Registry** | 工具管理 | `ToolRegistry` 单例管理工具注册/发现 |
| **Observer** | 事件分发 | `EventBus` + WebSocket 回调实时推送 |
| **Singleton** | 全局服务 | `LLMClient`, `ModelRouter`, `ToolRegistry` |
| **Command** | 动作映射 | `ActionType` 枚举 + `execute_action()` 分发 |
| **Memento** | 状态回溯 | `NodeState.copy()` + 搜索树回溯 |
| **Chain of Responsibility** | 多层防护 | PoC 沙箱五层隔离 |
| **Circuit Breaker** | 异常容错 | LLM 调用 3 次重试 + 指数退避 |

## 13. 数据模型

```
User (用户表)
  ├── username, email, password_hash, role
  └── Task (任务表)
        ├── name, target_type, strategy, status, progress, config
        ├── Event (事件日志)
        │     └── task_id, agent, type, data, tags, confidence, cost
        ├── Finding (漏洞发现)
        │     └── hypothesis_id, type, severity, title, description,
        │         trigger_path, payload, reproduction_steps, evidence
        ├── Report (扫描报告)
        │     └── content, format, version, created_by, finding_id
        └── AgentExecution (Agent 执行记录)

LLMProvider (LLM 供应商配置)
  └── provider_type, api_key_encrypted, base_url, default_model,
      models_available, is_active, priority
```

### 文件结构总览

```
backend/app/
├── agents/                     # 多 Agent 系统核心
│   ├── lats/                  # ★ LATS + ReAct 混合引擎
│   │   ├── graph.py           #   LangGraph 状态图构建（6 节点 + 条件路由）
│   │   ├── search_tree.py     #   MCTS 搜索树（节点/树/UCB1/回传/剪枝/回溯）
│   │   ├── react_executor.py  #   ReAct 循环执行器 + 并发池(Semaphore=4)
│   │   ├── reward.py          #   奖励函数 + 先验估计 + 漏洞类型推断
│   │   ├── actions.py         #   19 种动作定义 + 执行映射 + 漏洞检测指标
│   │   └── prompts.py         #   ReAct/Expand/Value 提示词模板
│   ├── nodes/                 # LangGraph 节点（Pipeline 模式用）
│   │   ├── orchestrator.py    #   总指挥：四层侦察 + LLM 画像 + 进度决策
│   │   ├── hypothesizer.py    #   假设生成器（type@endpoint 去重）
│   │   ├── verifier.py        #   验证器：工具验证 + LLM 综合判断（双重确认）
│   │   └── reporter.py        #   报告生成器（Jinja2 模板 + LLM 修复建议）
│   ├── llm.py                 # LLM 客户端（多供应商 + mock 降级 + 3 次重试）
│   ├── model_router.py        # 模型路由（按预算选择 primary/fallback）
│   ├── token_budget.py        # Token 预算管理（500k 默认，阶梯告警）
│   ├── state.py               # Blackboard + Hypothesis + VulnFinding 数据结构
│   ├── emit.py                # 节点内实时事件发射器（独立 DB session）
│   └── routing.py             # Pipeline 模式的条件路由
├── api/v1/                    # REST API 端点
│   ├── tasks.py               #   任务 CRUD + start/pause/resume/terminate
│   ├── ws.py                  #   WebSocket 事件流推送（JWT 认证）
│   ├── findings.py            #   漏洞发现查询
│   ├── reports.py             #   报告查询
│   ├── auth.py                #   认证（注册/登录/JWT）
│   ├── settings.py            #   LLM 供应商配置管理
│   └── system.py              #   健康检查/统计
├── core/                      # 基础设施
│   ├── event_bus.py           #   事件总线（DB + NATS + WebSocket 三层分发）
│   ├── playwright_manager.py  #   Chromium 浏览器单例管理
│   ├── proxy_client.py        #   Redis Pub/Sub 消费 mitmproxy 流量（deque 5000）
│   ├── crawlergo_client.py    #   crawlergo HTTP API 客户端
│   ├── poc_sandbox_client.py  #   PoC 沙箱 HTTP API 客户端
│   ├── security.py            #   JWT + bcrypt(SHA-256 预处理)
│   ├── encryption.py          #   API Key 加密存储（cryptography）
│   └── database.py            #   SQLAlchemy async engine + session
├── tools/                     # 安全工具集 (14 个已注册)
│   ├── base.py                #   BaseTool + ExecutionContext + ToolRegistry + RiskLevel
│   ├── http_requester.py      #   HTTP 请求（L0，5k 截断，自动注入认证，白名单校验）
│   ├── sql_injection.py       #   SQL 注入（L1，error-based + time-based）
│   ├── ssrf_detector.py       #   SSRF 检测（L1，11 个内网地址）
│   ├── auth_tester.py         #   越权检测（L1，difflib 相似度 0.8 阈值）
│   ├── payload_mutator.py     #   Payload 变异（L0，8 种技术）
│   ├── dir_scanner.py         #   目录扫描（L0，59 条默认字典，并发 10）
│   ├── nuclei_scanner.py      #   Nuclei 扫描（L1，JSONL 解析）
│   ├── port_scanner.py        #   端口扫描（L0）
│   ├── subdomain_enum.py      #   子域名枚举（L0）
│   ├── browser_request.py     #   Playwright 渲染（L1）
│   ├── browser_interact.py    #   浏览器交互（L2，fill/click/select/wait + 流量捕获）
│   ├── proxy_flows.py         #   代理流量查询（L0）
│   ├── deep_crawl.py          #   深度爬虫（L0，crawlergo）
│   ├── run_poc.py             #   PoC 沙箱执行（L2）
│   ├── api_doc_parser.py      #   OpenAPI 解析（新，尚未注册）
│   ├── js_endpoint_extractor.py # JS 端点提取（新，在侦察中使用）
│   └── sandbox.py             #   子进程沙箱执行器（nuclei/nmap 等依赖）
├── models/                    # SQLAlchemy ORM 模型
├── schemas/                   # Pydantic 请求/响应模型
└── services/                  # 业务逻辑层
    ├── agent_runner.py        #   Agent 生命周期管理（后台 asyncio.Task + 暂停/终止）
    ├── task_service.py        #   任务 CRUD + 状态机转换
    ├── finding_service.py     #   漏洞发现 CRUD
    ├── report_service.py      #   报告 CRUD
    └── event_service.py       #   事件分页查询
```

---

# 第二部分：SRC 漏洞挖掘能力缺陷分析

## 1. 漏洞类型覆盖严重不足

### 1.1 完全缺失的高价值漏洞类型

当前系统仅支持 12 种漏洞类型，**SRC 实战中以下高频漏洞类型完全缺失**：

| 缺失漏洞类型 | SRC 实战价值 | 现状 |
|---|---|---|
| **CSRF** | 高 | 无 CSRF token 检测、无 Origin/Referer 验证分析 |
| **CORS 配置错误** | 高 | 无法检测 `Access-Control-Allow-Origin` 反射 |
| **HTTP Request Smuggling** | 高 | 无 TE/CL 走私检测 |
| **Web Cache Poisoning** | 高 | 无法分析缓存键与未键化参数 |
| **反序列化漏洞** | 高 | 无 Java/PHP/Python 反序列化 payload |
| **XXE 注入** | 高 | 无 XML 外部实体注入检测 |
| **JWT 高级攻击** | 高 | 仅有 `alg:none`，缺少 kid 注入/JKU 头部注入/算法混淆/`jwk` 注入 |
| **GraphQL 注入** | 中 | 无内省查询、深度递归 DoS、字段级授权绕过 |
| **WebSocket 漏洞** | 中 | 无 WS 跨站劫持、消息注入检测 |
| **条件竞争** | 高 | 无并发请求发送能力 |
| **OAuth 2.0 流程缺陷** | 高 | 无 redirect_uri 验证、state 缺失、PKCE 绕过 |
| **SAML/OIDC 漏洞** | 中 | 无 XML 签名包装攻击 |
| **CRLF 注入** | 中 | 无 HTTP 头注入检测 |
| **Host Header 攻击** | 中 | 无密码重置投毒、缓存投毒检测 |
| **盲 XSS / 存储型 XSS** | 高 | 仅检测反射型，无外出回调验证 |
| **子域名接管** | 高 | 有枚举无接管检查 |
| **Nginx/Apache 配置缺陷** | 中 | 无路径穿越、别名遍历等中间件特定检测 |

### 1.2 已有类型的检测深度不足

**SQL 注入** — 仅有 error-based + time-based 两类：
- 缺少：布尔盲注、OOB 注入、二阶注入、堆叠查询、`LOAD_FILE`/`INTO OUTFILE`
- 时间注入仅 3 组 payload（MySQL/PostgreSQL/MSSQL 各一），无 Oracle/SQLite 的变体
- 无二次解码注入、无宽字节注入

**SSRF 检测** — 仅 GET 参数注入：
- 不测试 POST body、JSON body、XML、multipart 中的 URL 参数
- 无 DNS rebinding、302 重定向链、URL 解析器差异利用
- 无云元数据 IMDSv2 token 获取逻辑

**XSS 检测** — 仅反射型，7 个 payload：
- 无 DOM-based XSS 检测（需要浏览器上下文）
- 无 CSP bypass 尝试
- 无 WAF 专用 XSS 编码链

## 2. WAF/防护绕过能力极弱

### 2.1 Payload 变异器过于基础

`payload_mutator.py` 仅 8 种单层变换，且：

- **不支持组合/嵌套变异**：无法实现多层编码链
- **不支持 WAF 特定绕过**：Cloudflare/AWS WAF/ModSecurity/阿里云 WAF 各有不同的绕过技巧，全不支持
- **缺少关键技术**：
  - SQL 特定：科学计数法、浮点数注入、空白字符（`%09`/`%0a`/`%0d`）、反引号绕过、宽字节注入
  - XSS 特定：`<details/open/ontoggle>`、Mutation XSS、`window.name` DOM 利用
  - 路径穿越特定：`....//`、`..;/`、Unicode 规范化绕过
  - 编码链：UTF-7、UTF-16、IBM037、Quoted-Printable
- **无 WAF 指纹识别**：不知道 WAF 类型就无法精准绕过
- **probe_filter 极其简陋**：仅探测 12 个 ASCII 字符是否被拦截，不探测语义级规则

## 3. 认证/会话管理机制薄弱

### 3.1 ExecutionContext 过于简化

仅支持静态 header+cookie+token，意味着：
- **无自动会话刷新**：token 过期后不会自动重新登录
- **无 OAuth/SSO 流程**：无法自动获取授权码、token 交换
- **无 CSRF Token 提取**：页面中的 `csrfmiddlewaretoken`/`_csrf` 不会被自动提取和携带
- **Cookie 域/路径匹配缺失**：所有 cookie 绑定到 `target_host`，不考虑子域/路径

### 3.2 Auth Tester 不可用

`auth_tester.py` 依赖外部传入 `user_a_token`，但实际 ReAct 循环中 Agent 从不自动创建测试用户或生成 token——工具形同虚设。

### 3.3 SPA 认证不友好

没有对 SPA 的自动 token 提取（从 `localStorage`/`sessionStorage`/`IndexedDB` 中获取）。

## 4. 业务逻辑漏洞检测完全空白

SRC 中 30%+ 的高危漏洞是业务逻辑缺陷，当前系统完全无法检测：

1. **金额/积分篡改** — 无并发请求测试竞态条件
2. **越权流程** — 无跳过支付步骤、修改订单归属、低权限调用高权限 API
3. **参数污染/批量赋值** — 不自动尝试发送额外参数（`is_admin=true`, `role=admin`）
4. **速率限制漏洞** — 不测试 API 是否可被暴力破解
5. **UUID/ID 遍历** — IDOR 测试仅测试 6 个硬编码 ID（`1,2,0,999,admin`）

## 5. 侦察阶段存在严重盲区

### 5.1 目录扫描字典极小

`dir_scanner.py` 的 `DEFAULT_WORDLIST` 仅 **59 条路径**，而实战使用的字典通常在 2000-20000+ 条。
缺失：备份文件后缀（`.bak`, `.old`, `.swp`）、版本控制暴露（`.svn/`, `.hg/`, `.bzr/`）、CI/CD 暴露（`.gitlab-ci.yml`, `Jenkinsfile`）。

### 5.2 JS 端点提取过于粗糙

`js_endpoint_extractor.py` 仅 6 个正则模式，无法匹配：
- webpack chunk 文件
- sourcemap 解析
- 模板字符串（`` axios.get(`/api/${type}/${id}`) ``）

### 5.3 参数发现能力弱

`_execute_discover_params` 仅测试 20 个通用参数名，无：
- HTML 表单动态提取（仅在侦察阶段做一次）
- 框架特定参数名字典
- 基于 API 响应 JSON schema 的参数推断

## 6. 搜索架构的设计缺陷

### 6.1 分支因子爆炸 + 粗暴剪枝

`init_tree` 创建 (endpoint × param × vuln_type) 笛卡尔积分支后强制限制到 60 个。剪枝依靠静态 `value_estimate`（纯启发式规则），**一个真正的高危漏洞可能因参数名不匹配而被剪掉**。

### 6.2 搜索树实质上是静态的

搜索树仅在 `init_tree` 时创建分支。之后 MCTS 循环中无动态扩展——即使发现新端点/参数，也不会生成新的子节点。只有 `NEEDS_EXPANSION` 标记但无对应扩展逻辑。

### 6.3 UCB1 选择偏向先验而非实际结果

`ucb = exploitation + exploration + 0.3 * value_estimate`

`value_estimate` 来自参数名规则匹配，在低访问量时主导选择。RCE 先验 0.9、XSS 0.5、info_disclosure 0.3 → **系统性地偏向高先验类型**，即使目标可能只有 info_disclosure 但暴露的是高价值信息。

### 6.4 无跨分支信息共享

每个 ReAct Agent 在各自节点上独立运行。发现 WAF 规则、有效参数、技术栈信息**不在分支间共享**。如果分支 A 发现 `token` 参数被过滤，分支 B 仍会盲目测试 `token`。

### 6.5 ReAct 执行循环效率低

- 每步仅一个动作 → LLM 调用次数过高（估算：4 并发 × 8 步 × 15 周期 = 480 次调用）
- 无步骤并行化：`inject_payload` 一次只测一个 payload
- 回溯效率低：穷尽后需 MCTS 从根重选，不支持 sibling 直接尝试

## 7. Prompt 工程严重不足

### 7.1 提示词结构简陋

`REACT_SYSTEM_PROMPT` 仅 56 行，缺少：
- Few-shot 范例（成功漏洞发现的完整示例链）
- 漏洞判定的具体指标（不只有原则性描述）
- 错误恢复策略（遇到 429/503/超时时怎么做）
- 目标类型特定指导（API vs Web vs 管理后台的策略差异）
- 负样本（常见误判情形及如何避免）

### 7.2 无上下文窗口管理

ReAct 循环仅保留最近 5 步历史，无：
- 智能摘要压缩（关键信息提取 vs 冗余信息丢弃）
- Token 感知的裁剪策略
- 历史关键信息的持久化

### 7.3 无 prompt 优化反馈闭环

所有 prompt 是静态字符串，无基于执行结果的优化、无 A/B 测试、无不同供应商的 adapt 层。

## 8. Reward 系统的严重缺陷

### 8.1 鼓励浅层探测

MCTS 节点在初始访问量低时，一旦积累几次 `-0.03` 惩罚，exploitation 迅速降低，UCB1 不会再次选择——即使深层可能通向高危漏洞。

### 8.2 无延迟奖励

`compute_reward` 是即时奖励——需要 5 步确认的复杂漏洞在前 4 步会被判定为"无信息增益"并受罚。

### 8.3 先验偏见

RCE=0.9, info_disclosure=0.3 → 系统根本不会去探测 `.env` 文件泄露（即使其上包含 AWS 密钥）。

## 9. 带外（OOB）检测能力为零

1. **无 DNS 回调平台** — 无法检测盲 SSRF、盲 XXE、盲命令注入
2. **无 HTTP 回调服务器** — 无法验证无回显漏洞
3. 没有类似 Burp Collaborator / interactsh / ceye.io 的内置或外接方案

## 10. 反检测和速率控制缺失

1. **无请求间延迟/抖动** — 持续高频请求容易被 WAF/IDS 检测
2. **无 User-Agent 轮换** — 所有请求使用相同的 UA
3. **无代理池** — 所有流量从同一 IP 发出
4. **无 session 轮换** — 长时间扫描使用同一 session
5. **无目标感知的并发控制** — 4 个 ReAct Agent × 多工具并发可能压垮目标

## 11. 漏洞验证与误报控制的缺陷

### 11.1 依赖关键词匹配

`_detect_vuln_indicators` 基于纯关键词匹配判定漏洞：
- `uid=` 出现在响应 → 判定为 RCE
- `sql syntax` 出现在响应 → 判定为 SQLi

目标业务页面自身可能包含这些字符串 → **极高误报风险**。

### 11.2 无二次验证

LATS 模式下，ReAct Agent 提交 `report_finding` 后**直接写入 `bb.findings`**，没有独立的 Verifier 做二次验证。LLM 可以单方面产生"漏洞"——Pipeline 模式的 verifier 节点在 LATS 中未被复用。

### 11.3 无基线对比

大多数漏洞判定没有正常请求 vs 注入请求的系统性差异分析。

## 12. 工具设计层面的问题

### 12.1 工具无法组合

每个工具调用独立、无数据流管道：
- `browser_interact` 产生的流量不能喂给 SQLi 扫描器
- `deep_crawl` 发现的 URL 不能喂给 `dir_scanner`
- `proxy_flows` 捕获的 API 不能直接传递给 `sqli_detect`

### 12.2 无结果缓存

同一 URL 可能被不同 Agent 在不同步骤重复请求 → **浪费 Token + 增加被检测风险**。

### 12.3 超时处理粗糙

几乎所有工具超时都返回 `_make_error_result`，无渐进式降级（先缩短超时重试、再跳过）。

### 12.4 工具注册不完整

`api_doc_parser.py` 和 `js_endpoint_extractor.py` 作为独立工具文件存在但未注册到 `ToolRegistry`，LLM Agent 无法通过 function calling 调用。

## 13. 前端的可视化缺陷

从组件命名和类型定义推断：

1. **搜索树可视化单薄** — 仅显示树结构，不显示节点奖励值、UCB1 分数、选择路径历史
2. **无数据流图** — 看不到工具调用间的数据传递
3. **无统计面板** — 缺实时的漏洞类型分布、工具使用频率、Token 消耗趋势
4. **无法手动干预** — 用户不能在搜索进行中暂停/手动标记误报/引导搜索方向/添加自定义 payload/手动创建分支
5. **无对比视图** — 多个任务的结果无法横向对比
6. **报告仅 Markdown** — 无 HTML 渲染、无交互式报告（可点击展开的漏洞详情）

---

# 总结

Argus 在 **AI 驱动的自动化漏洞挖掘** 方向上做出了有意义的尝试，尤其是 LATS + MCTS 的搜索框架设计值得肯定。但从 **SRC 实战漏洞挖掘** 的标准来看，当前系统存在以下核心瓶颈：

### 最严重的 5 个问题

1. **搜索树静态化** — 无动态扩展能力，本质上是带 UCB1 排序的固定任务队列
2. **漏洞验证不可靠** — 关键词匹配 + LLM 单方面确认，误报率难以控制
3. **WAF 绕过极弱** — 8 种单层编码技术远不足以应对现代 WAF
4. **漏洞类型覆盖窄** — 缺失 CSRF/XXE/Deserialization/Request Smuggling/条件竞争等 SRC 高频漏洞
5. **业务逻辑盲区** — 完全无法检测金额篡改、越权流程、参数污染等逻辑缺陷

### 改进方向建议（概要）

- **搜索架构**：动态分支扩展、跨节点信息共享（共享知识库）、层次化 MCTS
- **验证层**：独立的双检机制（工具确认 + 正交验证）、基线对比引擎、带外回调平台
- **WAF 绕过**：组合变异引擎、WAF 指纹识别、自动化 fuzzing 发现绕过规则
- **漏洞覆盖**：按优先级逐步添加 CSRF/CORS/XXE/Deserialization/条件竞争模块
- **业务逻辑**：参数自动发现 + 批量赋值/参数污染测试 + 并发请求框架
