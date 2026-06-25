# Argus 项目缺陷分析与改进建议

## 1. 文档概述

### 1.1 分析范围

本文档对 Argus 自动化安全测试平台进行全面缺陷分析，覆盖以下四个层面：

- 后端服务（Python / FastAPI / LangGraph / SQLAlchemy）
- 前端应用（Next.js 15 / React 19 / TanStack Query / Zustand）
- 基础设施与工程化（Docker / docker-compose / 外部服务集成 / 测试 / 可观测性）
- 运行实例验证（浏览器实际访问验证系统行为与数据一致性）

### 1.2 分析方法

采用白盒代码审查与运行实例浏览器验证相结合的方法：

- 白盒审查：对全部源代码文件进行逐文件、逐模块的只读审查，覆盖代码逻辑、配置、依赖、测试等维度
- 运行实例验证：通过浏览器实际访问部署实例（http://192.168.110.143:3000），验证登录、控制台、任务详情、漏洞列表、系统设置等核心页面的真实运行行为，并通过截图取证
- 交叉验证：将代码审查发现的问题与运行实例观察到的现象进行关联，定位真实根因

### 1.3 分析元数据

| 项目 | 内容 |
|------|------|
| 分析日期 | 2026-06-24 |
| 系统版本 | Argus v0.1.0 |
| 后端代码路径 | backend/ |
| 前端代码路径 | frontend/ |
| 基础设施路径 | docker-compose.yml, Makefile, 各服务 Dockerfile |
| 运行实例地址 | http://192.168.110.143:3000 |

---

## 2. 执行摘要

### 2.1 整体评估结论

Argus 平台在功能架构设计上展现了较强的技术深度：LATS（Language Agent Tree Search）与 ReAct 混合搜索引擎、多 Agent 协作、黑板模型共享状态、事件驱动实时推送等设计体现了对自动化安全测试领域的深入思考。前端采用 Next.js 15 + React 19 + TanStack Query v5 的现代技术栈，数据获取层封装规范。

然而，系统在安全性、健壮性和工程化成熟度三个维度存在系统性缺陷。作为安全测试平台，自身的安全 posture 极其薄弱：容器以 root 运行、网络无隔离、端口全暴露、密钥硬编码、沙箱隔离可被绕过、API 端点认证缺失。全局可变状态泛滥导致并发安全问题、测试困难、状态污染。错误处理策略不统一，异常被静默吞没的情况普遍存在。

运行实例验证暴露了最严重的问题：漏洞数据不一致（统计显示 2 个漏洞但列表显示 0 个）、任务执行崩溃（'str' object has no attribute 'get'）、任务状态与 Agent 状态不一致。这些问题直接关联到后端 FindingService 无去重逻辑、emit 事件未真正落库、agent_runner 异常终止后未同步 Agent 状态等代码缺陷。现有测试与实际代码不匹配，大量断言错误，测试给人的虚假信心比没有测试更危险。

### 2.2 评分矩阵

| 层面 | 维度 | 评分 (1-10) | 关键问题数 | 总体评价 |
|------|------|-------------|------------|----------|
| 后端 | 整体架构与入口 | 3 | 6 | 密钥硬编码、无速率限制、CORS 全开放 |
| 后端 | Agent 核心引擎 | 4 | 6 | LLM 单例并发污染、无全局超时 |
| 后端 | 工具集 | 3 | 9 | 沙箱无隔离、SSL 全禁用、白名单缺失 |
| 后端 | API 层 | 2 | 5 | 多端点无认证、无 IDOR 防护、WS 认证可选 |
| 后端 | 数据模型与数据库 | 3 | 5 | 迁移与模型不一致、外键缺失 |
| 后端 | Schema 层 | 4 | 3 | 枚举校验缺失、target_config 无结构 |
| 后端 | Services 层 | 3 | 5 | 无去重逻辑、无锁保护、同步渲染 |
| 后端 | Core 基础设施 | 3 | 7 | 加密密钥派生不当、全局状态泛滥 |
| 后端 | 测试 | 2 | 5 | 覆盖率极低、测试与代码不匹配 |
| 后端 | 配置与依赖 | 3 | 5 | 依赖未固定、Dockerfile root 运行 |
| 前端 | 整体架构与配置 | 4 | 5 | rewrites 构建时固化、无安全头 |
| 前端 | 应用入口与路由 | 4 | 5 | 全页面 use client、无错误边界 |
| 前端 | 状态管理与数据获取 | 3 | 6 | 事件列表无限增长、API 直接访问 store |
| 前端 | 认证与安全 | 2 | 6 | token 存 localStorage、WS URL 传 token |
| 前端 | 组件设计 | 4 | 8 | wsRef 未赋值、any 类型滥用 |
| 前端 | 实时通信 | 3 | 6 | 重连无反馈、消息解析静默忽略、无虚拟化 |
| 前端 | 类型定义 | 4 | 4 | Record<string,any> 滥用 |
| 前端 | 性能问题 | 4 | 4 | 无代码分割、useMemo 全量遍历 |
| 前端 | 用户体验 | 4 | 6 | 无全局错误通知、模态框交互缺陷 |
| 前端 | 构建与部署 | 4 | 5 | npm install 非 ci、缺 .dockerignore |
| 基础设施 | 容器化与编排 | 4 | 8 | root 运行、端口全暴露、无网络隔离 |
| 基础设施 | 外部服务集成 | 3 | 7 | 沙箱网络隔离失效、静默吞没异常 |
| 基础设施 | 数据库与持久化 | 3 | 5 | init_db.sql 失效、迁移管理混乱 |
| 基础设施 | 配置管理 | 2 | 4 | 硬编码密钥、加密方案设计缺陷 |
| 基础设施 | 工程化与构建 | 3 | 4 | 无 CI/CD、自动化程度低 |
| 基础设施 | 测试策略 | 2 | 4 | 覆盖率极低、核心路径未测试 |
| 基础设施 | 可观测性 | 2 | 5 | 无指标/追踪/告警、日志不统一 |
| 基础设施 | 文档与设计 | 5 | 3 | README 较完整但与实现有偏差 |
| 基础设施 | 安全合规 | 1 | 5 | 安全平台自身安全性极差 |
| 基础设施 | 可扩展性与高可用 | 2 | 4 | 不支持水平扩展、多单点故障 |

**综合评分：后端 3.0/10，前端 3.5/10，基础设施 2.7/10**

---

## 3. 运行实例验证发现

本节呈现通过浏览器实际访问运行实例观察到的真实问题。这些问题最具说服力，因为它们是用户实际会遇到的故障。每个问题均关联到后端代码根因。

### 3.1 P0 - 漏洞数据不一致

- **现象描述**: 任务详情页统计 Tab 显示"漏洞发现分布 (2)"，即 2 个中危漏洞；事件流中存在 finding_confirmed 事件（auth_bypass, info_disclosure）；但概览 Tab 显示"发现漏洞(0)"，Findings 页面显示"共 0 条"。三处数据严重不一致。

- **截图证据**:
  - 统计 Tab 显示 2 个漏洞: ![/tmp/06_task_detail_stats.png](/tmp/06_task_detail_stats.png)
  - 概览 Tab 显示 0 个漏洞: ![/tmp/04_task_detail_overview.png](/tmp/04_task_detail_overview.png)
  - Findings 页面显示 0 条: ![/tmp/10_findings_page.png](/tmp/10_findings_page.png)

- **根因分析**: 
  - 后端 `FindingService.create_finding()` 无去重逻辑（finding_service.py 第 41-75 行），多轮迭代中 Agent 多次报告同一漏洞会导致重复记录，但更关键的是 finding_confirmed 事件可能未真正落库到 findings 表。
  - 事件流中的 finding_confirmed 是通过 `emit()` 函数发射的事件（emit.py），emit 在发射事件时可能仅写入了 events 表，而未调用 `FindingService.create_finding()` 写入 findings 表。
  - emit() 静默吞没所有异常（emit.py 第 36-37 行），如果 finding 落库过程中抛出异常，事件已记录但 finding 未落库，导致数据不一致。
  - 概览 Tab 的"发现漏洞(0)"来源于 `GET /api/v1/findings?task_id={id}` 查询 findings 表，统计 Tab 的"漏洞发现分布(2)"来源于对 events 表中 finding 类型事件的聚合统计，两个数据源不一致。

- **影响评估**: 用户无法信任系统报告的漏洞数据。安全测试平台的核心价值在于准确报告漏洞，数据丢失意味着真实漏洞被遗漏，可能导致安全风险被低估。

### 3.2 P0 - 任务执行崩溃

- **现象描述**: 事件流最后一条错误为 `'str' object has no attribute 'get'`，任务状态变为 failed。任务执行过程中某个组件对一个本应是 dict 的 str 值调用了 `.get()` 方法。

- **截图证据**: ![/tmp/04_task_detail_overview.png](/tmp/04_task_detail_overview.png)

- **根因分析**:
  - 后端 `routing.py` 或 agent 状态处理中对某个本应是 dict 的 str 值调用了 `.get()` 方法。LATS 图执行过程中，Agent 输出的 LLM 响应可能未被正确解析为 dict，或 state 中某个字段类型不一致。
  - 具体位置在 `backend/app/agents/routing.py` 的路由判断逻辑或 `backend/app/agents/state.py` 的状态访问逻辑中。LLM 返回的 JSON 字符串可能未被 `json.loads()` 解析就直接作为 str 传入后续处理。
  - agent_runner.py 第 205 行 `result = await graph.ainvoke(initial_state)` 无 try-except 包裹具体节点逻辑，异常向上传播导致整个任务失败。

- **影响评估**: 任务无法完成扫描，所有扫描结果可能丢失。这是阻塞性故障，用户无法获得完整的漏洞扫描结果。

### 3.3 P0 - 任务状态与 Agent 状态不一致

- **现象描述**: 任务整体状态为 failed，但 lats_expand Agent 显示"运行中"。WebSocket 连接显示"已连接"，但任务已失败。

- **截图证据**: ![/tmp/04_task_detail_overview.png](/tmp/04_task_detail_overview.png)

- **根因分析**:
  - 后端 `agent_runner.py` 中任务异常终止后未同步更新各 Agent 的状态。`_run_graph` 方法在捕获异常后将任务状态设为 failed，但没有遍历 `_active_states` 中的各 Agent 状态并统一更新为 failed/terminated。
  - Agent 状态存储在 `agent_executions` 表中，任务失败时仅更新了 `tasks.status`，未级联更新 `agent_executions.status`。
  - 前端 `OverviewPanel` 的 Agent 状态展示直接读取后端返回的 agent_executions 数据，后端数据不一致导致前端显示不一致。

- **影响评估**: 用户对系统状态产生困惑，无法判断任务是否真正在运行。可能误导用户等待一个实际已停止的任务，浪费时间。

### 3.4 P1 - 系统异常提示无法查看详情

- **现象描述**: 所有页面顶部显示"系统异常"红色提示，但点击通知按钮无反应，无法查看具体异常信息。

- **截图证据**: ![/tmp/03_dashboard_notification.png](/tmp/03_dashboard_notification.png)

- **根因分析**:
  - 前端 `header.tsx` 第 26-31 行每 60 秒轮询 `GET /api/v1/system/health` 健康检查端点。后端 system.py 的健康检查仅检测数据库和 Redis，未检测 NATS、mitmproxy、crawlergo、poc-sandbox。如果 NATS 或其他服务不可用，健康检查返回非 healthy 状态，前端显示"系统异常"。
  - 前端通知按钮缺少点击交互逻辑，无法展开异常详情。`header.tsx` 中的通知组件仅显示状态图标，未实现点击展开详情面板的功能。
  - 前端无全局错误通知系统（全项目缺失 toast/notification），导致系统异常信息无法有效传达给用户。

- **影响评估**: 用户始终看到"系统异常"提示但无法了解具体原因，严重影响用户体验和对系统的信任度。

### 3.5 P1 - 报告页面文案不当

- **现象描述**: 任务已 failed，但报告页仍提示"该任务尚未生成报告，请等待扫描完成后查看"。

- **截图证据**: ![/tmp/08_report_page.png](/tmp/08_report_page.png)

- **根因分析**:
  - 前端报告页面未根据任务状态区分提示文案。报告组件仅检查 `reports` 数组是否为空，未检查 `task.status` 是否为 failed/terminated。
  - 应根据任务状态显示不同提示：failed 时提示"任务执行失败，无法生成报告"；completed 但无报告时提示"正在生成报告"；running 时提示"请等待扫描完成后查看"。

- **影响评估**: 用户体验差，文案与实际状态不符造成困惑。

### 3.6 P1 - 缺少任务控制按钮

- **现象描述**: 任务列表和详情页无暂停/继续/停止按钮。运行中的任务无法被用户主动控制。

- **截图证据**: ![/tmp/09_tasks_list.png](/tmp/09_tasks_list.png)

- **根因分析**:
  - 前端任务操作按钮逻辑不完整。`tasks/page.tsx` 的 `getTaskActions` 函数和 `tasks/[id]/page.tsx` 的内联逻辑仅实现了启动和删除按钮，未实现暂停/继续/停止按钮。
  - 后端 `agent_runner.py` 虽然定义了 `_pause_events` 字典（第 50 行）支持暂停机制，但前端未对接这些 API 端点。后端可能缺少对应的 API 端点或前端未调用。
  - 即使后端有暂停机制，`wsRef` 未赋值导致 InterventionPanel 的 wsSend 永远无效（前端 5.3 节），用户干预功能完全失效。

- **影响评估**: 用户无法控制长时间运行的扫描任务，无法在发现问题时及时停止，浪费资源。

### 3.7 P1 - 缺少报告导出功能

- **现象描述**: 未见明显的报告导出按钮，用户无法将扫描报告导出为 PDF/HTML/Markdown 等格式。

- **截图证据**: ![/tmp/04_task_detail_overview.png](/tmp/04_task_detail_overview.png)

- **根因分析**:
  - 后端 `report_service.py` 已实现 Markdown 报告生成（使用 Jinja2 模板），但前端报告页面未提供导出按钮。
  - 后端 API 可能缺少报告导出端点（如 `GET /api/v1/tasks/{id}/report/export?format=pdf`），或前端未对接。
  - 后端 report_service 使用同步 Jinja2 渲染（第 220-223 行），在 async 上下文中阻塞事件循环，可能影响导出功能的可用性。

- **影响评估**: 用户无法将漏洞扫描结果分享给其他团队成员或用于合规报告，降低了平台的实用价值。

### 3.8 P2 - 登录密码强度要求过低

- **现象描述**: 登录页面密码字段仅要求"至少 6 位"，安全强度较低。

- **截图证据**: ![/tmp/01_login_page.png](/tmp/01_login_page.png)

- **根因分析**:
  - 后端 `auth.py` 注册端点对密码长度的校验过于宽松，未要求包含大小写字母、数字、特殊字符。
  - 前端登录页面密码输入框无可见性切换按钮，用户无法确认输入内容。

- **影响评估**: 弱密码容易被暴力破解，结合后端无速率限制（后端 1.5 节），安全风险加倍。

---

## 4. 后端缺陷分析

### 4.1 整体架构与入口 (main.py, config.py, dependencies.py)

#### P0 - 4.1.1 JWT 密钥硬编码且无启动校验

- **位置**: `backend/app/config.py` 第 34 行
- **现象**: JWT 密钥有不安全的默认值，部署时若未设置环境变量，应用将使用默认值启动。
- **根因分析**: 配置类直接定义默认值，无启动时校验逻辑。`.env.example` 文件中同样使用了这个默认值，极易在生产环境中遗忘。
- **代码证据**:
  ```python
  # config.py 第 34 行
  JWT_SECRET: str = "your-super-secret-key-change-in-production"
  ```
- **影响**: 攻击者可伪造任意用户的 JWT，完全绕过认证。安全工具平台的认证被绕过意味着所有漏洞数据泄露。
- **改进建议**: 启动时校验 JWT_SECRET 不等于默认值，否则拒绝启动（生产模式）。使用 `secrets.token_hex(32)` 生成随机密钥。参考以下实现：
  ```python
  @validator("JWT_SECRET")
  def validate_jwt_secret(cls, v):
      if v == "your-super-secret-key-change-in-production" and not settings.DEBUG:
          raise ValueError("JWT_SECRET 必须在生产环境中设置")
      return v
  ```

#### P0 - 4.1.2 默认管理员硬编码弱密码

- **位置**: `backend/app/main.py` 第 44-48 行
- **现象**: DEBUG 模式下自动创建管理员账号，密码为弱密码 `argus123`，日志中明文输出此密码。
- **根因分析**: 开发便利性优先于安全，未考虑 DEBUG 模式可能被误用于生产。
- **代码证据**:
  ```python
  admin = User(username="admin", ..., password_hash=hash_password("argus123"), role="admin")
  logger.info("默认管理员账号已创建: admin / argus123")
  ```
- **影响**: 攻击者可使用已知凭据登录管理员账号，获得系统完全控制权。运行实例验证中正是使用此默认账号登录。
- **改进建议**: 从环境变量 `ADMIN_PASSWORD` 读取密码，或生成随机密码并仅打印一次。移除日志中的明文密码输出。

#### P1 - CORS 配置不安全

- **位置**: `backend/app/main.py` 第 173-179 行
- **现象**: `allow_origins=["*"]` 与 `allow_credentials=True` 同时使用，注释说"生产环境应限制"但未实现环境区分。
- **根因分析**: 开发时为方便使用通配符，未根据环境变量切换 CORS 策略。
- **代码证据**:
  ```python
  app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, ...)
  ```
- **影响**: 可能导致跨站请求伪造。
- **改进建议**: 生产环境必须使用明确的域名列表，通过环境变量 `CORS_ORIGINS` 配置。

#### P2 - DEBUG 模式绕过 Alembic 迁移

- **位置**: `backend/app/main.py` 第 67-70 行
- **现象**: DEBUG 模式下使用 `create_all` 直接创建表，绕过 Alembic 迁移系统，导致数据库 schema 与迁移记录不一致。
- **根因分析**: 开发便利性设计，但 docker-compose.yml 中 `DEBUG: "true"` 是默认值，导致生产部署也使用此模式。
- **代码证据**: `await conn.run_sync(Base.metadata.create_all)`
- **影响**: 生产环境迁移时可能出现冲突或数据丢失，迁移管理与生产部署脱节。
- **改进建议**: 移除 DEBUG 模式下的自动建表逻辑，统一使用 Alembic 迁移。在容器启动脚本中加入 `alembic upgrade head` 步骤。

#### P1 - 无速率限制

- **位置**: `backend/app/main.py`（全文件）
- **现象**: 整个应用未配置任何速率限制中间件，认证端点特别容易遭受暴力破解。
- **根因分析**: 未集成限流中间件。
- **影响**: 暴力破解密码、DoS 攻击。
- **改进建议**: 集成 `slowapi` 库，至少对认证端点实施限流。

#### P2 - 无请求体大小限制

- **位置**: `backend/app/main.py`
- **现象**: FastAPI 应用未配置 `max_body_size`，Pydantic schema 中字符串字段无长度限制。
- **根因分析**: 未添加请求体大小限制中间件。
- **影响**: 攻击者可发送超大请求体导致内存耗尽。
- **改进建议**: 添加请求体大小限制中间件，Pydantic 字段添加 `max_length` 约束。

### 4.2 Agent 核心引擎 (agents/)

#### P0 - 4.2.1 LLM 客户端全局单例导致并发任务状态污染

- **位置**: `backend/app/agents/llm.py` 第 178 行, `backend/app/services/agent_runner.py` 第 183-185 行
- **现象**: LLM 客户端是全局单例，`_current_task_id` 和 `token_budget` 是实例属性。多个任务并发运行时，后启动的任务会覆盖前一个任务的配置。
- **根因分析**: 全局单例设计未考虑并发场景，task_id 和 token_budget 作为实例属性而非方法参数传递。
- **代码证据**:
  ```python
  # llm.py 第 178 行
  self._current_task_id = task_id  # 实例属性，非局部变量
  # agent_runner.py 第 183-185 行
  llm = lats_graph._get_llm_client()  # 全局单例
  if llm.token_budget is None:
      llm.token_budget = TokenBudget(task_id=task_id, total_budget=500_000)
  ```
- **影响**: 任务 A 的 token 消耗被错误计入任务 B；token 事件被发送到错误的任务；预算控制失效。这是运行实例中数据不一致问题的架构根源之一。
- **改进建议**: 每个任务创建独立的 LLM 客户端实例，或将 task_id 和 token_budget 作为方法参数传递。

#### P1 - 图执行无全局超时

- **位置**: `backend/app/services/agent_runner.py` 第 205 行
- **现象**: LangGraph 图的执行没有全局超时保护，LLM 调用挂起或工具执行无限循环时任务将永远运行。
- **根因分析**: 未使用 `asyncio.wait_for` 包装图执行。
- **代码证据**: `result = await graph.ainvoke(initial_state)` （无超时）
- **影响**: 资源泄漏、僵尸任务、内存持续增长。
- **改进建议**: 添加全局超时：`result = await asyncio.wait_for(graph.ainvoke(initial_state), timeout=3600)`

#### P1 - TokenBudget 非线程安全

- **位置**: `backend/app/agents/token_budget.py` 第 47 行
- **现象**: `consume()` 方法修改 `spent` 字段时无锁保护，LATS 架构中多个协程可能并发调用 LLM。
- **根因分析**: 未使用 `asyncio.Lock` 保护共享状态。
- **代码证据**: `self.spent += total_tokens` （无锁）
- **影响**: 预算控制失效，可能导致超额消费。
- **改进建议**: 使用 `asyncio.Lock` 保护 consume 操作。

#### P2 - 全局单例遍布 LATS 子系统

- **位置**: `backend/app/agents/lats/graph.py` 第 37-60 行
- **现象**: 三个全局单例（_llm_client、_executor_pool、_expansion_engine）跨任务共享。
- **根因分析**: 模块级全局变量设计。
- **代码证据**:
  ```python
  _llm_client: LLMClient | None = None
  _executor_pool: ReactExecutorPool | None = None
  _expansion_engine: ExpansionEngine | None = None
  ```
- **影响**: 任务间互相影响，难以隔离故障。
- **改进建议**: 改为每任务创建独立实例，或使用依赖注入容器管理生命周期。

#### P2 - emit() 静默吞没所有异常

- **位置**: `backend/app/agents/emit.py` 第 36-37 行
- **现象**: 事件发射失败时仅记录警告，不向上传播。这是运行实例中漏洞数据不一致问题的直接根因之一。
- **根因分析**: 设计意图是不中断扫描流程，但缺少错误计数和熔断机制。
- **代码证据**:
  ```python
  except Exception as e:
      logger.warning("事件发射失败 [%s/%s]: %s", agent, event_type, e)
  ```
- **影响**: 数据库连接故障时生成大量无用日志，finding_confirmed 事件可能仅写入 events 表而未写入 findings 表，导致运行实例中观察到的漏洞数据不一致。
- **改进建议**: 添加错误计数和熔断机制，连续失败超过阈值时触发告警。对于 finding 类事件，应确保 finding 落库与事件发射在同一个事务中。

#### P2 - 路由逻辑中迭代计数依赖 Orchestrator 自增

- **位置**: `backend/app/agents/routing.py` 第 26 行
- **现象**: `iteration_count` 从 state 中读取，其自增逻辑在 Orchestrator 节点内部。如果 Orchestrator 因异常未能自增，可能导致无限循环。routing 中 `max_iter` 默认值为 5，与 `create_initial_state` 的默认值 8 不一致。
- **根因分析**: 迭代计数管理分散在多处，默认值不统一。
- **影响**: 可能导致无限循环或提前终止。
- **改进建议**: 统一 max_iter 默认值，在路由层独立维护迭代计数。

### 4.3 工具集 (tools/)

#### P0 - 4.3.1 沙箱执行器无真正的隔离

- **位置**: `backend/app/tools/sandbox.py` 第 26-27 行
- **现象**: `SandboxExecutor` 直接使用 `asyncio.create_subprocess_exec` 在应用进程所在的主机上执行命令，无任何隔离。
- **根因分析**: MVP 阶段仅做进程级隔离，未使用 Docker 容器。
- **代码证据**: `# 注释: MVP 阶段仅做进程级隔离，未使用 Docker 容器。`
- **影响**: 如果 LLM 生成的 nuclei 模板路径或参数被构造为恶意值，可能导致任意命令执行或信息泄露。nmap、subfinder、nuclei 都在主机上直接执行。
- **改进建议**: 所有外部命令执行应在 Docker 容器或 nsjail 中进行，使用 seccomp 配置文件限制系统调用。

#### P1 - Nuclei 模板路径注入

- **位置**: `backend/app/tools/nuclei_scanner.py` 第 105-107 行
- **现象**: `templates` 参数来自 LLM 输出，直接作为 nuclei 命令的 `-t` 参数，未验证路径范围。
- **根因分析**: 未对模板路径做白名单校验。
- **代码证据**:
  ```python
  if templates:
      for template in templates:
          cmd.extend(["-t", template])
  ```
- **影响**: 恶意路径可能导致信息泄露或非预期的模板执行。
- **改进建议**: 验证模板路径在允许的模板目录内，或仅允许模板 ID。

#### P1 - 所有 HTTP 工具禁用 SSL 验证

- **位置**: http_requester.py:112, sql_injection.py:159, ssrf_detector.py:133, auth_tester.py:128, dir_scanner.py:193
- **现象**: 所有工具在发送 HTTP 请求时都禁用了 SSL 证书验证。
- **根因分析**: 对安全测试工具的常见做法做了硬编码，未作为可配置选项。
- **影响**: 中间人攻击可以拦截或篡改工具与目标之间的通信。
- **改进建议**: 将 SSL 验证作为可配置选项，通过工具参数或全局配置控制，默认启用验证。

#### P1 - 端口扫描器和子域名枚举器缺少白名单校验

- **位置**: `backend/app/tools/port_scanner.py` 第 94-155 行, `backend/app/tools/subdomain_enum.py` 第 64-128 行
- **现象**: `PortScannerTool.execute()` 接受 `host` 参数不经过 `_validate_target()`，`SubdomainEnumTool` 同样未调用白名单校验。
- **根因分析**: `_validate_target()` 方法期望 URL 格式，非 URL 工具无法复用，且未实现专门的主机白名单校验。
- **影响**: SSRF 攻击面 - LLM 可让工具扫描任意内网主机（数据库、Redis、NATS 等）。
- **改进建议**: 为非 URL 工具添加专门的主机白名单校验逻辑，禁止扫描内网保留地址段。

#### P1 - PoC 执行工具代码注入风险

- **位置**: `backend/app/tools/run_poc.py` 第 30-35 行
- **现象**: PoC 代码来自 LLM 输出，仅做了长度检查，未做任何代码分析或危险操作检测。
- **根因分析**: 依赖沙箱容器隔离，但沙箱配置不当。
- **代码证据**:
  ```python
  code = params.get("code", "")
  if len(code) > 10000:
      return self._make_error_result("代码长度超过限制")
  ```
- **影响**: 如果沙箱逃逸，可能导致容器逃逸和主机入侵。
- **改进建议**: 添加代码静态分析，禁止 `import os; os.system`、`subprocess`、`socket` 等危险模块的使用。

#### P2 - 沙箱审计日志无限增长

- **位置**: `backend/app/tools/sandbox.py` 第 31 行
- **现象**: 审计日志列表无大小限制。
- **根因分析**: 使用 list 存储审计日志，无上限。
- **代码证据**: `self._audit_log: list[dict] = []`
- **影响**: 长时间运行后内存持续增长。
- **改进建议**: 使用 `collections.deque(maxlen=N)` 或定期持久化后清空。

#### P2 - 端口扫描器 socket 未在异常路径关闭

- **位置**: `backend/app/tools/port_scanner.py` 第 238-260 行
- **现象**: `sock` 在第 238 行创建，仅在成功路径调用 `sock.close()`。如果 `asyncio.wait_for` 超时，socket 不会被关闭。
- **根因分析**: 未使用 `try/finally` 确保资源释放。
- **影响**: 文件描述符泄漏。
- **改进建议**: 使用 `try/finally` 或上下文管理器确保 socket 关闭。

#### P2 - URL 参数拼接未编码

- **位置**: `backend/app/tools/sql_injection.py` 第 351-352 行, `backend/app/tools/ssrf_detector.py` 第 232-233 行
- **现象**: 注入载荷直接拼接到 URL 中，未使用 `urllib.parse.urlencode`。
- **根因分析**: 简单字符串拼接，未考虑 URL 编码。
- **代码证据**:
  ```python
  separator = "&" if "?" in url else "?"
  full_url = f"{url}{separator}{param}={value}"
  ```
- **影响**: 特殊字符可能破坏 URL 结构或被截断，导致测试不准确。
- **改进建议**: 使用 `urllib.parse.urlencode` 正确构建 URL。

#### P3 - 工具结果结构不一致

- **位置**: 全部工具文件
- **现象**: 各工具返回的结果字典结构不统一，增加下游处理复杂度。
- **根因分析**: 缺少统一的 ToolResult 基类定义。
- **影响**: 下游处理代码需要针对不同工具做特殊处理。
- **改进建议**: 定义统一的 `ToolResult` TypedDict 或基类，所有工具返回统一结构。

### 4.4 API 层 (api/)

#### P0 - 4.4.1 多个端点缺少认证

- **位置**: `backend/app/api/v1/events.py` 第 26-66 行, `backend/app/api/v1/steps.py` 第 23-93 行, `backend/app/api/v1/system.py` 第 68-110 行
- **现象**: `GET /tasks/{task_id}/events`、`GET /tasks/{task_id}/steps`、`GET /tasks/{task_id}/tree`、`GET /system/stats` 均无认证。
- **根因分析**: 端点定义时未添加 `Depends(get_current_user)` 依赖。
- **影响**: 任何人无需认证即可获取所有任务的执行细节和发现的漏洞信息，信息泄露。
- **改进建议**: 所有非公开端点必须添加 `Depends(get_current_user)`。

#### P1 - 无 IDOR 防护

- **位置**: `backend/app/api/v1/tasks.py`（全文件）, `backend/app/api/v1/findings.py`（全文件）
- **现象**: 端点要求认证但不检查当前用户是否有权访问请求的资源。Task 模型有 `created_by` 字段但从未在查询中使用。
- **根因分析**: service 层未实现所有权检查。
- **影响**: 水平越权 - 用户 A 可以查看/修改用户 B 的任务和漏洞数据。
- **改进建议**: 在 service 层添加所有权检查。

#### P1 - WebSocket 认证可选

- **位置**: `backend/app/api/v1/ws.py` 第 59-63 行
- **现象**: WebSocket 连接的 token 验证是可选的，token 为空时连接直接被接受。
- **根因分析**: token 参数定义为 `Optional[str] = Query(default=None)`，空值时不做验证。
- **代码证据**:
  ```python
  if token:  # token 是可选的
      payload = decode_access_token(token)
      if payload is None:
          await websocket.close(...)
          return
  # 如果 token 为 None，直接 accept
  await websocket.accept()
  ```
- **影响**: 未认证的攻击者可以实时监控任务执行、注入恶意搜索分支、终止节点等。
- **改进建议**: WebSocket 连接必须要求有效 token，移除可选逻辑。

#### P2 - 注册端点完全开放

- **位置**: `backend/app/api/v1/auth.py` 第 33-82 行
- **现象**: `/auth/register` 端点无任何限制，任何人都可以注册账号，新用户默认角色为 `operator`。
- **根因分析**: 未实现注册码机制或管理员邀请制。
- **影响**: 任意用户可注册并创建漏洞扫描任务。
- **改进建议**: 添加注册码机制、管理员邀请制，或限制仅管理员可创建账号。

#### P2 - JWT Token 在 URL 查询参数中传递

- **位置**: `backend/app/api/v1/ws.py` 第 39 行
- **现象**: JWT token 通过 URL 查询参数传递给 WebSocket，URL 会被记录在服务器访问日志、浏览器历史记录和代理日志中。
- **根因分析**: WebSocket API 不支持自定义 header，选择查询参数作为传递方式。
- **影响**: Token 泄露到日志中。前端报告 4.2 节同样存在此问题。
- **改进建议**: 使用 WebSocket 子协议（`Sec-WebSocket-Protocol`）或首次消息认证。

### 4.5 数据模型与数据库 (models/, alembic/)

#### P0 - 4.5.1 迁移与模型不一致

- **位置**: `backend/alembic/versions/001_initial_schema.py`
- **现象**: 迁移文件与 ORM 模型存在多处不一致。
- **根因分析**: 迁移文件与模型独立维护，未保持同步。
- **具体差异**:
  - 迁移文件未创建 `llm_providers` 表，但模型定义了该模型
  - 迁移中 `reports` 表的 `finding_id` 为 `nullable=False`（第 407 行），但模型中为 `nullable=True`（report.py 第 37 行）
  - 迁移中 `reports` 表缺少 `task_id` 字段和 `report_metadata` 列，但模型中定义了
- **影响**: 生产环境数据库缺少必要的表和列，导致应用崩溃。运行实例中使用 DEBUG 模式的 `create_all` 绕过了此问题，但生产部署必出问题。
- **改进建议**: 修复迁移文件使其与模型完全一致，创建新的迁移脚本添加缺失的表和列。

#### P1 - 多个外键缺失

- **位置**: `backend/app/models/task.py` 第 78 行, `backend/app/models/finding.py` 第 121 行, `backend/app/models/report.py` 第 68 行
- **现象**: `Task.created_by`、`Finding.report_id`、`Report.created_by` 均缺少外键约束。
- **根因分析**: 模型定义时遗漏外键约束。
- **影响**: 数据完整性无法保证，可能出现孤儿引用。
- **改进建议**: 添加外键约束，配合迁移脚本更新数据库。

#### P2 - 邮箱字段未设置唯一约束

- **位置**: `backend/app/models/user.py` 第 33-37 行
- **现象**: `email` 字段没有 `unique=True`，但 auth 路由中检查邮箱是否已注册。
- **根因分析**: 模型定义遗漏唯一约束。
- **影响**: 并发请求同时注册相同邮箱可能创建重复记录。
- **改进建议**: 添加 `unique=True` 约束，并创建迁移脚本。

#### P2 - 无软删除机制

- **位置**: 全部模型文件
- **现象**: 所有删除操作都是物理删除，配合 `ondelete="CASCADE"` 会级联删除所有关联数据。
- **根因分析**: 未实现软删除设计。
- **影响**: 对安全审计场景不可接受 - 漏洞发现和执行记录应该可追溯。
- **改进建议**: 实现软删除（`is_deleted` 字段）或归档机制。

#### P3 - datetime.utcnow() 使用已弃用 API

- **位置**: `event_bus.py` 第 68 行, `auth.py` 第 108 行, `task_service.py` 第 162 行
- **现象**: `datetime.utcnow()` 返回 naive datetime，在 Python 3.12 中已弃用。
- **根因分析**: 使用旧 API。
- **影响**: 时区处理不一致，可能导致时间比较错误。
- **改进建议**: 使用 `datetime.now(timezone.utc)` 返回 timezone-aware datetime。

### 4.6 Schema 层 (schemas/)

#### P2 - FindingUpdate 缺少枚举校验

- **位置**: `backend/app/schemas/finding.py` 第 68-71 行
- **现象**: `FindingUpdate` 的 `status` 和 `severity` 字段是自由字符串，未使用已定义的枚举校验。
- **根因分析**: 已定义枚举但未在 update schema 中使用。
- **代码证据**:
  ```python
  status: Optional[str] = Field(default=None, description="发现状态")
  severity: Optional[str] = Field(default=None, description="严重级别")
  ```
- **影响**: 客户端可以设置任意字符串值，导致数据不一致。
- **改进建议**: 使用 `FindingStatus` 和 `FindingSeverity` 枚举类型。

#### P2 - target_config 完全无结构校验

- **位置**: `backend/app/schemas/task.py` 第 24 行
- **现象**: `target_config` 接受任意 JSON 字典，没有 schema 定义。
- **根因分析**: 使用 dict 类型而非结构化 schema。
- **代码证据**: `target_config: dict = Field(description="目标配置（URL、范围等）")`
- **影响**: `target_url`、`scope` 等关键字段没有校验，LLM 可能收到格式不正确的配置。
- **改进建议**: 定义 `TargetConfig` Pydantic 模型，包含 `target_url`、`scope` 等字段及校验规则。

#### P2 - 测试文件使用不存在的 Schema 字段

- **位置**: `backend/tests/test_schemas.py`
- **现象**: 测试中使用 `TaskCreate(name="test", target_url="https://example.com", task_type="web_scan")`，但实际字段是 `target_config`、`target_type`、`strategy`。
- **根因分析**: 测试与代码不同步。
- **影响**: 测试无法通过，详见后端 4.9 节。

### 4.7 Services 层 (services/)

#### P1 - AgentRunner 后台任务无超时和资源控制

- **位置**: `backend/app/services/agent_runner.py` 第 205 行
- **现象**: `_run_graph` 方法执行 `await graph.ainvoke(initial_state)` 没有超时限制。
- **根因分析**: 未添加超时保护。
- **影响**: 如果 LLM API 响应缓慢或工具执行挂起，任务将无限期运行，占用内存和 asyncio 事件循环资源。
- **改进建议**: 添加 `asyncio.wait_for()` 包装，设置合理的全局超时（如 1 小时）。

#### P1 - 并发任务状态共享且无锁保护

- **位置**: `backend/app/services/agent_runner.py` 第 49-54 行
- **现象**: 三个共享字典在多个协程间读写，没有使用 `asyncio.Lock` 保护。
- **根因分析**: 依赖 GIL 但忽略了 `await` 点之间的逻辑竞争。
- **代码证据**:
  ```python
  self._tasks: dict[str, asyncio.Task] = {}
  self._pause_events: dict[str, asyncio.Event] = {}
  self._active_states: dict[str, dict] = {}
  ```
- **影响**: 在 `await` 点之间可能出现逻辑竞争。这也是运行实例中任务状态与 Agent 状态不一致的根因之一 - 任务异常终止时未同步更新 Agent 状态。
- **改进建议**: 使用 `asyncio.Lock` 保护关键操作，任务失败时遍历 `_active_states` 统一更新所有 Agent 状态。

#### P2 - 报告服务中使用同步 Jinja2

- **位置**: `backend/app/services/report_service.py` 第 220-223 行
- **现象**: `Environment` 和 `tmpl.render()` 是同步操作，在 async 上下文中会阻塞事件循环。
- **根因分析**: 直接使用同步 Jinja2 API。
- **代码证据**:
  ```python
  env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
  tmpl = env.get_template(f"{template_name}.md")
  return tmpl.render(...)
  ```
- **影响**: 对于大型报告，可能造成明显的延迟。这也影响了运行实例中报告导出功能的可用性。
- **改进建议**: 使用 `asyncio.to_thread()` 包装同步模板渲染。

#### P2 - FindingService 无去重逻辑

- **位置**: `backend/app/services/finding_service.py` 第 41-75 行
- **现象**: `create_finding` 不检查是否已存在相同类型+URL+参数的发现。这是运行实例中漏洞数据不一致问题的直接根因之一。
- **根因分析**: 未实现去重逻辑。
- **影响**: 在多轮迭代中，Agent 可能多次报告同一漏洞，导致重复记录。更严重的是，结合 emit() 静默吞没异常，可能导致 finding 事件已记录但 finding 数据未落库。
- **改进建议**: 添加基于 (task_id, type, trigger_path) 的去重逻辑，并确保 finding 落库与事件发射在同一事务中。

#### P2 - 任务删除不终止运行中的 Agent

- **位置**: `backend/app/api/v1/tasks.py` 第 124-139 行
- **现象**: `delete_task` 端点删除任务记录，但不检查任务是否正在运行，也不终止 AgentRunner 中的后台任务。
- **根因分析**: 删除逻辑未与 AgentRunner 联动。
- **影响**: 被删除的任务的 Agent 可能继续在后台运行，尝试写入已不存在的 task_id 的数据。
- **改进建议**: 删除任务前检查并终止运行中的 Agent。

### 4.8 Core 基础设施 (core/)

#### P0 - 4.8.1 加密密钥从 JWT_SECRET 派生

- **位置**: `backend/app/core/encryption.py` 第 16-21 行
- **现象**: Fernet 加密密钥直接从 `JWT_SECRET` 的 SHA-256 派生，没有使用 KDF 和 salt。
- **根因分析**: 密钥管理设计缺陷，未分离加密密钥与签名密钥。
- **代码证据**:
  ```python
  key = base64.urlsafe_b64encode(hashlib.sha256(settings.JWT_SECRET.encode()).digest())
  return Fernet(key)
  ```
- **影响**: 如果 JWT_SECRET 是默认值，所有加密的 API Key 都可被解密。JWT_SECRET 的变更会导致所有已加密的 API Key 无法解密。基础设施报告 6.4.1 节同样指出此问题。
- **改进建议**: 使用独立的 `ENCRYPTION_KEY` 环境变量，或使用 PBKDF2/HKDF 从 JWT_SECRET 派生加密密钥。

#### P1 - Playwright 以 --no-sandbox 模式运行

- **位置**: `backend/app/core/playwright_manager.py` 第 26 行
- **现象**: `--no-sandbox` 禁用了 Chromium 的沙箱保护。
- **根因分析**: 容器以 root 运行时 Chromium 需要 `--no-sandbox`。
- **代码证据**: `"args": ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]`
- **影响**: 如果 Playwright 访问恶意页面，浏览器漏洞可能被利用来逃逸到主机进程。基础设施报告 6.1.1 节指出容器以 root 运行是根因。
- **改进建议**: 在 Docker 容器中以非 root 用户运行，或使用 seccomp 配置文件替代 `--no-sandbox`。

#### P2 - 密码哈希使用非标准方案

- **位置**: `backend/app/core/security.py` 第 17-23 行
- **现象**: 使用 SHA-256 预哈希来绕过 bcrypt 的 72 字节限制，项目依赖中已包含 `passlib[bcrypt]` 但未使用。
- **根因分析**: 自实现密码哈希而非使用标准库。
- **代码证据**:
  ```python
  pw_bytes = hashlib.sha256(password.encode()).hexdigest().encode()
  salt = bcrypt.gensalt(rounds=12)
  return bcrypt.hashpw(pw_bytes, salt).decode()
  ```
- **影响**: 非标准方案可能存在未知风险。
- **改进建议**: 使用 `passlib` 库的 `CryptContext`。

#### P2 - EventBus WebSocket 客户端字典非线程安全

- **位置**: `backend/app/core/event_bus.py` 第 29 行
- **现象**: `_ws_clients` 字典在多个方法中被并发读写，在 `await` 期间列表可能被修改。
- **根因分析**: 未创建副本迭代。
- **代码证据**: `self._ws_clients: dict[str, list[Callable]] = {}`
- **影响**: 可能出现 `RuntimeError: list changed during iteration`。
- **改进建议**: 在广播时使用 `callbacks = list(self._ws_clients.get(task_id, []))` 创建副本。

#### P2 - NATS/Redis 无重连机制

- **位置**: `backend/app/core/nats_client.py` 第 29 行, `backend/app/core/redis.py` 第 23-27 行
- **现象**: NATS 和 Redis 连接均无重连配置，服务重启或网络抖动时连接不会自动恢复。
- **根因分析**: 未配置重连策略。
- **影响**: 连接断开后系统降级运行且无法自动恢复。这与运行实例中"系统异常"提示有关。
- **改进建议**: NATS 使用 `nats.connect(url, reconnect_cb=..., max_reconnect_attempts=-1)`；Redis 配置 `health_check_interval` 和 `socket_timeout`。

#### P2 - get_redis_client/get_nats_client 在未初始化时抛异常

- **位置**: `backend/app/core/redis.py` 第 47-48 行, `backend/app/core/nats_client.py` 第 62-63 行
- **现象**: 如果 Redis 或 NATS 在启动时连接失败，后续调用会抛出 `RuntimeError`。
- **根因分析**: lifespan 中 catch 了异常继续运行，但未提供降级处理。
- **影响**: 健康检查本身会崩溃。
- **改进建议**: 提供降级处理，返回 None 而非抛异常，调用方做空值检查。

#### P2 - 全局可变状态过多

- **位置**: 多个文件（redis.py, nats_client.py, playwright_manager.py, proxy_client.py, event_bus.py, agent_runner.py）
- **现象**: 整个 Core 层大量使用全局可变变量。
- **根因分析**: 模块级全局变量设计，未使用依赖注入。
- **影响**: 测试困难（全局状态难以 mock），并发安全无保障。详见第 7 节共性问题。
- **改进建议**: 引入依赖注入容器管理生命周期，参考 FastAPI 的 `Depends` 机制。

### 4.9 测试 (tests/)

#### P0 - 4.9.1 测试覆盖率极低

- **位置**: `backend/tests/`
- **现象**: `tests/unit/` 和 `tests/integration/` 目录为空，仅有 3 个测试文件。安全关键模块完全无测试。
- **根因分析**: 测试开发滞后于功能开发。
- **影响**: 核心业务逻辑无测试保障，重构和修改风险极高。详见第 7 节共性问题。
- **改进建议**: 优先为 API 端点、服务层、安全工具编写测试。

#### P1 - 现有测试存在大量错误

- **位置**: `backend/tests/test_agents.py`
- **现象**: 多个断言与实际代码不匹配：第 72 行断言 `result == "__end__"` 但实际返回 `"reporter"`；第 115 行断言 `state["blackboard"].target_profile["base_url"]` 但实际设置的是空字典；第 119 行断言 `state["max_iterations"] == 3` 但默认值是 8。
- **根因分析**: 测试与代码不同步。
- **影响**: 测试无法通过，给人虚假信心。详见第 7 节共性问题。
- **改进建议**: 修复所有断言使其与实际代码一致。

#### P1 - test_schemas.py 与实际 Schema 完全不匹配

- **位置**: `backend/tests/test_schemas.py`
- **现象**: 测试中使用的字段名与实际 Schema 定义完全不同（target_url vs target_config, UNCONFIRMED vs draft 等）。
- **根因分析**: Schema 重构后测试未更新。
- **影响**: 测试完全无法通过。
- **改进建议**: 根据当前 Schema 定义重写测试。

#### P2 - test_tools.py 断言错误

- **位置**: `backend/tests/test_tools.py` 第 47-49 行
- **现象**: `ToolRegistry.get()` 在工具不存在时抛出 `KeyError`，不返回 `None`，但测试断言返回 `None`。
- **根因分析**: 测试与实现行为不一致。
- **改进建议**: 修改测试断言为 `pytest.raises(KeyError)`。

#### P2 - 测试客户端 fixture 未覆盖依赖注入

- **位置**: `backend/tests/conftest.py` 第 61-68 行
- **现象**: `client` fixture 未通过 `app.dependency_overrides` 替换 `get_db` 依赖。
- **根因分析**: 未使用依赖注入覆盖机制。
- **影响**: API 测试可能命中真实数据库或因数据库未初始化而失败。
- **改进建议**: 使用 `app.dependency_overrides[get_db] = lambda: db_session`。

### 4.10 配置与依赖 (pyproject.toml, Dockerfile, alembic.ini)

#### P1 - 依赖版本未固定

- **位置**: `backend/pyproject.toml` 第 11-32 行
- **现象**: 所有依赖都使用无版本约束的指定方式，每次安装可能获得不同版本。
- **根因分析**: 未指定版本范围。
- **影响**: 依赖升级引入不兼容变更或安全漏洞，构建不可重现。
- **改进建议**: 使用 `pip-compile` 生成锁文件，或在 `pyproject.toml` 中指定最低版本。

#### P1 - Dockerfile 以 root 运行

- **位置**: `backend/Dockerfile`
- **现象**: Dockerfile 没有 `USER` 指令，容器以 root 身份运行。结合 `--no-sandbox` 的 Chromium 和直接执行外部命令的沙箱，风险极高。
- **根因分析**: 未创建非 root 用户。基础设施报告 6.1.1 节同样指出此问题。
- **影响**: 容器逃逸或 RCE 漏洞可直接获取宿主机 root 权限。
- **改进建议**: 添加 `RUN useradd -m argus` 和 `USER argus`。

#### P2 - Dockerfile 在运行时镜像中安装安全工具

- **位置**: `backend/Dockerfile` 第 30-31 行
- **现象**: nmap 安装在应用容器中，增加了攻击面。
- **根因分析**: 安全工具与应用混合部署。
- **影响**: 应用容器攻击面增大。
- **改进建议**: 安全工具应在独立的 sidecar 容器中运行。

#### P2 - 日志系统不统一

- **位置**: 全项目
- **现象**: 代码中混用 `logging` 和 `structlog`，structlog 在 pyproject.toml 中声明但未配置。
- **根因分析**: 日志方案未统一规划。
- **影响**: 日志格式不一致，难以统一收集和分析。基础设施报告 6.7.1 节同样指出此问题。
- **改进建议**: 统一使用 structlog 并配置 JSON 格式处理器。

#### P3 - alembic.ini 可能存在配置问题

- **位置**: `backend/alembic/env.py` 第 30-31 行
- **现象**: `settings = get_settings()` 在模块级别调用，使用 `@lru_cache` 缓存。如果环境变量在运行时被修改，Alembic 仍使用缓存的配置。
- **根因分析**: lru_cache 导致配置不可变。
- **影响**: 运行时修改环境变量对 Alembic 无效。
- **改进建议**: 可接受，但需文档说明。

---

## 5. 前端缺陷分析

### 5.1 整体架构与配置

#### P1 - Next.js rewrites 在 standalone 构建模式下无法运行时生效

- **位置**: `frontend/next.config.ts` 第 8-16 行 + `frontend/Dockerfile` 第 24-25 行
- **现象**: `rewrites()` 在构建时被解析，Dockerfile 中通过 `ARG BACKEND_INTERNAL_URL` 在构建时注入后端地址，运行时修改环境变量无效。
- **根因分析**: standalone 构建模式下 rewrites 在构建时固化，未使用运行时配置。
- **代码证据**:
  ```ts
  async rewrites() {
    const backendUrl = process.env.BACKEND_INTERNAL_URL || "http://localhost:8000";
  }
  ```
- **影响**: 同一镜像无法部署到不同后端地址的环境，丧失 Docker 镜像的可移植性。
- **改进建议**: 改为运行时反向代理，或使用 `NEXT_PUBLIC_API_BASE` 环境变量让前端直接请求后端。

#### P1 - 缺少安全响应头配置

- **位置**: `frontend/next.config.ts`
- **现象**: `nextConfig` 中未配置任何 `headers()`，缺少 CSP、X-Frame-Options、X-Content-Type-Options、Referrer-Policy 等安全头。
- **根因分析**: 未添加安全头配置。
- **影响**: XSS 攻击面扩大、点击劫持风险、MIME 嗅探攻击。
- **改进建议**: 添加 `headers()` 返回安全头配置，至少包含 CSP、X-Frame-Options: DENY、X-Content-Type-Options: nosniff。

#### P2 - TypeScript target 过低

- **位置**: `frontend/tsconfig.json` 第 3 行
- **现象**: `"target": "ES2017"` 过低，而项目使用 Next.js 15 + React 19 + Node 22。
- **根因分析**: 未更新 target 配置。
- **影响**: 代码体积略增，无法使用原生 `??=`、`.at()` 等特性。
- **改进建议**: 升级为 `"target": "ES2022"`。

#### P2 - 缺少 ESLint 配置文件

- **位置**: `frontend/package.json` 第 9 行
- **现象**: `package.json` 声明了 lint 脚本，但项目中没有 `.eslintrc` 或 `eslint.config.js/mjs` 文件。
- **根因分析**: ESLint 配置文件缺失。
- **影响**: 代码质量检查实际未启用。
- **改进建议**: 添加 ESLint 配置文件，至少 extends `next/core-web-vitals`。

#### P3 - 未使用的依赖 @xyflow/react

- **位置**: `frontend/package.json` 第 16 行
- **现象**: `@xyflow/react` 被声明为依赖，但全项目未找到任何 import 引用。
- **根因分析**: 引入后未使用或已替换为自写实现。
- **影响**: 增加 bundle 体积约 200KB+ (gzipped)。
- **改进建议**: 移除未使用依赖。

### 5.2 应用入口与路由

#### P1 - 所有页面均为 "use client"，完全丧失 SSR/SSG 优势

- **位置**: 全部 11 个 `page.tsx` 文件均以 `"use client"` 开头
- **现象**: Next.js App Router 的核心优势是服务端渲染和静态生成，但本项目所有页面都是客户端组件。
- **根因分析**: 数据获取逻辑直接在页面组件中使用 hooks，未分离页面壳层与数据组件。
- **影响**: 首屏加载白屏时间长，SEO 完全无效，Next.js 退化为纯 SPA。
- **改进建议**: 将数据获取逻辑保留在客户端组件中，但页面壳层改为服务端组件。利用 `loading.tsx`、`error.tsx` 等约定文件。

#### P1 - 缺少全局错误边界

- **位置**: `frontend/src/app/` 目录下无 `error.tsx`
- **现象**: 缺少 Next.js App Router 的错误边界文件，任何未捕获的运行时错误会导致整个应用白屏。
- **根因分析**: 未添加 error.tsx 约定文件。
- **影响**: 用户遇到任何 JS 异常都会看到空白页面，无错误提示，无恢复手段。
- **改进建议**: 添加 `src/app/error.tsx` 和 `src/app/global-error.tsx` 作为全局错误处理。

#### P2 - 缺少 loading.tsx 和 not-found.tsx

- **位置**: `frontend/src/app/` 目录下无 `loading.tsx`、`not-found.tsx`
- **现象**: 缺少约定路由文件，Next.js 不会自动展示加载态和自定义 404 页面。
- **根因分析**: 未添加约定文件。
- **改进建议**: 添加 `loading.tsx` 显示骨架屏，添加 `not-found.tsx` 提供友好的 404 页面。

#### P2 - layout.tsx 中 Provider 未包含 AuthGuard

- **位置**: `frontend/src/app/layout.tsx` + `providers.tsx`
- **现象**: `Providers` 组件只包裹了 `QueryClientProvider`，认证守卫 `AuthGuard` 被放在 `MainLayout` 内部，且没有 `middleware.ts` 做服务端路由保护。
- **根因分析**: 认证逻辑分散，未使用中间件。
- **影响**: 未认证用户可以直接访问路由，客户端守卫有闪烁延迟。
- **改进建议**: 添加 Next.js `middleware.ts` 在服务端检查认证 token。

#### P3 - globals.css 未利用 CSS 变量做主题切换

- **位置**: `frontend/src/app/globals.css` + `tailwind.config.ts`
- **现象**: `darkMode: "class"` 配置了类切换暗色模式，但 `<html className="dark">` 硬编码为 dark，light 模式完全未实现。
- **根因分析**: 仅实现暗色主题。
- **影响**: 无法支持浅色主题，主题扩展性差。
- **改进建议**: 如果只做暗色，移除 `darkMode` 配置避免误导；如需双主题，使用 CSS 变量实现。

### 5.3 状态管理与数据获取

#### P0 - 5.3.1 API 客户端在模块级直接调用 Zustand store

- **位置**: `frontend/src/lib/api.ts` 第 28 行
- **现象**: `request()` 函数内部直接调用 `useAuthStore.getState().token` 获取 token，在服务端渲染时返回初始值 null。
- **根因分析**: token 注入逻辑耦合在 API 客户端中，未通过拦截器或 Context 传递。
- **代码证据**:
  ```ts
  async function request<T>(path: string, options?: RequestInit): Promise<T> {
    const token = useAuthStore.getState().token;  // 模块级直接访问 store
  ```
- **影响**: 架构限制，阻碍未来 SSR 迁移；token 获取非响应式，登出后 inflight 请求仍携带旧 token。
- **改进建议**: 将 token 注入逻辑移到 fetch interceptor 或通过 React Context 传递。

#### P1 - useEventStream 中事件列表和去重 Set 无限增长

- **位置**: `frontend/src/hooks/use-events.ts` 第 59 行, 第 99 行
- **现象**: `seenIds` (Set) 和 `events` (数组) 都没有上限，长时间运行的任务会持续累积事件，最终导致内存溢出和渲染卡顿。
- **根因分析**: 未设置最大长度限制。
- **代码证据**:
  ```ts
  const seenIds = useRef<Set<string>>(new Set());  // 无上限
  setEvents((prev) => [...prev, event]);  // 无上限追加
  ```
- **影响**: 运行数小时后内存占用持续增长，OverviewPanel 渲染全部事件导致 DOM 节点爆炸，页面卡死。
- **改进建议**: 对 `events` 数组设置最大长度（如 1000 条），超出时丢弃最旧事件；`seenIds` 同步清理。

#### P2 - useTasks 和 useTask 的 refetchInterval 双重轮询

- **位置**: `frontend/src/hooks/use-tasks.ts` 第 31-36 行, 第 50-53 行
- **现象**: `useTask` 的 5 秒轮询加上 `useTasks` 的 10 秒轮询同时运行时，会产生双重请求。
- **根因分析**: 两个 hook 独立轮询，未协调。
- **影响**: 同一任务详情被两个 hook 同时轮询，浪费网络请求。
- **改进建议**: 在任务详情页只使用 `useTask`，列表页只在用户可见时轮询。

#### P2 - WebSocket 心跳定时器未在 disconnect 时清除

- **位置**: `frontend/src/lib/websocket.ts` 第 111-115 行
- **现象**: 心跳定时器在 `use-events.ts:127` 中创建，但 `disconnect()` 方法不清除心跳定时器。
- **根因分析**: 心跳逻辑分散在 hook 层和 manager 层。
- **影响**: React 18 Strict Mode 双重挂载时可能产生多个心跳定时器。
- **改进建议**: 将心跳逻辑移入 WebSocketManager 类内部，在 `connect()` 时启动、`disconnect()` 时停止。

#### P2 - api.ts 错误处理不够细粒度

- **位置**: `frontend/src/lib/api.ts` 第 53-56 行
- **现象**: 非 401 错误统一抛出 `new Error(error.detail || ...)`，丢失了 HTTP 状态码信息。401 自动登出后直接 `window.location.href` 跳转，导致当前页面状态丢失。
- **根因分析**: 错误处理过于简单。
- **代码证据**:
  ```ts
  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(error.detail || `HTTP ${res.status}`);
  }
  ```
- **影响**: 调用方无法区分 403/404/500/502 等不同错误类型。
- **改进建议**: 创建自定义 ApiError 类包含 status code、detail 字段。区分网络错误和业务错误。

#### P3 - QueryClient 配置 staleTime 过短

- **位置**: `frontend/src/app/providers.tsx` 第 11 行
- **现象**: `staleTime: 30 * 1000` (30秒) 对于变化不频繁的数据过短。
- **改进建议**: 为不同数据类型设置不同的 staleTime，或在各 hook 中单独配置。

### 5.4 认证与安全

#### P0 - 5.4.1 JWT Token 存储在 localStorage

- **位置**: `frontend/src/stores/auth.ts` 第 26-44 行
- **现象**: 使用 Zustand `persist` 中间件，JWT token 以明文形式保存在 `localStorage["argus-auth"]` 中。
- **根因分析**: 默认使用 localStorage 持久化。
- **代码证据**:
  ```ts
  export const useAuthStore = create<AuthState>()(
    persist(
      (set) => ({ token: null, user: null }),
      { name: "argus-auth" }  // localStorage key
    )
  );
  ```
- **影响**: 任何 XSS 攻击都可以通过 `localStorage.getItem("argus-auth")` 窃取 token。对于安全工具平台，这是极其危险的。
- **改进建议**: 使用 httpOnly + Secure + SameSite cookie 存储 token，前端无法通过 JS 读取。后端设置 cookie，前端 fetch 自动携带。

#### P0 - 5.4.2 WebSocket 通过 URL 查询参数传递 JWT Token

- **位置**: `frontend/src/lib/websocket.ts` 第 44-49 行
- **现象**: WebSocket 连接时将 JWT token 拼接到 URL 查询参数中。
- **根因分析**: WebSocket API 不支持自定义 header，选择查询参数作为传递方式。后端 ws.py 第 39 行同样接受此方式。
- **代码证据**:
  ```ts
  const tokenParam = token ? `?token=${encodeURIComponent(token)}` : "";
  this.ws = new WebSocket(`${protocol}//${host}/api/v1/ws/tasks/${this.taskId}/stream${tokenParam}`);
  ```
- **影响**: Token 泄露到服务器访问日志、代理日志、浏览器历史记录、Referer 头中。
- **改进建议**: WebSocket 连接后通过 `ws.send()` 发送认证消息，或使用 Sec-WebSocket-Protocol header 传递 token。

#### P1 - 认证守卫纯客户端实现，存在安全闪烁

- **位置**: `frontend/src/components/layout/auth-guard.tsx`
- **现象**: `AuthGuard` 通过 `useEffect` 在客户端检查认证状态，首次渲染时显示加载态，useEffect 执行后才判断是否跳转。
- **根因分析**: 未使用服务端中间件。
- **影响**: 受保护页面的 JS bundle 会先被下载和执行，敏感组件代码暴露给未认证用户，存在短暂的内容闪烁。
- **改进建议**: 添加 Next.js `middleware.ts` 在服务端检查认证 cookie/token。

#### P1 - 登录流程先保存临时用户信息再请求真实信息

- **位置**: `frontend/src/app/login/page.tsx` 第 35-39 行
- **现象**: 登录后先 `login(access_token, { id: "", username, email: "", role: "" })` 保存临时空用户信息，再请求 `/auth/me` 获取真实信息。
- **根因分析**: 登录流程设计不合理。
- **代码证据**:
  ```ts
  login(access_token, { id: "", username, email: "", role: "" });  // 临时空信息
  const userData = await authApi.me();
  login(access_token, userData);  // 真实信息
  ```
- **影响**: 如果 `/auth/me` 请求失败，用户会停留在空的认证状态，但 `isAuthenticated` 为 true。
- **改进建议**: 先请求 `/auth/me`，成功后再一起保存 token 和用户信息。或登录接口直接返回用户信息。

#### P2 - 登出未通知后端使 token 失效

- **位置**: `frontend/src/components/layout/header.tsx` 第 35-38 行
- **现象**: `handleLogout` 仅调用 `logout()` 清除前端状态并跳转，未调用后端登出 API 使 JWT token 失效。
- **根因分析**: 未实现后端登出。
- **影响**: 被窃取的 token 在过期前仍然有效。
- **改进建议**: 登出时调用后端 `/auth/logout` 使 token 加入黑名单。

#### P2 - 无 CSRF 防护

- **位置**: `frontend/src/lib/api.ts`
- **现象**: 所有 API 请求通过 fetch 发送，未携带 CSRF token。
- **根因分析**: 当前使用 Bearer token 认证，CSRF 风险较低但未添加额外防护。
- **改进建议**: 如果保持 Bearer token 认证，建议添加 `X-Requested-With` 头。

### 5.5 组件设计

#### P1 - OverviewPanel 使用 any 类型丧失类型安全

- **位置**: `frontend/src/components/execution/OverviewPanel.tsx` 第 129-133 行
- **现象**: `OverviewPanelProps` 中 `task` 和 `findingsData` 都定义为 `any` 类型。
- **根因分析**: 类型定义不完整。
- **代码证据**:
  ```ts
  interface OverviewPanelProps {
    task: any;          // 应为 Task
    events: AgentEvent[];
    connected: boolean;
    findingsData: any;  // 应为 PaginatedResponse<Finding>
  }
  ```
- **影响**: 组件内部访问无类型检查，重构时易出错。这也是运行实例中漏洞数据不一致问题的前端根因之一。
- **改进建议**: 使用正确的类型 `Task` 和 `PaginatedResponse<Finding>`。

#### P1 - React Fragment 缺少 key 导致列表渲染警告

- **位置**: `frontend/src/app/findings/page.tsx` 第 90-173 行
- **现象**: `data.items.map((finding) => (<>...</>))` 中使用 Fragment 简写 `<>`，无法添加 key。
- **根因分析**: 使用 Fragment 简写而非带 key 的形式。
- **影响**: React 控制台报 warning，可能影响 diff 性能。
- **改进建议**: 使用 `<Fragment key={finding.id}>` 替代 `<>`。

#### P1 - wsRef 声明但从未赋值，InterventionPanel 的 wsSend 永远无效

- **位置**: `frontend/src/app/tasks/[id]/page.tsx` 第 39 行, 第 48-52 行, 第 161 行
- **现象**: 组件声明了 `const wsRef = useRef<WebSocket | null>(null)`，但从未将其赋值为实际的 WebSocket 实例，`wsRef` 始终为 null。`wsSend` 函数中 `wsRef.current.readyState === WebSocket.OPEN` 永远为 false。
- **根因分析**: WebSocket 连接在 `useEventStream` hook 内部管理，wsRef 未与 hook 内部的 WebSocket 实例关联。
- **代码证据**:
  ```ts
  const wsRef = useRef<WebSocket | null>(null);  // 永远为 null
  const wsSend = useCallback((msg: object) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {  // 永远 false
      wsRef.current.send(JSON.stringify(msg));
    }
  }, []);
  <InterventionPanel ... wsSend={wsSend} />  // wsSend 永远不发送
  ```
- **影响**: 用户干预功能完全失效，用户无法在任务执行过程中进行任何手动干预。这是运行实例中缺少任务控制按钮的根因之一。
- **改进建议**: `useEventStream` 应暴露 WebSocketManager 实例或 send 方法，或将 wsRef 传入 hook。

#### P2 - 重复的任务操作按钮逻辑

- **位置**: `frontend/src/app/tasks/page.tsx` 第 19-38 行 vs `src/app/tasks/[id]/page.tsx` 第 92-126 行
- **现象**: `getTaskActions` 函数和任务详情页内联了几乎相同的条件渲染逻辑。
- **根因分析**: 未抽取共享组件。
- **影响**: 修改操作按钮逻辑时需要同步两处，容易遗漏。
- **改进建议**: 抽取为共享组件 `<TaskActions task={task} onAction={...} />`。

#### P2 - 大量组件缺少 React.memo 和 useCallback 优化

- **位置**: 全部 execution 组件
- **现象**: 每次新事件到达时 `events` 引用变化，所有子组件都会重新渲染，即使它们只关心特定类型的事件。
- **根因分析**: 未使用 React.memo 和 useMemo 优化。
- **影响**: 高频事件流时，每个事件触发全量重渲染，导致 CPU 占用高、界面卡顿。
- **改进建议**: 使用 `React.memo` 包裹子组件，配合 `useMemo` 对 events 做选择性 memo。

#### P2 - UI 组件全部标记 "use client"

- **位置**: `frontend/src/components/ui/*.tsx`（全部 5 个文件）
- **现象**: Badge、Button、Card、EmptyState、Loading 都标记了 `"use client"`，但这些组件没有使用任何客户端 API。
- **根因分析**: 统一添加 "use client" 而非按需添加。
- **影响**: 这些组件无法在服务端组件中使用，强制所有使用它们的页面都是客户端组件。
- **改进建议**: 移除 Card、Badge、Loading、EmptyState 的 `"use client"`。

#### P3 - statusColor 和 severityColor 函数与 Badge 组件逻辑重复

- **位置**: `frontend/src/lib/utils.ts` 第 23-57 行 vs `src/components/ui/badge.tsx` 第 14-37 行
- **现象**: `severityColor()` 和 `statusColor()` 函数在 utils.ts 中定义了颜色映射，Badge 组件内部也有自己的映射，两套逻辑独立维护。
- **根因分析**: 颜色映射逻辑未统一。
- **影响**: 同一状态在不同位置可能显示不同颜色。
- **改进建议**: 统一颜色映射逻辑到单一数据源。

#### P3 - statusColor 缺少 "created" 和 "done" 状态

- **位置**: `frontend/src/lib/utils.ts` 第 39-56 行
- **现象**: `TaskStatus` 类型包含 `"created"` 和 `"done"`，但 `statusColor()` 的参数类型和映射表中都没有这两个值。
- **根因分析**: 类型定义与实现不匹配。
- **影响**: `created` 和 `done` 状态的任务返回默认 `pending` 颜色，可能造成视觉混淆。
- **改进建议**: 补充缺失的状态颜色映射。

### 5.6 实时通信

#### P0 - 5.6.1 WebSocket 重连失败后无用户反馈

- **位置**: `frontend/src/lib/websocket.ts` 第 122-126 行
- **现象**: 重连最多 5 次，达到上限后 `scheduleReconnect()` 直接 return，不再尝试重连，但没有任何回调通知 UI 层连接已永久断开。
- **根因分析**: 缺少 `onReconnectFailed` 回调。
- **代码证据**:
  ```ts
  private scheduleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) return;  // 静默放弃
  ```
- **影响**: 网络长时间中断后，用户以为只是暂时断开，实际上已停止重连，无法再收到实时事件。
- **改进建议**: 添加 `onReconnectFailed` 回调，UI 显示"连接已断开，点击重试"并提供手动重连按钮。

#### P1 - WebSocket 消息解析失败静默忽略

- **位置**: `frontend/src/lib/websocket.ts` 第 57-68 行
- **现象**: `onmessage` 中 `JSON.parse` 失败时 catch 块为空，静默忽略，不记录日志，不通知用户。
- **根因分析**: 异常处理过于宽泛。
- **代码证据**:
  ```ts
  this.ws.onmessage = (e: MessageEvent) => {
    try {
      const msg = JSON.parse(e.data);
    } catch {
      // 解析失败静默忽略
    }
  };
  ```
- **影响**: 后端发送格式错误的消息时，前端无任何感知，调试困难。这与后端 emit() 静默吞没异常形成前后端双重静默。
- **改进建议**: 至少 `console.error` 记录解析失败的消息内容。

#### P1 - OverviewPanel 事件流无虚拟化

- **位置**: `frontend/src/components/execution/OverviewPanel.tsx` 第 272-308 行
- **现象**: 事件流容器 `h-[500px] overflow-y-auto` 直接渲染全部 `filteredEvents`，每个事件是一个 `<div>`。
- **根因分析**: 未使用虚拟滚动。
- **影响**: 长时间运行的任务中，事件积累到数千条后，DOM 节点数量爆炸，滚动卡顿，内存占用高。
- **改进建议**: 使用虚拟滚动库（如 `@tanstack/react-virtual`）或限制渲染条数。

#### P2 - WebSocket onerror 触发 close 但未阻止重复 close

- **位置**: `frontend/src/lib/websocket.ts` 第 70-78 行
- **现象**: `onerror` 调用 `this.ws?.close()`，这会触发 `onclose`，如果 `onerror` 和 `onclose` 同时触发，`scheduleReconnect` 可能被调用两次。
- **根因分析**: 未检查是否已有定时器在运行。
- **影响**: 多个重连定时器同时运行，可能导致多次并发连接尝试。
- **改进建议**: 在 `scheduleReconnect` 开始时检查是否已有定时器在运行。

#### P2 - MessageCallback 使用 any 类型

- **位置**: `frontend/src/lib/websocket.ts` 第 10 行
- **现象**: `type MessageCallback = (msg: any) => void;` 使用 any 类型。
- **改进建议**: 定义 `WebSocketMessage` 联合类型替代 any。

#### P3 - 心跳间隔 30 秒可能过长

- **位置**: `frontend/src/hooks/use-events.ts` 第 127-129 行
- **现象**: 30 秒心跳间隔，如果中间网络设备的 idle timeout 小于 30 秒，连接可能被静默关闭。
- **改进建议**: 缩短为 15-20 秒，或根据后端配置调整。

### 5.7 类型定义

#### P1 - 大量 Record<string, any> 类型滥用

- **位置**: `frontend/src/types/index.ts`
- **现象**: 多个接口使用 `Record<string, any>` 作为字段类型，包括 `Task.progress`、`Task.config`、`Task.error_info`、`AgentEvent.data`（最严重）、`Finding.trigger_path`、`Finding.reproduction_steps`、`Finding.evidence`。
- **根因分析**: 类型定义不完整，使用 any 绕过类型检查。
- **影响**: `AgentEvent.data` 为 `Record<string, any>` 意味着所有 `event.data.xxx` 访问都没有类型检查。这与后端 schema 严重脱节，也是运行实例中数据不一致问题的前端类型根因。
- **改进建议**: 为不同 `event_type` 定义对应的 data 类型，使用联合类型。

#### P2 - TaskStatus 包含 "done" 但多处代码未处理

- **位置**: `frontend/src/types/index.ts` 第 6 行 vs 多处使用
- **现象**: `TaskStatus` 类型包含 `"done"`，但 utils.ts 的 `statusColor()`、badge.tsx 的 `statusVariant`、tasks/page.tsx 的 `getTaskActions()` 都不包含 `"done"`。
- **根因分析**: 类型定义与实现不匹配。
- **影响**: `done` 状态的任务在列表中显示默认颜色，无操作按钮，用户可能困惑。
- **改进建议**: 统一处理所有 TaskStatus 值。

#### P2 - ApiResponse 接口定义但未使用

- **位置**: `frontend/src/types/index.ts` 第 96-100 行
- **现象**: 定义了 `ApiResponse<T>` 接口，但 api.ts 中的 `request()` 函数直接解包 `{code, data}` 结构，未使用此类型。`ApiResponse` 的 `success` 字段与实际后端的 `code` 字段不匹配。
- **根因分析**: 类型定义与实际使用脱节。
- **改进建议**: 修正 `ApiResponse` 使其与后端一致并在 api.ts 中使用，或删除未使用的定义。

#### P3 - as any 类型断言

- **位置**: `frontend/src/app/tasks/new/page.tsx` 第 64, 66 行
- **现象**: `target_type: targetType as any` 和 `strategy: strategy as any` 使用 as any 绕过类型检查。
- **改进建议**: 使用 `satisfies` 操作符或正确的类型断言。

### 5.8 性能问题

#### P1 - 无代码分割和懒加载

- **位置**: 全项目
- **现象**: 所有 execution 组件在任务详情页直接 import，全部打包到同一个 chunk，没有任何 `next/dynamic` 或 `React.lazy` 使用。
- **根因分析**: 未使用动态导入。
- **影响**: 首次加载任务详情页时下载所有面板代码（包括不活跃的 tab），首屏加载慢。
- **改进建议**: 使用 `next/dynamic(() => import(...), { ssr: false })` 按需加载非活跃 tab 的组件。

#### P1 - StatsPanel 中多个 useMemo 遍历全部事件

- **位置**: `frontend/src/components/execution/StatsPanel.tsx` 第 50-116 行
- **现象**: 六个 `useMemo` 都遍历 `events` 数组。其中 `treeStats`、`tokenUsage`、`knowledgeSummary` 只需要最后一个匹配事件，却遍历全部。
- **根因分析**: useMemo 依赖整个 events 数组，未做增量优化。
- **代码证据**:
  ```ts
  const treeStats = useMemo<TreeStats>(() => {
    const cycleEvents = events.filter((e) => e.type === "cycle_summary" || e.type === "cycle_complete");
    const last = cycleEvents[cycleEvents.length - 1];  // 只需最后一个，但遍历全部
  }, [events]);
  ```
- **影响**: 事件数达到数千条时，每次新事件触发 6 次全量遍历，性能下降明显。
- **改进建议**: 只需要最新值的计算，改为从数组末尾反向查找，或维护增量更新。

#### P2 - 表格列表无分页 UI

- **位置**: `frontend/src/app/tasks/page.tsx`、`src/app/findings/page.tsx`
- **现象**: 任务列表和漏洞列表页面调用 `useTasks()` / `useFindings()` 时未传递分页参数，UI 上没有分页控件。
- **根因分析**: 未实现分页 UI。
- **影响**: 数据量大时用户无法浏览全部数据。运行实例中任务列表无分页功能已被观察到。
- **改进建议**: 添加分页控件，传递 page 和 page_size 参数。

#### P2 - header.tsx 每 60 秒健康检查

- **位置**: `frontend/src/components/layout/header.tsx` 第 26-31 行
- **现象**: 系统健康状态每 60 秒轮询一次，且 `retry: false` 意味着首次失败后不再重试。
- **根因分析**: 轮询配置不合理。
- **影响**: 健康检查请求持续运行，即使后端已恢复。这与运行实例中"系统异常"提示有关。
- **改进建议**: 设置更长的间隔（如 120 秒）或使用 WebSocket 事件驱动状态更新。

### 5.9 用户体验

#### P1 - 无全局错误提示/通知系统

- **位置**: 全项目
- **现象**: 所有 mutation 错误只在各页面局部处理或完全不处理。例如 `settings/page.tsx` 的 `handleSubmit` 中 `await updateMutation.mutateAsync(...)` 没有 try-catch。
- **根因分析**: 未实现全局通知系统。
- **影响**: 操作失败时用户无感知，不知道操作是否成功。运行实例中"系统异常"提示无法查看详情正是此问题的体现。
- **改进建议**: 添加全局 toast/notification 系统（如 react-hot-toast），在 mutation 的 `onError` 中显示错误提示。

#### P1 - Settings 模态框缺少 Escape 和背景点击关闭

- **位置**: `frontend/src/app/settings/page.tsx` 第 248-393 行
- **现象**: 模态框使用 `fixed inset-0 z-50`，但背景遮罩 `div` 没有 `onClick` 关闭逻辑，也没有 Escape 键监听。
- **根因分析**: 未实现模态框标准交互。
- **影响**: 用户体验不佳，不符合模态框交互惯例。
- **改进建议**: 背景点击关闭模态框，添加 `useEffect` 监听 Escape 键。

#### P2 - 登录页面无密码可见性切换

- **位置**: `frontend/src/app/login/page.tsx` 第 111-119 行
- **现象**: 密码输入框 `type="password"` 无切换按钮。
- **根因分析**: 未添加可见性切换功能。运行实例中已观察到此问题。
- **改进建议**: 添加密码可见性切换图标按钮。

#### P2 - EmptyState 组件的 onAction 使用 window.location.href

- **位置**: `frontend/src/app/tasks/page.tsx` 第 85-88 行
- **现象**: `EmptyState` 的 `onAction` 使用 `window.location.href = "/tasks/new"` 进行整页刷新跳转，而非 Next.js 的 `router.push`。
- **根因分析**: 使用了传统跳转方式。
- **影响**: 页面完全重新加载，丢失所有客户端状态。
- **改进建议**: 使用 `useRouter().push("/tasks/new")`。

#### P2 - 表格无响应式设计

- **位置**: `tasks/page.tsx`、`findings/page.tsx`、`settings/page.tsx`
- **现象**: 所有表格使用 `overflow-x-auto` 处理窄屏幕，但列数多时移动端体验极差。
- **根因分析**: 未实现响应式表格设计。
- **改进建议**: 移动端切换为卡片列表布局，或隐藏次要列。

#### P3 - 无国际化支持

- **位置**: 全项目
- **现象**: 所有文本硬编码为中文，无 i18n 框架。
- **改进建议**: 如果只需中文可接受，否则引入 next-intl 或类似方案。

### 5.10 构建与部署

#### P1 - Dockerfile 使用 npm install 而非 npm ci

- **位置**: `frontend/Dockerfile` 第 10 行
- **现象**: 使用 `npm install` 而非 `npm ci`，可能更新 lock 文件，安装的版本可能与 `package-lock.json` 不一致。
- **根因分析**: 使用了错误的安装命令。
- **代码证据**:
  ```dockerfile
  COPY package.json ./
  RUN npm install
  ```
- **影响**: 不同时间构建的镜像可能包含不同版本的依赖，引入难以排查的 bug。
- **改进建议**: 改为 `COPY package.json package-lock.json ./` + `RUN npm ci`。

#### P2 - Dockerfile 未复制 package-lock.json

- **位置**: `frontend/Dockerfile` 第 9 行
- **现象**: `COPY package.json ./` 只复制了 package.json，未复制 package-lock.json。
- **根因分析**: COPY 指令不完整。
- **影响**: 即使改用 `npm ci` 也会因缺少 lock 文件而失败。
- **改进建议**: 添加 `COPY package.json package-lock.json ./`。

#### P2 - Dockerfile 缺少 .dockerignore

- **位置**: 项目根目录无 `.dockerignore`
- **现象**: Dockerfile 中 `COPY . .` 会将 `node_modules`、`.next`、`.git` 等全部复制到构建上下文中。基础设施报告 6.1.4 节同样指出全项目无 .dockerignore。
- **根因分析**: 未创建 .dockerignore 文件。
- **影响**: 构建缓慢，构建上下文体积大。
- **改进建议**: 添加 `.dockerignore` 排除 `node_modules`、`.next`、`.git` 等。

#### P2 - HEALTHCHECK 使用 wget 但 node:22-alpine 可能不包含 wget

- **位置**: `frontend/Dockerfile` 第 54-55 行
- **现象**: `CMD wget -q --spider http://127.0.0.1:3000 || exit 1`，`node:22-alpine` 基础镜像默认可能不安装 wget。
- **根因分析**: 健康检查命令依赖可能不存在的工具。
- **影响**: 健康检查可能失败导致容器被标记为 unhealthy。
- **改进建议**: 使用 `node -e "require('http').get(...)"` 或安装 curl。

#### P3 - docker-compose.yml 中 NEXT_PUBLIC_WS_HOST 配置错误

- **位置**: `docker-compose.yml` 第 103 行
- **现象**: `NEXT_PUBLIC_WS_HOST: localhost:8000` 配置为 localhost:8000，但前端运行在容器内（端口 3000），容器内的 localhost 指向自身。
- **根因分析**: 环境变量配置错误。
- **影响**: Docker 部署时 WebSocket 连接失败。
- **改进建议**: 移除 `NEXT_PUBLIC_WS_HOST` 环境变量，让 websocket.ts 使用默认的 `window.location.host`。

---

## 6. 基础设施与工程化缺陷分析

### 6.1 容器化与编排

#### P0 - 6.1.1 后端、mitmproxy、crawlergo 容器以 root 运行

- **位置**: `backend/Dockerfile`、`mitmproxy/Dockerfile`、`crawlergo/Dockerfile`
- **现象**: 三个服务的 Dockerfile 均没有 `USER` 指令，容器内进程以 root 身份运行。仅 frontend 和 poc-sandbox 创建了非 root 用户。
- **根因分析**: 未添加非 root 用户配置。后端报告 4.10.2 节同样指出此问题。
- **影响**: 容器逃逸或 RCE 漏洞可直接获取宿主机 root 权限。crawlergo 的 Chromium 以 root 运行需 `--no-sandbox`，进一步放大风险。
- **改进建议**: 为所有容器创建非 root 用户：`RUN useradd -m -s /bin/bash argus` + `USER argus`

#### P0 - 6.1.2 所有服务端口暴露到宿主机

- **位置**: `docker-compose.yml` 多处
- **现象**: PostgreSQL(5432)、Redis(6379)、NATS(4222/8222)、mitmproxy(8080)、crawlergo(7777)、poc-sandbox(9090) 全部映射到宿主机端口。
- **根因分析**: 开发便利性配置，使用 `ports` 而非 `expose`。
- **影响**: 数据库、Redis 等基础设施暴露在外网；poc-sandbox 的 `/execute` 端点无认证，任何人可远程执行 Python 代码；crawlergo 的 `/crawl` 端点无认证，可被滥用发起 SSRF。
- **改进建议**: 仅暴露 frontend(3000) 和 backend(8000) 到宿主机；其余服务使用 Docker 内部网络通信。

#### P1 - 无网络隔离

- **位置**: `docker-compose.yml`
- **现象**: 所有服务在默认 bridge 网络中，无自定义网络定义。poc-sandbox（执行不可信代码）与 PostgreSQL、Redis 在同一网络平面。
- **根因分析**: 未配置自定义网络。
- **影响**: PoC 沙箱逃逸后可直接访问数据库和 Redis；mitmproxy 可嗅探内部流量。
- **改进建议**: 划分前端网络、后端网络、数据层网络、沙箱隔离网络，通过 `networks` 配置严格限制跨网络访问。

#### P1 - 无 .dockerignore 文件

- **位置**: 项目根目录及各子目录
- **现象**: 全项目无任何 `.dockerignore` 文件。前端报告 5.10.3 节同样指出此问题。
- **根因分析**: 未创建 .dockerignore 文件。
- **影响**: 构建上下文过大，构建缓慢；测试文件和缓存进入生产镜像，增大攻击面；可能泄露 `.env` 等敏感文件。
- **改进建议**: 为每个有 Dockerfile 的目录创建 `.dockerignore`，排除 `__pycache__`、`.pytest_cache`、`node_modules`、`.next`、`.git`、`.env` 等。

#### P1 - 硬编码密钥与默认凭据

- **位置**: `docker-compose.yml` 第 17、65、70 行；`backend/app/main.py` 第 33-52 行
- **现象**: PostgreSQL 密码硬编码 `argus_dev_password`；JWT 密钥默认值 `argus-dev-secret-key-2024`；DEBUG 模式开启导致自动创建 admin/argus123。
- **根因分析**: 开发配置直接用于 docker-compose 默认配置。后端报告 4.1.1 和 4.1.2 节同样指出此问题。
- **影响**: 使用默认配置部署即等于开放系统。
- **改进建议**: 强制要求环境变量注入密钥，无默认值；DEBUG 模式不应用于 docker-compose 默认配置。

#### P2 - 资源限制不均衡

- **位置**: `docker-compose.yml`
- **现象**: 仅 poc-sandbox 配置了资源限制（CPU 1.0 / Memory 512M），其余 7 个服务无任何限制。
- **根因分析**: 未统一配置资源限制。
- **影响**: Chromium 是内存大户，无限制时可能 OOM 影响全栈稳定性。
- **改进建议**: 为所有服务设置 CPU/内存限制和预留。

#### P2 - NATS 使用 latest 标签且无健康检查

- **位置**: `docker-compose.yml` 第 41、47 行
- **现象**: `image: nats:latest` 使用不固定标签；NATS 服务无 healthcheck 配置。
- **根因分析**: 未固定版本标签，未添加健康检查。
- **影响**: latest 标签导致构建不可重现；NATS 无健康检查导致 backend 依赖检查仅检查进程启动。
- **改进建议**: 固定 NATS 版本标签（如 `nats:2.10`）；添加 NATS healthcheck。

#### P3 - docker-compose version 字段已废弃

- **位置**: `docker-compose.yml` 第 4 行
- **现象**: `version: "3.9"` 在新版 Docker Compose 中已废弃，产生警告。
- **改进建议**: 移除 `version` 字段。

### 6.2 外部服务集成

#### P0 - 6.2.1 PoC 沙箱 allowed_hosts 未实际执行网络隔离

- **位置**: `poc-sandbox/sandbox_worker.py` 第 26-30、110-111 行
- **现象**: `allowed_hosts` 参数被传入 `restricted_globals` 作为变量，但代码中没有任何逻辑实际限制网络请求的目标主机。`ALLOWED_IMPORTS` 包含 `socket`、`http`、`urllib`，可发起任意网络连接。
- **根因分析**: 网络隔离仅在代码层设置变量，无实际过滤逻辑。后端报告 4.3.1 节指出沙箱执行器无真正隔离。
- **代码证据**:
  ```python
  restricted_globals["ALLOWED_HOSTS"] = req.allowed_hosts or [req.target_host]  # 仅设置为变量
  ALLOWED_IMPORTS = ["socket", "http", "urllib", ...]  # 可用于任意网络访问
  ```
- **影响**: PoC 代码可扫描内网、访问数据库、攻击其他容器——沙箱网络隔离形同虚设。README 声称"仅允许访问指定目标主机"与实际实现不符。
- **改进建议**: 在容器层使用网络策略强制限制出站流量；或移除 `socket`/`http`/`urllib` 从白名单。

#### P0 - 6.2.2 mitmproxy addon 静默吞没所有异常

- **位置**: `mitmproxy/addon.py` 第 39-40 行
- **现象**: `FlowPublisher.response()` 方法中 `except Exception: pass` 完全静默地吞没所有异常。
- **根因分析**: 异常处理过于宽泛。后端报告 4.2.5 节指出 emit() 静默吞没异常，与此形成系统性模式。
- **代码证据**: `except Exception: pass`
- **影响**: Redis 连接断开、JSON 序列化失败等问题完全不可见；流量捕获静默失效后，Agent 无法获取浏览器流量分析数据。
- **改进建议**: 添加 logging 并记录异常；考虑重试机制或断路器。

#### P1 - Sidecar 服务无认证

- **位置**: `crawlergo/api_wrapper.py`、`poc-sandbox/sandbox_worker.py`
- **现象**: crawlergo 的 `/crawl` 和 poc-sandbox 的 `/execute` 端点完全无认证。结合端口暴露到宿主机，任何人可直接调用。
- **根因分析**: 内部服务未实现认证。
- **影响**: 远程代码执行（poc-sandbox）、SSRF 攻击（crawlergo 可被指向任意 URL）。
- **改进建议**: 添加共享密钥认证；或确保端口不暴露到宿主机。

#### P1 - 客户端无重试和断路器

- **位置**: `backend/app/core/crawlergo_client.py`、`backend/app/core/poc_sandbox_client.py`
- **现象**: 两个客户端的 HTTP 调用无重试逻辑、无断路器模式，失败即返回异常。
- **根因分析**: 未实现容错机制。
- **影响**: Sidecar 服务短暂不可用导致整个 Agent 任务失败，无法自动恢复。
- **改进建议**: 使用 `httpx` 的重试传输或 `tenacity` 库实现指数退避重试。

#### P1 - crawlergo 客户端与服务端超时不匹配

- **位置**: `backend/app/core/crawlergo_client.py` 第 23-24 行 vs `crawlergo/api_wrapper.py` 第 46 行
- **现象**: 客户端默认超时 130 秒，服务端 subprocess 超时 180 秒。客户端可能在服务端仍在爬取时超时断开。
- **根因分析**: 超时配置不协调。
- **影响**: 长时间爬取任务在客户端超时后，服务端进程仍继续运行消耗资源。
- **改进建议**: 统一超时配置，客户端超时应大于服务端超时。

#### P2 - mitmproxy SSL 验证禁用

- **位置**: `mitmproxy/Dockerfile` 第 12 行
- **现象**: `--set ssl_insecure=true` 禁用了 SSL 证书验证。后端报告 4.3.3 节指出所有 HTTP 工具禁用 SSL 验证。
- **改进建议**: 在非测试场景中应启用 SSL 验证。

#### P2 - mitmproxy 无健康检查在 Dockerfile 中

- **位置**: `mitmproxy/Dockerfile`
- **现象**: mitmproxy 的 Dockerfile 中没有 HEALTHCHECK 指令，健康检查仅在 docker-compose.yml 中定义。
- **改进建议**: 在 Dockerfile 中添加 HEALTHCHECK 指令。

### 6.3 数据库与持久化

#### P0 - 6.3.1 init_db.sql 与模型/迁移完全不一致且从未被使用

- **位置**: `scripts/init_db.sql` vs `backend/alembic/versions/001_initial_schema.py` vs `backend/app/models/`
- **现象**: init_db.sql 的表结构与 Alembic 迁移和 ORM 模型存在大量不一致，且该脚本从未被挂载到 PostgreSQL 容器。
- **根因分析**: 三个数据源独立维护，未保持一致。后端报告 4.5.1 节指出迁移与模型不一致。
- **关键差异**: users 表列名不同（hashed_password vs password_hash）；tasks 表字段不同（target_url vs target_type）；events 表列名不同（event_type vs type）；findings 表默认值不同（unconfirmed vs draft）；llm_providers 表在 init_db.sql 中完全缺失。
- **影响**: 如果有用户按照 init_db.sql 初始化数据库，应用将完全无法工作。
- **改进建议**: 删除 init_db.sql 或使其与 Alembic 迁移保持一致；明确数据库初始化应通过 `alembic upgrade head` 完成。

#### P1 - DEBUG 模式绕过 Alembic 迁移

- **位置**: `backend/app/main.py` 第 67-73 行
- **现象**: 当 `DEBUG=true` 时，应用启动直接调用 `Base.metadata.create_all()` 创建表，完全绕过 Alembic 迁移系统。docker-compose.yml 中 `DEBUG: "true"` 是默认值。
- **根因分析**: 开发便利性设计。后端报告 4.1.4 节同样指出此问题。
- **影响**: 迁移管理与生产部署脱节。
- **改进建议**: 移除 DEBUG 模式下的自动建表逻辑，统一使用 Alembic 迁移。

#### P1 - LLMProvider 表未在 Alembic 迁移中创建

- **位置**: `backend/app/models/llm_provider.py` vs `backend/alembic/versions/001_initial_schema.py`
- **现象**: `LLMProvider` 模型已定义，但 001 迁移脚本中未创建 `llm_providers` 表。
- **根因分析**: 迁移脚本遗漏。后端报告 4.5.1 节同样指出此问题。
- **影响**: 非 DEBUG 模式下 LLM 供应商配置功能将因表不存在而报错。
- **改进建议**: 创建新的 Alembic 迁移脚本添加 `llm_providers` 表。

#### P2 - 无数据库备份策略

- **位置**: 全项目
- **现象**: 无任何数据库备份脚本、定时任务或文档说明。
- **改进建议**: 添加 pg_dump 定时备份脚本；考虑 WAL 归档配置。

#### P3 - 数据库连接池参数硬编码

- **位置**: `backend/app/core/database.py` 第 21-27 行
- **现象**: `pool_size=20`、`max_overflow=10` 硬编码，无法通过环境变量调整。
- **改进建议**: 将连接池参数移至 Settings 配置类。

### 6.4 配置管理

#### P0 - 6.4.1 加密密钥派生自 JWT_SECRET

- **位置**: `backend/app/core/encryption.py` 第 16-21 行
- **现象**: API Key 加密使用的 Fernet 密钥直接从 `JWT_SECRET` 的 SHA-256 派生。后端报告 4.8.1 节同样指出此问题。
- **影响**: 如果 JWT_SECRET 使用默认值，所有加密的 API Key 可被轻易解密；密钥轮换会导致已加密数据无法解密。
- **改进建议**: 使用独立的加密密钥（如 `ENCRYPTION_KEY` 环境变量），与 JWT_SECRET 分离。

#### P1 - .env.example 不完整

- **位置**: `.env.example`
- **现象**: 缺少多个重要环境变量：`MITMPROXY_URL`、`CRAWLERGO_URL`、`POC_SANDBOX_URL` 等。仅包含 8 个变量，而 config.py 定义了 15+ 个配置项。
- **影响**: 用户不知道需要配置哪些变量；缺少关键配置可能导致功能异常但不报错。
- **改进建议**: 补全所有环境变量到 .env.example，并添加说明注释。

#### P1 - CORS 配置允许所有来源

- **位置**: `backend/app/main.py` 第 173-179 行
- **现象**: `allow_origins=["*"]` 配合 `allow_credentials=True` 是已知的安全反模式。后端报告 4.1.3 节同样指出此问题。
- **改进建议**: 根据 DEBUG 配置或独立的环境变量控制 CORS 策略。

#### P2 - 无密钥轮换机制

- **位置**: 全项目
- **现象**: 无 JWT_SECRET 轮换机制；无数据库密码轮换流程；加密密钥与 JWT_SECRET 绑定使轮换更复杂。
- **改进建议**: 设计密钥轮换流程；考虑使用密钥管理服务（如 Vault）。

### 6.5 工程化与构建

#### P1 - 无 CI/CD 流水线

- **位置**: 全项目
- **现象**: 无 GitHub Actions、GitLab CI、Jenkinsfile 或任何 CI/CD 配置文件。
- **影响**: 代码变更无自动化测试/构建/安全扫描保障；部署完全依赖手动操作。
- **改进建议**: 添加 CI 流水线，至少包含：lint 检查、单元测试、Docker 镜像构建、依赖安全扫描。

#### P2 - Makefile 功能有限

- **位置**: `Makefile`
- **现象**: 仅 37 行，缺少常用命令。
- **改进建议**: 添加 `logs`、`ps`、`migrate-create`、`frontend-dev`、`clean` 等目标。

#### P2 - 无 pre-commit 钩子

- **位置**: 全项目
- **现象**: 无 `.pre-commit-config.yaml`，代码质量检查完全依赖开发者手动执行。
- **改进建议**: 添加 pre-commit 配置，集成 ruff、eslint 等。

#### P3 - npm 依赖使用 caret 范围

- **位置**: `frontend/package.json`
- **现象**: 所有依赖使用 `^` 范围，`npm install` 可能安装不同的次版本。
- **改进建议**: CI 中添加 `npm ci` 验证。

### 6.6 测试策略

#### P0 - 6.6.1 集成测试和单元测试目录为空

- **位置**: `backend/tests/integration/`、`backend/tests/unit/`
- **现象**: 两个目录完全为空。后端报告 4.9.1 节同样指出测试覆盖率极低。
- **改进建议**: 将现有测试移入 `unit/`；为 API 端点、服务层、外部服务集成编写真正的集成测试。

#### P1 - 测试覆盖率严重不足

- **位置**: `backend/tests/`
- **现象**: 仅 3 个测试文件，覆盖范围极窄。未覆盖的关键路径包括所有 API 端点、服务层、外部服务客户端、核心组件、所有安全工具、LATS 搜索引擎。
- **影响**: 核心业务逻辑无测试保障。详见第 7 节共性问题。
- **改进建议**: 优先为 API 端点、服务层、安全工具编写测试。

#### P1 - 测试使用 SQLite 而非 PostgreSQL

- **位置**: `backend/tests/conftest.py` 第 20 行
- **现象**: 测试使用 SQLite 内存数据库，但生产使用 PostgreSQL。JSONB、ARRAY、UUID 等特有类型行为可能不同。
- **影响**: 测试通过但生产失败的假阴性。
- **改进建议**: 集成测试使用 testcontainers 启动真实 PostgreSQL。

#### P1 - conftest.py 未正确覆盖数据库依赖

- **位置**: `backend/tests/conftest.py` 第 61-68 行
- **现象**: 测试客户端 fixture 未通过 `app.dependency_overrides` 替换 `get_db` 依赖。后端报告 4.9.5 节同样指出此问题。
- **改进建议**: 使用 `app.dependency_overrides[get_db] = ...` 注入测试数据库会话。

### 6.7 可观测性

#### P1 - 日志系统不一致

- **位置**: 全项目
- **现象**: 代码库中混用 `structlog` 和标准 `logging` 模块。structlog 仅在 4 个文件中使用，未配置处理器。后端报告 4.10.4 节同样指出此问题。
- **改进建议**: 统一使用 structlog 并配置 JSON 格式处理器。

#### P1 - 无指标收集系统

- **位置**: 全项目
- **现象**: 无 Prometheus 指标暴露、无自定义指标端点、无 Grafana 仪表板。
- **影响**: 系统运行状况不可见；无法监控 LLM API 费用。对于 AI Agent 系统尤其需要 Token 消耗、任务执行时间等指标。
- **改进建议**: 集成 prometheus-fastapi-instrumentator；添加自定义业务指标。

#### P1 - 无分布式追踪

- **位置**: 全项目
- **现象**: 无 OpenTelemetry、Jaeger 或任何分布式追踪集成。
- **影响**: 无法诊断跨服务调用的延迟问题；Agent 执行链路不可观测。
- **改进建议**: 集成 OpenTelemetry SDK，追踪 HTTP 请求、数据库查询、NATS 消息。

#### P2 - 无告警机制

- **位置**: 全项目
- **现象**: 无告警规则配置。系统降级运行时仅记录 warning 日志，无主动通知。
- **影响**: 系统异常无法及时发现。运行实例中"系统异常"提示正是此问题的体现。
- **改进建议**: 集成 Alertmanager 或类似工具；关键服务不可用时发送告警。

#### P2 - 健康检查不完整

- **位置**: `backend/app/api/v1/system.py` 第 23-65 行
- **现象**: 健康检查仅检测数据库和 Redis，未检测 NATS、mitmproxy、crawlergo、poc-sandbox 的连通性。
- **影响**: 部分依赖服务不可用时健康检查仍返回 healthy。运行实例中"系统异常"提示可能与此有关。
- **改进建议**: 添加对所有依赖服务的健康检测。

### 6.8 文档与设计

#### P1 - README 使用说明与实现不一致

- **位置**: `README.md` 第 139 行 vs `backend/app/main.py` 第 33-52 行
- **现象**: README 说"访问前端并注册账户"，但代码在 DEBUG 模式下自动创建 admin/argus123 账号。
- **改进建议**: 更新 README 说明默认管理员账号；或实现注册功能。

#### P2 - init_db.sql 文档说明与实际不符

- **位置**: `scripts/init_db.sql` 第 2-3 行
- **现象**: 注释说"在 PostgreSQL 容器首次启动时执行"，但该脚本从未被挂载到 PostgreSQL 的 `/docker-entrypoint-initdb.d/` 目录。
- **改进建议**: 删除此脚本或正确挂载。

#### P2 - 设计文档可能已过时

- **位置**: `ANALYSIS.md`、`DESIGN_RECOMMENDATION.md`、`DESIGN_SEARCH_ARCHITECTURE.md`、`design.md`
- **现象**: 存在多个设计文档，内容有重叠，引用的代码行数可能与当前代码不符。
- **改进建议**: 定期审查文档与代码的一致性；合并重叠文档。

### 6.9 安全合规

#### P0 - 6.9.1 安全平台自身安全 posture 极弱

- **位置**: 全项目
- **现象**: 作为安全测试平台，自身安全防护严重不足，汇总如下：

  | 安全维度 | 当前状态 | 风险 | 关联章节 |
  |---|---|---|---|
  | 容器权限 | 3/5 服务以 root 运行 | 容器逃逸即 root 权限 | 6.1.1 |
  | 网络隔离 | 无自定义网络 | 沙箱逃逸可访问数据库 | 6.1.3 |
  | 端口暴露 | 全部端口映射到宿主机 | 外部可直接访问所有服务 | 6.1.2 |
  | 认证 | Sidecar 服务无认证 | RCE/SSRF 风险 | 6.2.3 |
  | 密钥管理 | 硬编码默认值 | 使用默认配置即被攻破 | 6.1.5 |
  | CORS | `allow_origins=["*"]` | CSRF 风险 | 6.4.3 |
  | 审计日志 | 无 | 操作不可追溯 | 6.9.2 |
  | 速率限制 | 无 | 暴力破解/DoS | 4.1.5 |
  | SSL 验证 | mitmproxy 禁用 | MITM 风险 | 6.2.6 |

- **改进建议**: 逐一解决上述安全问题，详见第 8 节改进路线图。

#### P1 - 无审计日志

- **位置**: 全项目
- **现象**: 无用户操作审计日志。谁在何时创建/删除了任务、查看/修改了漏洞发现、更改了系统设置——这些操作完全不可追溯。
- **影响**: 安全测试平台缺乏审计能力是不可接受的。
- **改进建议**: 实现审计日志中间件，记录所有写操作。

#### P1 - 无 API 速率限制

- **位置**: `backend/app/main.py`
- **现象**: 无 API 速率限制中间件。后端报告 4.1.5 节同样指出此问题。
- **改进建议**: 集成 `slowapi` 或类似库实现速率限制。

#### P1 - PoC 沙箱逃逸风险

- **位置**: `poc-sandbox/sandbox_worker.py`
- **现象**: RestrictedPython 是已知的不可靠沙箱方案，`_getitem_` 和 `_write_` guard 使用了不安全的 lambda 实现。
- **代码证据**:
  ```python
  restricted_globals["_getitem_"] = lambda obj, key: obj[key]  # 允许任意下标访问
  restricted_globals["_write_"] = lambda obj: obj  # 无任何写入限制
  ```
- **影响**: PoC 代码可能通过 RestrictedPython 绕过技术获取完整 Python 权限。
- **改进建议**: 使用 gVisor 或 Kata Containers 提供更强的隔离；移除网络模块从白名单；使用更严格的 guard 函数。

#### P2 - JWT Token 有效期过长且无刷新机制

- **位置**: `backend/app/config.py` 第 36 行
- **现象**: JWT Token 默认有效期 24 小时（1440 分钟），无 refresh token 机制，无 token 撤销机制。
- **改进建议**: 缩短 access token 有效期（如 30 分钟），实现 refresh token 机制。

### 6.10 可扩展性与高可用

#### P0 - 6.10.1 不支持水平扩展

- **位置**: 全项目
- **现象**: 多处架构设计阻碍水平扩展：WebSocket 连接存储在内存中（event_bus.py:29）；Playwright 浏览器是进程内单例（playwright_manager.py:15）；ProxyFlowConsumer 使用内存 deque（proxy_client.py:24）；container_name 硬编码阻止 `docker compose up --scale`。
- **根因分析**: 架构设计未考虑多实例场景。后端报告 4.8.7 节指出全局可变状态过多。
- **影响**: 后端只能单实例运行，无法通过增加实例提升吞吐量或实现高可用。
- **改进建议**: WebSocket 使用 Redis Pub/Sub 跨实例广播；Playwright 提取为独立浏览器池服务；移除 container_name。

#### P1 - 多个单点故障

- **位置**: `docker-compose.yml`
- **现象**: 所有服务都是单实例，任何服务崩溃都会导致系统不可用。
- **改进建议**: 至少为 PostgreSQL 配置流复制；Redis 配置哨兵或集群模式；backend 支持多实例。

#### P2 - 降级运行缺乏恢复机制

- **位置**: `backend/app/main.py` 第 76-97 行
- **现象**: Redis 和 NATS 连接失败时系统降级运行，但没有定期重连机制。后端报告 4.8.5 节同样指出此问题。
- **改进建议**: 实现连接健康检查和自动重连机制。

#### P2 - 无限流降级策略

- **位置**: 全项目
- **现象**: 当 LLM API 调用达到速率限制或预算耗尽时，无明确的降级策略。
- **改进建议**: 实现令牌桶限流；预算耗尽时自动降级到更便宜模型或暂停任务排队。

---

## 7. 跨层面共性问题

通过对后端、前端、基础设施三个层面的分析，可以归纳出 5 个跨层面的共性问题主题。这些问题不是孤立的单点缺陷，而是系统性的架构模式问题，需要在整体层面进行治理。

### 7.1 全局可变状态泛滥

**问题描述**: 从后端到前端，全局可变状态的使用泛滥成灾，导致并发安全问题、测试困难、状态污染。

**多处来源**:
- 后端 LLM 客户端全局单例（llm.py:178）- `_current_task_id` 和 `token_budget` 作为实例属性，多任务并发时互相覆盖
- 后端 LATS 子系统三个全局单例（lats/graph.py:37-60）- `_llm_client`、`_executor_pool`、`_expansion_engine` 跨任务共享
- 后端 Core 层 6 处全局变量（redis.py、nats_client.py、playwright_manager.py、proxy_client.py、event_bus.py、agent_runner.py）
- 后端 AgentRunner 三个共享字典（agent_runner.py:49-54）- 无锁保护
- 前端 API 客户端模块级直接调用 Zustand store（api.ts:28）- 阻碍 SSR 迁移
- 前端 Zustand store 使用模块级 persist（stores/auth.ts:26-44）- token 暴露在 localStorage

**影响**:
- 运行实例中 LLM 单例并发污染是数据不一致的架构根源之一
- 测试困难 - 全局状态难以 mock
- 不支持水平扩展 - 进程内状态无法跨实例共享（基础设施 6.10.1 节）
- 并发安全无保障 - `await` 点之间的逻辑竞争

**改进方向**: 引入依赖注入容器管理对象生命周期，将全局单例改为按任务/按请求创建的实例。后端参考 FastAPI 的 `Depends` 机制，前端通过 React Context 传递状态。

### 7.2 安全边界全面缺失

**问题描述**: 作为安全测试平台，自身的安全防护严重不足，安全边界在容器层、网络层、应用层、前端层全面缺失。

**多处来源**:
- 容器层: 3/5 服务以 root 运行（基础设施 6.1.1 节）
- 网络层: 无网络隔离，所有端口暴露到宿主机（基础设施 6.1.2、6.1.3 节）
- 沙箱层: PoC 沙箱 allowed_hosts 未实际执行网络隔离，RestrictedPython guard 不安全（基础设施 6.2.1、6.9.4 节）
- 应用层: 多个 API 端点无认证（后端 4.4.1 节），无 IDOR 防护（后端 4.4.2 节），WebSocket 认证可选（后端 4.4.3 节），Sidecar 服务无认证（基础设施 6.2.3 节）
- 前端层: JWT Token 存 localStorage（前端 5.4.1 节），WebSocket URL 传 token（前端 5.4.2 节）
- 密钥层: JWT 密钥硬编码默认值（后端 4.1.1 节），加密密钥从 JWT_SECRET 派生（后端 4.8.1 节），docker-compose 硬编码密钥（基础设施 6.1.5 节）

**影响**:
- 使用默认配置部署即等于开放系统
- 攻击者可从多个层面突破：容器逃逸、网络嗅探、API 越权、token 窃取
- 安全平台自身被攻破后可能成为攻击内网的跳板

**改进方向**: 实施纵深防御策略，在每一层建立安全边界。详见第 8 节改进路线图中的 P0 和 P1 任务。

### 7.3 错误处理策略不统一

**问题描述**: 异常处理模式不一致，从后端到前端到外部服务，错误被静默吞没的情况普遍存在，导致故障不可见、调试困难。

**多处来源**:
- 后端 emit() 静默吞没所有异常（emit.py:36-37）- 仅记录 warning 不向上传播，是运行实例中漏洞数据不一致的直接根因
- 后端多个工具的 `except Exception` 过于宽泛
- 前端 WebSocket 消息解析失败静默忽略（websocket.ts:57-68）- catch 块为空
- 前端无全局错误通知系统（全项目）- mutation 错误只在局部处理或完全不处理
- 基础设施 mitmproxy addon 静默吞没所有异常（addon.py:39-40）- `except Exception: pass`
- 前端 WebSocket 重连失败后无用户反馈（websocket.ts:122-126）- 静默放弃

**影响**:
- 运行实例中漏洞数据不一致 - emit() 静默吞没异常导致 finding 未落库但事件已记录
- 运行实例中"系统异常"提示无法查看详情 - 前端无全局通知系统
- 故障不可见 - 数据库连接断开、JSON 序列化失败等问题完全不可见
- 调试困难 - 后端和前端双重静默

**改进方向**: 统一错误处理策略，区分可恢复错误和不可恢复错误。对于关键操作（如 finding 落库），确保错误不被静默吞没。前端实现全局 toast/notification 系统展示错误。

### 7.4 测试形同虚设

**问题描述**: 现有测试与实际代码不匹配，大量断言错误，关键路径完全无测试覆盖。测试给人的虚假信心比没有测试更危险。

**多处来源**:
- 后端 test_agents.py 多个断言错误（第 72、115、119 行）- 断言值与实际返回值不匹配
- 后端 test_schemas.py 与实际 Schema 完全不匹配（target_url vs target_config, UNCONFIRMED vs draft）
- 后端 test_tools.py 断言错误（第 47-49 行）- 断言返回 None 但实际抛 KeyError
- 后端 conftest.py 未覆盖依赖注入（第 61-68 行）- 测试客户端未替换 get_db
- 后端 tests/unit/ 和 tests/integration/ 目录为空
- 后端测试使用 SQLite 而非 PostgreSQL - JSONB、ARRAY 行为不同
- 前端无任何测试文件
- 全项目无 CI/CD 流水线验证测试

**影响**:
- 运行实例中的崩溃（'str' object has no attribute 'get'）本应被测试发现
- 重构和修改风险极高 - 无测试保障
- 测试通过但生产失败的假阴性

**改进方向**: 修复所有现有测试使其与代码一致，为核心路径（API 端点、服务层、安全工具）编写真正的集成测试，引入 CI/CD 强制测试通过。

### 7.5 数据一致性故障

**问题描述**: 从数据库迁移到前后端类型定义到运行时数据流，数据一致性问题贯穿全栈，最终在运行实例中表现为漏洞数据丢失。

**多处来源**:
- 数据库层: init_db.sql 与模型/迁移完全不一致（基础设施 6.3.1 节）- 三个数据源独立维护
- 数据库层: 迁移与模型不一致（后端 4.5.1 节）- llm_providers 表缺失、reports 表字段不一致
- 数据库层: 多个外键缺失（后端 4.5.2 节）- Task.created_by、Finding.report_id、Report.created_by
- 类型层: 前端 AgentEvent.data 为 Record<string,any>（前端 5.7.1 节）- 与后端 schema 严重脱节
- 类型层: 前端 TaskStatus 包含 "done" 但多处代码未处理（前端 5.7.2 节）
- 类型层: 前端 ApiResponse 接口定义但未使用（前端 5.7.3 节）- success 字段与后端 code 字段不匹配
- 运行时层: FindingService 无去重逻辑（后端 4.7.4 节）- 多轮迭代重复记录
- 运行时层: emit() 静默吞没异常（后端 4.2.5 节）- finding 事件已记录但 finding 数据未落库
- 运行时层: LLM 单例并发污染（后端 4.2.1 节）- token 消耗错误计入其他任务

**影响**:
- 运行实例中统计 Tab 显示 2 个漏洞但概览和 Findings 页面显示 0 个 - 直接的数据丢失
- 生产环境数据库缺少必要的表和列，导致应用崩溃
- 前后端类型脱节，重构成本高

**改进方向**: 统一数据库初始化为 Alembic 迁移，修复迁移与模型不一致，前后端共享类型定义（可使用 OpenAPI 自动生成前端类型），确保 finding 落库与事件发射在同一事务中，FindingService 添加去重逻辑。

---

## 8. 改进路线图

本节按 P0（立即修复）、P1（短期改进）、P2（中期改进）、P3（长期演进）四级给出分阶段实施计划。

### 8.1 P0 - 立即修复（1-2 周）

P0 级别问题是阻塞性的安全漏洞和功能性故障，必须在 1-2 周内修复。

| 序号 | 任务 | 预估时间 | 负责模块 | 关联章节 |
|------|------|----------|----------|----------|
| 1 | JWT 密钥启动校验，移除默认值 | 0.5 天 | 后端 config.py | 4.1.1 |
| 2 | 为所有无认证 API 端点添加 `Depends(get_current_user)` | 1 天 | 后端 api/v1/ | 4.4.1 |
| 3 | LLM 客户端改为每任务独立实例，隔离 task_id 和 token_budget | 2 天 | 后端 agents/llm.py, agent_runner.py | 4.2.1 |
| 4 | 修复 Alembic 迁移与模型不一致，添加 llm_providers 表 | 1 天 | 后端 alembic/ | 4.5.1, 6.3.3 |
| 5 | JWT Token 存储迁移到 httpOnly cookie | 2 天 | 前后端 | 5.4.1 |
| 6 | 修复 wsRef 未赋值，使 InterventionPanel 的 wsSend 生效 | 0.5 天 | 前端 tasks/[id]/page.tsx | 5.5.3 |
| 7 | 修复漏洞数据落库：finding 落库与事件发射在同一事务中，emit 不静默吞没 finding 类异常 | 1 天 | 后端 emit.py, finding_service.py | 3.1, 4.2.5, 4.7.4 |
| 8 | 修复任务执行崩溃：定位并对 str 类型值添加类型检查和 json.loads 解析 | 1 天 | 后端 routing.py, state.py | 3.2 |
| 9 | 任务异常终止时同步更新所有 Agent 状态 | 0.5 天 | 后端 agent_runner.py | 3.3, 4.7.2 |
| 10 | 所有容器创建非 root 用户 | 0.5 天 | 所有 Dockerfile | 6.1.1 |
| 11 | 关闭非必要端口暴露，仅暴露 frontend(3000) 和 backend(8000) | 0.5 天 | docker-compose.yml | 6.1.2 |
| 12 | 移除 docker-compose 中硬编码密钥和 DEBUG=true 默认值 | 0.5 天 | docker-compose.yml | 6.1.5 |
| 13 | 删除或修复 init_db.sql，统一数据库初始化为 Alembic 迁移 | 0.5 天 | scripts/ | 6.3.1 |

**P0 总预估时间**: 约 12 天（可并行，实际 1-2 周）

### 8.2 P1 - 短期改进（2-4 周）

P1 级别问题是重要的安全和健壮性改进，应在 2-4 周内完成。

| 序号 | 任务 | 预估时间 | 负责模块 | 关联章节 |
|------|------|----------|----------|----------|
| 1 | 实现 IDOR 防护，service 层添加所有权检查 | 2 天 | 后端 services/ | 4.4.2 |
| 2 | 集成 slowapi 速率限制中间件，至少覆盖认证端点 | 1 天 | 后端 main.py | 4.1.5 |
| 3 | Dockerfile 安全加固：非 root 用户、移除运行时安全工具安装 | 1 天 | 所有 Dockerfile | 4.10.2, 4.10.3 |
| 4 | OverviewPanel 事件流虚拟化（@tanstack/react-virtual） | 2 天 | 前端 OverviewPanel.tsx | 5.6.3 |
| 5 | 事件列表设置最大长度（1000 条），超出丢弃最旧事件 | 0.5 天 | 前端 use-events.ts | 5.3.2 |
| 6 | 添加全局错误通知系统（react-hot-toast） | 1 天 | 前端全局 | 5.9.1, 3.4 |
| 7 | PoC 沙箱真正隔离化：移除 socket/http/urllib 白名单，容器层强制网络策略 | 2 天 | poc-sandbox/ | 6.2.1, 6.9.4 |
| 8 | Docker 网络隔离：划分前端/后端/数据层/沙箱网络 | 1 天 | docker-compose.yml | 6.1.3 |
| 9 | WebSocket 认证改为必须，移除可选逻辑 | 0.5 天 | 后端 ws.py | 4.4.3 |
| 10 | 图执行添加全局超时（asyncio.wait_for, timeout=3600） | 0.5 天 | 后端 agent_runner.py | 4.2.2, 4.7.1 |
| 11 | Sidecar 服务添加共享密钥认证 | 1 天 | crawlergo/, poc-sandbox/ | 6.2.3 |
| 12 | 添加 .dockerignore 文件 | 0.5 天 | 所有含 Dockerfile 的目录 | 6.1.4 |
| 13 | 报告页面根据任务状态区分提示文案 | 0.5 天 | 前端报告组件 | 3.5 |
| 14 | 添加全局错误边界 error.tsx 和 global-error.tsx | 0.5 天 | 前端 app/ | 5.2.2 |
| 15 | 健康检查添加对所有依赖服务的检测 | 1 天 | 后端 system.py | 6.7.5 |

**P1 总预估时间**: 约 15 天（可并行，实际 2-4 周）

### 8.3 P2 - 中期改进（1-2 月）

P2 级别问题是架构优化和工程化提升，需要 1-2 个月完成。

| 序号 | 任务 | 预估时间 | 负责模块 | 关联章节 |
|------|------|----------|----------|----------|
| 1 | 全局状态重构为依赖注入容器 | 2 周 | 后端 core/, agents/ | 4.2.4, 4.8.7, 7.1 |
| 2 | 测试体系重建：修复现有测试，为 API/服务层/工具编写集成测试 | 2 周 | 后端 tests/ | 4.9, 6.6, 7.4 |
| 3 | 日志/监控/追踪体系建设：统一 structlog + Prometheus + OpenTelemetry | 1 周 | 全项目 | 6.7.1, 6.7.2, 6.7.3 |
| 4 | 代码分割与 SSR 优化：页面壳层改服务端组件，execution 组件动态导入 | 1 周 | 前端全局 | 5.2.1, 5.8.1 |
| 5 | 依赖版本锁定：后端 pip-compile 锁文件，前端 npm ci + CI 验证 | 2 天 | 后端 pyproject.toml, 前端 package.json | 4.10.1, 5.10.1 |
| 6 | 前后端类型同步：OpenAPI 自动生成前端类型，消除 any 滥用 | 1 周 | 前端 types/, 后端 schemas/ | 5.7.1, 7.5 |
| 7 | FindingService 去重逻辑 + 数据一致性修复 | 2 天 | 后端 finding_service.py | 4.7.4, 7.5 |
| 8 | 软删除机制实现 | 3 天 | 后端 models/ | 4.5.4 |
| 9 | CI/CD 流水线搭建（lint + test + build + 安全扫描） | 3 天 | 全项目 | 6.5.1 |
| 10 | 安全响应头配置 + CSP | 1 天 | 前端 next.config.ts | 5.1.2 |
| 11 | API 客户端 token 注入重构，移除模块级 store 访问 | 2 天 | 前端 api.ts | 5.3.1 |
| 12 | 认证守卫迁移到 middleware.ts 服务端检查 | 1 天 | 前端 middleware.ts | 5.2.4, 5.4.3 |

**P2 总预估时间**: 约 6-8 周

### 8.4 P3 - 长期演进 （2+ 月）

P3 级别问题是长期演进目标，提升系统的可扩展性、高可用性和国际化能力。

| 序号 | 任务 | 预估时间 | 负责模块 | 关联章节 |
|------|------|----------|----------|----------|
| 1 | 水平扩展能力：WebSocket Redis Pub/Sub，Playwright 浏览器池服务，移除 container_name | 3 周 | 后端 core/, docker-compose.yml | 6.10.1 |
| 2 | 高可用部署：PostgreSQL 流复制，Redis 哨兵，backend 多实例 | 2 周 | docker-compose.yml | 6.10.2 |
| 3 | 密钥轮换机制 + 密钥管理服务（Vault） | 1 周 | 后端 config/, core/encryption.py | 6.4.4 |
| 4 | 国际化支持（next-intl） | 2 周 | 前端全局 | 5.9.6 |
| 5 | 审计日志系统 | 1 周 | 后端中间件 | 6.9.2 |
| 6 | 数据库备份策略（pg_dump + WAL 归档） | 3 天 | scripts/ | 6.3.4 |
| 7 | Token refresh 机制 | 3 天 | 后端 auth/, 前端 | 6.9.5 |
| 8 | 沙箱升级为 gVisor/Kata Containers | 1 周 | poc-sandbox/ | 6.9.4 |
| 9 | 全局状态重构完成后的并发安全测试 | 1 周 | 后端 tests/ | 4.7.2 |

**P3 总预估时间**: 约 10-12 周

---

## 9. 附录

### 9.1 问题统计汇总表

以下矩阵按问题等级（P0/P1/P2/P3）和模块维度汇总所有发现的问题数量。

| 模块 | P0 | P1 | P2 | P3 | 合计 |
|------|----|----|----|----|------|
| **后端 - 整体架构与入口** | 2 | 2 | 2 | 0 | 6 |
| **后端 - Agent 核心引擎** | 1 | 2 | 3 | 0 | 6 |
| **后端 - 工具集** | 1 | 4 | 3 | 1 | 9 |
| **后端 - API 层** | 1 | 2 | 2 | 0 | 5 |
| **后端 - 数据模型与数据库** | 1 | 1 | 2 | 1 | 5 |
| **后端 - Schema 层** | 0 | 0 | 3 | 0 | 3 |
| **后端 - Services 层** | 0 | 2 | 3 | 0 | 5 |
| **后端 - Core 基础设施** | 1 | 1 | 5 | 0 | 7 |
| **后端 - 测试** | 1 | 2 | 2 | 0 | 5 |
| **后端 - 配置与依赖** | 0 | 2 | 2 | 1 | 5 |
| **前端 - 整体架构与配置** | 0 | 2 | 2 | 1 | 5 |
| **前端 - 应用入口与路由** | 0 | 2 | 2 | 1 | 5 |
| **前端 - 状态管理与数据获取** | 1 | 1 | 3 | 1 | 6 |
| **前端 - 认证与安全** | 2 | 2 | 2 | 0 | 6 |
| **前端 - 组件设计** | 0 | 3 | 3 | 2 | 8 |
| **前端 - 实时通信** | 1 | 2 | 2 | 1 | 6 |
| **前端 - 类型定义** | 0 | 1 | 2 | 1 | 4 |
| **前端 - 性能问题** | 0 | 2 | 2 | 0 | 4 |
| **前端 - 用户体验** | 0 | 2 | 3 | 1 | 6 |
| **前端 - 构建与部署** | 0 | 1 | 3 | 1 | 5 |
| **基础设施 - 容器化与编排** | 2 | 3 | 2 | 1 | 8 |
| **基础设施 - 外部服务集成** | 2 | 3 | 2 | 0 | 7 |
| **基础设施 - 数据库与持久化** | 1 | 2 | 1 | 1 | 5 |
| **基础设施 - 配置管理** | 1 | 2 | 1 | 0 | 4 |
| **基础设施 - 工程化与构建** | 0 | 1 | 2 | 1 | 4 |
| **基础设施 - 测试策略** | 1 | 3 | 0 | 0 | 4 |
| **基础设施 - 可观测性** | 0 | 3 | 2 | 0 | 5 |
| **基础设施 - 文档与设计** | 0 | 1 | 2 | 0 | 3 |
| **基础设施 - 安全合规** | 1 | 3 | 1 | 0 | 5 |
| **基础设施 - 可扩展性与高可用** | 1 | 1 | 2 | 0 | 4 |
| **运行实例验证** | 3 | 4 | 1 | 0 | 8 |
| **合计** | **24** | **62** | **67** | **15** | **168** |

注：部分问题在多个报告中重复出现（如 JWT 密钥硬编码在后端 4.1.1 和基础设施 6.1.5 中各计一次），上表各行统计含跨报告重复项，合计行为各行求和。其中跨报告重复问题 16 项，去重后唯一问题数为 152 项。运行实例验证的 8 个问题已关联到代码根因，不重复计入后端/前端计数。

### 9.2 改进路线图任务统计

| 优先级 | 任务数量 | 预估总时间 | 实施周期 |
|--------|----------|------------|----------|
| P0 | 13 | 约 12 天 | 1-2 周 |
| P1 | 15 | 约 15 天 | 2-4 周 |
| P2 | 12 | 约 6-8 周 | 1-2 月 |
| P3 | 9 | 约 10-12 周 | 2+ 月 |
| **合计** | **49** | 约 20-25 周 | 约 5-6 月 |

### 9.3 数据来源说明

本文档整合了以下 4 份研究报告的发现：

1. **后端分析报告**: 对 backend/ 目录全部源代码的白盒审查，覆盖 10 个模块，发现 56 个问题
2. **前端分析报告**: 对 frontend/ 目录全部 27 个源文件的深度分析，覆盖 10 个维度，发现 55 个问题
3. **基础设施分析报告**: 对全项目基础设施、部署架构、外部服务集成的白盒审查，覆盖 10 个维度，发现 49 个问题
4. **运行实例验证报告**: 通过浏览器实际访问部署实例的验证，发现 8 个运行时问题并截图取证

文档编写过程中对重复发现的问题进行了合并描述并标注多处来源，对运行实例问题关联了代码根因。

---

*文档结束*
