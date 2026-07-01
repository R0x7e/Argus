<p align="center">
  <img src="https://img.shields.io/badge/Argus-AI%20Vulnerability%20Hunter-blueviolet?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQyIDAtOC0zLjU4LTgtOHMzLjU4LTggOC04IDggMy41OCA4IDgtMy41OCA4LTggOHoiLz48L3N2Zz4="/>
</p>

<h1 align="center">Argus</h1>

<p align="center">
  <strong>AI-Powered SRC Vulnerability Mining Multi-Agent System</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white"/>
  <img src="https://img.shields.io/badge/Next.js-15-000000?style=flat-square&logo=next.js&logoColor=white"/>
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black"/>
  <img src="https://img.shields.io/badge/LangGraph-LATS+ReAct-FF6F00?style=flat-square&logo=chainlink&logoColor=white"/>
  <img src="https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white"/>
  <img src="https://img.shields.io/badge/Redis-7-DC382D?style=flat-square&logo=redis&logoColor=white"/>
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white"/>
  <img src="https://img.shields.io/badge/Katana-API%20Discovery-00ADD8?style=flat-square&logo=go&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
</p>

<p align="center">
  <a href="./README_EN.md">English</a> | <strong>中文</strong>
</p>

---

## 项目简介

**Argus** 是一个基于 LLM 驱动的多 Agent 协作漏洞挖掘系统，专为 SRC（安全应急响应中心）场景设计。系统采用 **LATS（Language Agent Tree Search）+ ReAct** 混合架构，通过蒙特卡洛树搜索（MCTS）策略智能探索漏洞空间，结合 Katana API 端点发现、Playwright 浏览器引擎、mitmproxy 流量分析、crawlergo 深度爬虫和隔离 PoC 沙箱，实现从侦察到验证的全链路自动化漏洞挖掘。

与传统扫描器不同，Argus 不依赖固定规则或签名库，而是通过 LLM 的推理能力生成漏洞假设、自适应构造 payload、智能回溯无效路径，模拟真实安全研究员的漏洞挖掘思维过程。

## 功能演示

<p align="center">
  <img src="./img/1.gif" alt="Argus 功能演示" width="100%"/>
</p>

## 核心特性

| 特性 | 说明 |
|------|------|
| **LATS + ReAct 混合架构** | 蒙特卡洛树搜索指导探索方向，ReAct 循环执行具体验证，搜索效率远超线性管线 |
| **工具驱动攻击面构造** | 端点发现完全由侦察工具（Katana、crawlergo、Playwright、dir_scan）驱动，LLM 仅作策略顾问，消除端点幻觉 |
| **EndpointCapability 统一模型** | 结构化端点能力画像 + VulnType×Endpoint 声明式兼容性矩阵，杜绝错误类型匹配 |
| **MCTS 智能搜索** | Wilson UCB + 多样性 + 端点多维评分，将有限搜索预算分配到最有价值的方向 |
| **渐进式 Level0 快速探测** | 两轮 9 次探测 + 参数自动回退，精准筛选高价值分支 |
| **多类型漏洞检测** | SQL 注入、XSS、SSRF、LFI、RCE、IDOR、SSTI、认证绕过、信息泄露等 |
| **Katana API 端点发现** | ProjectDiscovery Katana 被动+主动爬取，JS 端点提取，表单自动发现 |
| **Playwright 浏览器引擎** | 支持 SPA/前后端分离站点的动态渲染、表单交互、JS 事件触发 |
| **mitmproxy 流量捕获** | 实时捕获浏览器交互产生的隐藏 API 调用，发现前端看不到的攻击面 |
| **crawlergo 深度爬虫** | 基于 Chromium 的深度爬虫，自动触发 JS 事件和填充表单 |
| **隔离 PoC 沙箱** | RestrictedPython + Docker 双层隔离执行 PoC 代码，安全验证复杂漏洞 |
| **自适应 Payload 变异** | WAF 检测 + payload 变异绕过，支持编码、大小写、注释等多种绕过技术 |
| **实时事件流** | WebSocket 推送 Agent 思考过程和工具执行状态，前端实时可视化搜索树 |
| **自动报告生成** | 漏洞确认后自动生成结构化报告，包含复现步骤和修复建议 |
| **16 款安全工具** | 覆盖被动侦察、主动探测、PoC 执行全阶段，四级风险管控 |

## 系统架构

```
┌──────────────────────────────────────────────────────────────────────┐
│                      Frontend (Next.js 15 + React 19)                  │
│         TanStack Query + Zustand + WebSocket 实时搜索树可视化          │
└─────────────────────────────────┬────────────────────────────────────┘
                                  │ REST API / WebSocket (SSE)
┌─────────────────────────────────▼────────────────────────────────────┐
│                        Backend (FastAPI + LangGraph)                   │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                  LATS + ReAct 混合搜索引擎                        │  │
│  │                                                                 │  │
│  │   ┌───────────┐    ┌────────────────┐    ┌──────────────────┐   │  │
│  │   │   Recon   │───▶│  MCTS Select   │───▶│  ReAct Executor  │   │  │
│  │   │  (侦察)   │    │  (节点选择)     │    │  (思考-行动-观察) │   │  │
│  │   └───────────┘    └────────┬───────┘    └────────┬─────────┘   │  │
│  │                             │                     │             │  │
│  │                    ┌────────▼───────┐    ┌────────▼─────────┐   │  │
│  │                    │    Expand      │    │   Backpropagate  │   │  │
│  │                    │  (节点扩展)     │    │   (奖励回传)      │   │  │
│  │                    └────────────────┘    └────────┬─────────┘   │  │
│  │                                                   │             │  │
│  │                                          ┌────────▼─────────┐   │  │
│  │                                          │    Reporter      │   │  │
│  │                                          │   (报告生成)      │   │  │
│  │                                          └──────────────────┘   │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌──────────────── 攻击面构造管线 ────────────────────────────────┐    │
│  │ EndpointNormalizer → AttackSurfaceBuilder → EndpointCapability │    │
│  │ → estimate_branch_value_v2 (兼容性矩阵) → Level0 QuickProber   │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌──────────────────── 安全工具集 (16款) ─────────────────────────┐    │
│  │ HTTP请求 | SQL注入 | SSRF | XSS | 认证测试 | Payload变异 | ... │    │
│  └────────────────────────────────────────────────────────────────┘    │
└───────┬──────────────┬──────────────┬──────────────┬─────────────────┘
        │              │              │              │
┌───────▼──────┐ ┌────▼─────┐ ┌─────▼──────┐ ┌────▼──────────────────┐
│ PostgreSQL 16│ │  Redis 7 │ │    NATS    │ │ Sidecar Services      │
│  (数据存储)   │ │(缓存/队列)│ │ (消息总线)  │ │                       │
└──────────────┘ └──────────┘ └────────────┘ │ ┌───────────────────┐ │
                                              │ │     Katana        │ │
                                              │ │  (API端点发现)     │ │
                                              │ ├───────────────────┤ │
                                              │ │    mitmproxy      │ │
                                              │ │   (流量捕获)       │ │
                                              │ ├───────────────────┤ │
                                              │ │    crawlergo      │ │
                                              │ │   (深度爬虫)       │ │
                                              │ ├───────────────────┤ │
                                              │ │   PoC Sandbox     │ │
                                              │ │   (代码执行)       │ │
                                              │ └───────────────────┘ │
                                              └───────────────────────┘
```

## 快速开始

### 环境要求

- Docker & Docker Compose (v2.0+)
- 至少 4GB 可用内存（Chromium + crawlergo + Katana 消耗较大）
- AI API Key（Anthropic Claude）

### 一键启动

```bash
# 克隆项目
git clone <repo-url> argus && cd argus

# 配置 API Key
export ANTHROPIC_API_KEY="sk-ant-..."

# 构建并启动所有服务（9 个容器）
docker compose up -d

# 查看所有服务状态
docker compose ps
```

### 服务端口

| 服务 | 端口 | 说明 |
|------|------|------|
| Web 前端 | http://localhost:3000 | 主操作界面（任务管理、搜索树可视化、报告查看） |
| 后端 API | http://localhost:8000 | RESTful API + WebSocket 事件流 |
| API 文档 | http://localhost:8000/docs | Swagger UI 交互式文档 |
| Katana | 7778 (内部网络) | API 端点发现爬虫 |
| mitmproxy | 8080 (内部网络) | HTTP 代理（用于捕获浏览器流量） |
| crawlergo | 7777 (内部网络) | 深度爬虫 API |
| PoC Sandbox | 9090 (内部网络) | 隔离代码执行 API |
| PostgreSQL | 5432 (内部网络) | 数据库（用户名/密码: argus/argus_dev_password） |
| Redis | 6379 (内部网络) | 缓存与消息队列 |
| NATS | 4222 (内部网络) | JetStream 消息总线 |

### 使用流程

1. 访问 `http://localhost:3000` 并注册账户
2. 进入 **系统设置** 页面配置 LLM API Key
3. 创建扫描任务，填入目标 URL（例如 `https://target.example.com`）
4. 启动任务，在任务详情页实时查看：
   - 搜索树展开过程（MCTS 节点选择与扩展）
   - Agent 思考链（Thought → Action → Observation 循环）
   - 工具执行结果与奖励信号
5. 漏洞确认后自动生成报告，可导出为结构化格式

## 项目结构

```
argus/
├── backend/                          # Python 后端服务
│   ├── app/
│   │   ├── agents/                   # 多 Agent 系统
│   │   │   ├── lats/                # LATS 核心引擎
│   │   │   │   ├── graph.py          #   LangGraph 状态图构建 (Recon→Init→MCTS→React→Expand→Eval)
│   │   │   │   ├── search_tree.py    #   MCTS 搜索树 (Wilson UCB + 多维评分 + value_decay)
│   │   │   │   ├── react_executor.py #   ReAct 循环执行器 (并发池 + 端点预算控制)
│   │   │   │   ├── expansion_engine.py # 发现驱动的动态扩展引擎 (capability 门控)
│   │   │   │   ├── shared_knowledge.py # 跨分支共享知识库 (端点配额 + WAF + 信号)
│   │   │   │   ├── multi_level_prober.py # 多级探测器 (两轮渐进探测 + 参数回退)
│   │   │   │   ├── endpoint_capability.py # 端点能力统一模型 + VulnType 兼容性矩阵
│   │   │   │   ├── endpoint_normalizer.py # 端点路径标准化器 (LLM 注释清洗)
│   │   │   │   ├── attack_surface_builder.py # 工具驱动攻击面构造器 (零 LLM)
│   │   │   │   ├── reward.py         #   奖励函数 + estimate_branch_value_v2
│   │   │   │   ├── actions.py        #   动作空间定义与执行 (含 info_disclosure 证据判定)
│   │   │   │   ├── blind_verifier.py #   统一盲漏洞验证引擎
│   │   │   │   ├── diagnostic_prober.py # 诊断探测器 (失败原因分类)
│   │   │   │   ├── endpoint_explorer.py # 端点聚焦探索器 (HDE 架构)
│   │   │   │   ├── endpoint_selector.py # 端点优先级排序器
│   │   │   │   ├── hypothesis_agent.py # 假设驱动探索代理
│   │   │   │   ├── payload_library.py # Payload 库 (SQLi/XSS/LFI/RCE/SSTI/SSRF)
│   │   │   │   └── prompts.py        #   Agent 提示词模板
│   │   │   ├── nodes/                # LangGraph 节点
│   │   │   │   ├── orchestrator.py   #   编排器 (三层回退提取 + Katana 集成 + LLM 策略顾问)
│   │   │   │   └── reporter.py       #   报告生成器
│   │   │   ├── prompts/              # Agent 系统提示词
│   │   │   ├── llm.py               # LLM 客户端（多供应商支持）
│   │   │   ├── model_router.py      # 模型路由（按预算动态选模型）
│   │   │   ├── token_budget.py      # Token 预算管理
│   │   │   ├── state.py             # 共享黑板与状态定义
│   │   │   ├── emit.py              # 事件发射器
│   │   │   └── routing.py           # 图路由逻辑
│   │   ├── api/v1/                   # REST API 路由
│   │   │   ├── tasks.py             #   任务 CRUD + 状态控制
│   │   │   ├── findings.py          #   漏洞发现查询
│   │   │   ├── events.py            #   事件流
│   │   │   ├── ws.py                #   WebSocket 实时推送
│   │   │   ├── reports.py           #   报告管理
│   │   │   ├── settings.py          #   LLM 供应商配置
│   │   │   ├── system.py            #   系统健康检查
│   │   │   └── auth.py              #   认证路由
│   │   ├── core/                     # 核心基础设施
│   │   │   ├── auth.py              #   JWT 认证
│   │   │   ├── security.py          #   安全中间件
│   │   │   ├── database.py          #   异步数据库引擎
│   │   │   ├── redis.py             #   Redis 客户端
│   │   │   ├── nats_client.py       #   NATS JetStream 客户端
│   │   │   ├── event_bus.py         #   事件总线
│   │   │   ├── encryption.py        #   API Key 加密存储
│   │   │   ├── playwright_manager.py #  Playwright 浏览器池 (修复 root/appuser 路径)
│   │   │   ├── proxy_client.py      #   mitmproxy 流量订阅
│   │   │   ├── crawlergo_client.py  #   crawlergo 深度爬虫客户端
│   │   │   ├── poc_sandbox_client.py #  PoC 沙箱客户端
│   │   │   ├── middleware.py        #   请求中间件
│   │   │   └── exceptions.py        #   自定义异常
│   │   ├── models/                   # SQLAlchemy ORM 模型
│   │   ├── schemas/                  # Pydantic 数据模型
│   │   ├── services/                 # 业务逻辑层
│   │   │   ├── agent_runner.py      #   Agent 异步执行生命周期管理
│   │   │   ├── task_service.py      #   任务状态机
│   │   │   ├── finding_service.py   #   漏洞发现持久化
│   │   │   ├── report_service.py    #   报告服务
│   │   │   └── event_service.py     #   事件持久化
│   │   ├── tools/                    # 安全检测工具集（16 款工具）
│   │   ├── templates/                # Jinja2 报告模板
│   │   └── config.py                 # 全局配置（pydantic-settings）
│   ├── alembic/                      # 数据库迁移
│   ├── tests/                        # 测试用例 (27 passed)
│   └── Dockerfile                    # 修复 Playwright appuser Chromium 路径
├── frontend/                         # Next.js 前端服务
│   ├── src/
│   │   ├── app/                      # App Router 页面
│   │   ├── components/               # UI 组件
│   │   ├── hooks/                    # React Hooks
│   │   ├── lib/                      # API 客户端 & 工具库
│   │   ├── stores/                   # Zustand 状态管理
│   │   └── types/                    # TypeScript 类型定义
│   └── Dockerfile
├── katana/                           # Katana API 端点发现 Sidecar (NEW)
│   ├── api_wrapper.py               #   Flask HTTP API (JSONL 解析 + URL 标准化)
│   └── Dockerfile                    #   projectdiscovery/katana + Flask
├── crawlergo/                        # 深度爬虫 Sidecar
│   ├── api_wrapper.py               #   Flask HTTP API
│   └── Dockerfile
├── poc-sandbox/                      # PoC 隔离沙箱
│   ├── sandbox_worker.py            #   FastAPI + RestrictedPython
│   └── Dockerfile
├── mitmproxy/                        # 流量捕获 Sidecar
│   ├── addon.py                      #   请求/响应 → Redis pub/sub
│   └── Dockerfile
├── scripts/                          # 初始化脚本
│   └── init_db.sql                   #   数据库初始化 SQL
├── docker-compose.yml                # 9 服务容器编排
└── .env.example                      # 环境变量模板
```

## 核心技术解析

### 攻击面构造管线（v3 架构修复）

系统经过三轮架构修复，解决了 LLM 幻觉端点、MCTS 错误选择和发现质量三大核心问题：

```
Recon Phase (三层回退提取)
  ├─ Layer1: http_request 工具 → 正则提取 href/action/src
  ├─ Layer2: httpx 直连 → 正则提取 (工具层失败时)
  ├─ Layer3: Playwright headless → DOM 渲染提取 (JS 页面)
  └─ Katana 并行爬取 → 端点 + 表单 + JS API (与 dir_scan 并行)

AttackSurface Construction (零 LLM 驱动)
  ├─ EndpointNormalizer → 清洗 LLM 注释/通配符/非法字符
  ├─ 7 种端点来源合并去重 (categorized_links + forms + dir_scan + katana + ...)
  ├─ P0 智能分类评分 → vuln_page / api_endpoint / auth_page / config_leak
  ├─ P1 能力探测 → GET 每个端点 → 过滤 forbidden/not_found
  ├─ P3 URL 参数推断 → sqli_id.php → ["id"]
  └─ EndpointCapability → VulnType 兼容性矩阵

Branch Value Estimation (语义感知)
  ├─ estimate_branch_value_v2 → 不兼容组合 → score=0.00
  ├─ /.git/HEAD + RCE → 0.00 (is_version_control → 仅 info_disclosure)
  ├─ /vul/rce/rce_ping.php + RCE → 1.00 (路径含 "rce"+"ping"→强信号)
  └─ value_decay_factor → 每次 backprop 衰减 15%, <0.1 → exhausted

Level0 Quick Probe (两轮渐进)
  ├─ Round 1: 3 次探测 → promoted / killed / needs_deeper_probe
  ├─ Round 2: 3 种不同技术 payload → 深度验证
  ├─ 无参端点保护 → 通用参数回退 (sqli→["id","q"], rce→["cmd","ping"])
  └─ 参数发现后自动注入 node.state.current_param
```

### LATS + ReAct 混合搜索引擎

传统漏洞扫描器使用线性管线（枚举 → 测试 → 报告），存在两个问题：
1. 无法根据中间结果调整策略（如发现 WAF 后无法智能绕过）
2. 搜索空间爆炸时无法智能分配预算

Argus 采用 **LATS（Language Agent Tree Search）** 架构解决这两个问题：

```
MCTS Loop:
  1. Select   — 自适应多因素选择 (Wilson UCB + 多样性 + 新近度 + 先验 + accessibility + value_decay)
  2. Execute  — ReAct 循环执行具体验证 (Thought → Action → Observation)
  3. Expand   — 发现驱动的动态扩展 (新端点、WAF 规则、参数推断) + capability 门控
  4. Backprop — 将奖励信号沿路径回传, 更新节点价值估计 + value_decay_factor 衰减
  5. Evaluate — 检查终止条件 (发现漏洞 / 预算耗尽 / 全部穷尽 / 连续无发现)
```

**MCTS 选择因子**:
- `exploitation` (Wilson score lower bound): 利用已知高价值节点
- `exploration` (UCB): 探索未访问节点
- `prior` (value_estimate): 先验价值估计
- `diversity`: 端点/vuln_type 多样性
- `recency`: 新近度加权
- `accessibility`: 端点可达性 (forbidden/not_found → 0.0)
- `vuln_penalty`: vuln_type 全局失败惩罚

**奖励信号设计**：
- 确认漏洞: +0.4 ~ +1.0（按严重性分级）
- 发现有价值线索: +0.1 ~ +0.3（鼓励继续深挖）
- 无信息增益: -0.12（鼓励换方向）
- 明确死路: -0.15（鼓励回溯）

**跨分支共享知识库**：
- 端点指纹、WAF 规则、漏洞信号在各搜索分支间实时同步
- 避免独立 ReAct Agent 的信息孤岛问题
- 支持 Graveyard 节点复活（已剪枝节点在有信号时重新探索）
- 端点步数配额 (单端点 ≤12 步, ≤10%, 连续 3 步无信息截断)
- 端点×vuln_type 组合配额 (同一组合 ≤3 次完整 ReAct)

### PoC 沙箱安全模型

PoC 代码在多层隔离环境中执行：

| 层级 | 机制 | 作用 |
|------|------|------|
| AST 层 | RestrictedPython 编译检查 | 禁止危险语法（import *、exec 等） |
| Import 层 | 白名单机制 | 仅允许 requests、json、hashlib 等 15 个模块 |
| 运行时层 | Guard 函数 | 控制属性访问、下标操作、迭代行为 |
| 容器层 | Docker read_only + tmpfs + 资源限制 | 文件系统只读、内存 512MB、CPU 1 核 |
| 网络层 | allowed_hosts 限制 | 仅允许访问指定目标主机 |

### 安全工具集

| 工具 | 功能 | 风险等级 |
|------|------|----------|
| `http_requester` | HTTP 请求构造与发送 | L0 |
| `dir_scanner` | 目录与路径扫描 | L0 |
| `subdomain_enum` | 子域名枚举 | L0 |
| `port_scanner` | 端口探测与服务发现 | L0 |
| `payload_mutator` | Payload 变异绕过 WAF | L0 |
| `proxy_flows` | 查询 mitmproxy 捕获的浏览器流量 | L0 |
| `deep_crawl` | crawlergo 深度爬虫 | L0 |
| `katana_crawl` | Katana headless 爬虫 (端点 + JS API 发现) | L0 |
| `nuclei_scanner` | Nuclei PoC 扫描已知 CVE | L1 |
| `sql_injection` | SQL 注入检测（时间盲注、报错注入、布尔盲注） | L1 |
| `ssrf_detector` | SSRF 漏洞检测（DNS rebinding、协议切换） | L1 |
| `auth_tester` | 认证绕过测试（JWT 伪造、空密码等） | L1 |
| `browser_request` | 浏览器级别 HTTP 请求（带 Cookie/Session） | L1 |
| `browser_interact` | 浏览器表单交互（填充、点击、提交） | L2 |
| `run_poc` | 隔离沙箱执行 Python PoC 代码 | L2 |
| `payload_library` | 内置 Payload 库 (SQLi/XSS/LFI/RCE/SSTI/SSRF 预设) | — |

> 风险等级：L0 = 只读/被动扫描，L1 = 主动探测/有限写，L2 = 真实漏洞利用，L3 = 高危破坏性操作

## 环境变量配置

| 变量 | 必需 | 默认值 | 说明 |
|------|------|--------|------|
| `ANTHROPIC_API_KEY` | 是 | - | Anthropic Claude API 密钥（也可通过前端设置页面配置） |
| `JWT_SECRET` | 生产环境必需 | `argus-dev-secret-key-2024` | JWT 签名密钥 |
| `DATABASE_URL` | 否 | `postgresql+asyncpg://argus:...@postgres:5432/argus` | PostgreSQL 连接串 |
| `REDIS_URL` | 否 | `redis://redis:6379/0` | Redis 连接地址 |
| `NATS_URL` | 否 | `nats://nats:4222` | NATS 消息总线地址 |
| `ENCRYPTION_KEY` | 否 | 从 JWT_SECRET 派生 | Fernet 加密密钥（用于 API Key 加密存储） |
| `MITMPROXY_URL` | 否 | `http://mitmproxy:8080` | mitmproxy 代理地址 |
| `CRAWLERGO_URL` | 否 | `http://crawlergo:7777` | crawlergo 深度爬虫 API 地址 |
| `KATANA_URL` | 否 | `http://katana:7778` | Katana API 端点发现服务地址 |
| `POC_SANDBOX_URL` | 否 | `http://poc-sandbox:9090` | PoC 沙箱执行器地址 |
| `SIDECAR_SECRET` | 否 | - | Sidecar 服务共享密钥 |
| `TASK_TIMEOUT_SECONDS` | 否 | `3600` | 任务执行全局超时（秒） |
| `DEBUG` | 否 | `false` | 调试模式 |
| `LOG_LEVEL` | 否 | `INFO` | 日志级别（DEBUG/INFO/WARNING/ERROR） |

## 开发指南

### 本地开发

```bash
# 启动基础设施（数据库、Redis、NATS）
docker compose up -d postgres redis nats

# 后端开发（热重载）
cd backend
pip install -e .
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 前端开发（热重载）
cd frontend
npm install
npm run dev
```

### 常用命令

```bash
docker compose up -d        # 启动所有服务
docker compose down         # 停止所有服务
docker compose build        # 重新构建镜像
docker compose logs -f backend  # 查看后端日志
docker compose ps           # 查看服务状态
```

### 添加新工具

1. 在 `backend/app/tools/` 下创建工具文件，继承 `BaseTool`：

```python
from app.tools.base import BaseTool, ExecutionContext, RiskLevel

class MyNewTool(BaseTool):
    name = "my_tool"
    description = "工具描述"
    risk_level = RiskLevel.L1

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        return {"success": True, "data": result}
```

2. 在 `backend/app/tools/__init__.py` 的 `_register_all_tools()` 中注册
3. 在 `backend/app/agents/lats/actions.py` 中添加执行逻辑

### 数据库迁移

```bash
cd backend
alembic revision --autogenerate -m "description"  # 创建迁移
alembic upgrade head                                # 执行迁移
alembic downgrade -1                                # 回滚
```

## Agent 工作流程

```mermaid
graph TD
    A[Recon 侦察] -->|Katana+crawlergo+Playwright| B[Init Tree 初始化搜索树]
    B -->|EndpointCapability 兼容性过滤| C{MCTS Select 选择节点}
    C -->|多维评分| D[Expand 生成候选方向]
    D --> E[ReAct Execute 执行验证]

    E --> F{Thought}
    F -->|推理| G[Action 选择工具]
    G --> H[Observation 观察结果]
    H -->|继续| F
    H -->|完成/回溯| I[Compute Reward]

    I --> J[Backpropagate 回传奖励 + 衰减]
    J --> K{终止条件?}
    K -->|漏洞确认| L[Reporter 生成报告]
    K -->|预算耗尽| L
    K -->|继续搜索| C
    K -->|分支穷尽| M[Prune 剪枝]
    M --> C
```

## 安全注意事项

- Argus 仅用于 **授权的安全测试**（SRC 漏洞挖掘、渗透测试授权范围内）
- 使用前请确保已获得目标的 **书面授权**
- PoC 沙箱虽有多层隔离，但不建议在生产环境中长期运行
- 默认配置的 JWT_SECRET 仅供开发使用，**生产环境必须更换**
- 建议配置独立的 `ENCRYPTION_KEY` 用于 API Key 加密存储
- 数据库密码同理，**生产环境必须使用强密码**

## 常见问题

**Q: 启动后前端无法访问？**
A: 确认所有容器健康：`docker compose ps`。前端依赖后端启动完成，通常需要等待 30-60 秒。

**Q: Agent 不执行任何动作？**
A: 检查 `ANTHROPIC_API_KEY` 是否正确配置。查看后端日志：`docker logs argus-backend --tail 100`。

**Q: Playwright 报 "未初始化"？**
A: 已修复。确保使用最新 Dockerfile（Chromium 缓存已复制到 appuser 目录）。如需重建：`docker compose build backend && docker compose up -d backend`。

**Q: Katana 爬取返回空结果？**
A: Katana 首次 headless 运行需下载 Chrome (~130MB)。被动模式（headless=false）对传统网站已足够。检查日志：`docker logs argus-katana --tail 50`。

**Q: PoC 执行报 "Import not allowed"？**
A: 沙箱仅允许以下模块：`requests`, `urllib3`, `base64`, `json`, `hashlib`, `re`, `time`, `socket`, `struct`, `urllib`, `http`, `collections`, `itertools`, `string`, `binascii`, `zlib`。修改 `poc-sandbox/sandbox_worker.py` 中的 `ALLOWED_IMPORTS` 可扩展白名单。

**Q: crawlergo 返回空结果？**
A: 目标站点可能阻止了 Chromium 访问。检查容器日志：`docker logs argus-crawlergo --tail 50`。

**Q: 如何调整搜索深度？**
A: 创建任务时可设置 `max_iterations`（默认 15）。核心参数位于 `backend/app/agents/lats/graph.py`。

## License

MIT License

---

<p align="center">
  <sub>Built with care for Security Researchers</sub>
</p>
