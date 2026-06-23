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
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
</p>

<p align="center">
  <a href="./README_EN.md">English</a> | <strong>中文</strong>
</p>

---

## 项目简介

**Argus** 是一个基于 LLM 驱动的多 Agent 协作漏洞挖掘系统，专为 SRC（安全应急响应中心）场景设计。系统采用 **LATS（Language Agent Tree Search）+ ReAct** 混合架构，通过蒙特卡洛树搜索（MCTS）策略智能探索漏洞空间，结合 Playwright 浏览器引擎、mitmproxy 流量分析、crawlergo 深度爬虫和隔离 PoC 沙箱，实现从侦察到验证的全链路自动化漏洞挖掘。

与传统扫描器不同，Argus 不依赖固定规则或签名库，而是通过 LLM 的推理能力生成漏洞假设、自适应构造 payload、智能回溯无效路径，模拟真实安全研究员的漏洞挖掘思维过程。

## 核心特性

| 特性 | 说明 |
|------|------|
| **LATS + ReAct 混合架构** | 蒙特卡洛树搜索指导探索方向，ReAct 循环执行具体验证，搜索效率远超线性管线 |
| **MCTS 智能搜索** | UCB1 选择策略、奖励回传、自动剪枝，将有限搜索预算分配到最有价值的方向 |
| **多类型漏洞检测** | SQL 注入、XSS、SSRF、LFI、RCE、IDOR、SSTI、认证绕过、信息泄露等 |
| **Playwright 浏览器引擎** | 支持 SPA/前后端分离站点的动态渲染、表单交互、JS 事件触发 |
| **mitmproxy 流量捕获** | 实时捕获浏览器交互产生的隐藏 API 调用，发现前端看不到的攻击面 |
| **crawlergo 深度爬虫** | 基于 Chromium 的深度爬虫，自动触发 JS 事件和填充表单 |
| **隔离 PoC 沙箱** | RestrictedPython + Docker 双层隔离执行 PoC 代码，安全验证复杂漏洞 |
| **自适应 Payload 变异** | WAF 检测 + payload 变异绕过，支持编码、大小写、注释等多种绕过技术 |
| **实时事件流** | WebSocket 推送 Agent 思考过程和工具执行状态，前端实时可视化搜索树 |
| **自动报告生成** | 漏洞确认后自动生成结构化报告，包含复现步骤和修复建议 |
| **一键部署** | Docker Compose 全栈 8 服务编排，开箱即用 |

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
│  ┌──────────────────── 安全工具集 ────────────────────────────────┐    │
│  │ HTTP请求 | SQL注入 | SSRF | XSS | 认证测试 | Payload变异 | ... │    │
│  └────────────────────────────────────────────────────────────────┘    │
└───────┬──────────────┬──────────────┬──────────────┬─────────────────┘
        │              │              │              │
┌───────▼──────┐ ┌────▼─────┐ ┌─────▼──────┐ ┌────▼──────┐
│ PostgreSQL 16│ │  Redis 7 │ │    NATS    │ │ Sidecar   │
│  (数据存储)   │ │(缓存/队列)│ │ (消息总线)  │ │  Services │
└──────────────┘ └──────────┘ └────────────┘ └───────────┘
                                                    │
                                    ┌───────────────┼───────────────┐
                                    │               │               │
                              ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐
                              │ mitmproxy │  │ crawlergo │  │PoC Sandbox│
                              │ (流量捕获) │  │ (深度爬虫) │  │ (代码执行) │
                              └───────────┘  └───────────┘  └───────────┘
```

## 快速开始

### 环境要求

- Docker & Docker Compose (v2.0+)
- 至少 4GB 可用内存（Chromium + crawlergo 消耗较大）
- AI API Key（Anthropic Claude）

### 一键启动

```bash
# 克隆项目
git clone <repo-url> argus && cd argus

# 配置 API Key
export ANTHROPIC_API_KEY="sk-ant-..."

# 构建并启动所有服务（8 个容器）
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
| mitmproxy | localhost:8080 | HTTP 代理（用于捕获浏览器流量） |
| crawlergo | localhost:7777 | 深度爬虫 API |
| PoC Sandbox | localhost:9090 | 隔离代码执行 API |
| PostgreSQL | localhost:5432 | 数据库（用户名/密码: argus/argus_dev_password） |
| Redis | localhost:6379 | 缓存与消息队列 |
| NATS | localhost:4222 | JetStream 消息总线（监控端口: 8222） |

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
├── backend/                        # Python 后端服务
│   ├── app/
│   │   ├── agents/                 # 多 Agent 系统
│   │   │   ├── lats/              # LATS 核心引擎
│   │   │   │   ├── graph.py       #   LangGraph 状态图构建
│   │   │   │   ├── search_tree.py #   MCTS 搜索树（UCB1、回传、剪枝）
│   │   │   │   ├── react_executor.py # ReAct 循环执行器
│   │   │   │   ├── reward.py      #   奖励函数（信号设计）
│   │   │   │   ├── actions.py     #   动作空间定义与执行
│   │   │   │   └── prompts.py     #   Agent 提示词模板
│   │   │   ├── nodes/             # LangGraph 节点
│   │   │   │   ├── orchestrator.py#   编排器（侦察与规划）
│   │   │   │   ├── hypothesizer.py#   假设生成器
│   │   │   │   ├── verifier.py    #   验证器
│   │   │   │   └── reporter.py    #   报告生成器
│   │   │   ├── llm.py            # LLM 客户端抽象
│   │   │   ├── model_router.py   # 模型路由（按任务复杂度选模型）
│   │   │   └── state.py          # 共享黑板状态
│   │   ├── api/v1/               # REST API 路由
│   │   ├── core/                 # 核心模块
│   │   │   ├── auth.py           #   JWT 认证
│   │   │   ├── security.py       #   安全中间件
│   │   │   ├── playwright_manager.py # Playwright 浏览器池
│   │   │   └── proxy_client.py   #   mitmproxy 客户端
│   │   ├── models/               # SQLAlchemy ORM 模型
│   │   ├── schemas/              # Pydantic 数据模型
│   │   ├── services/             # 业务逻辑层
│   │   ├── tools/                # 安全检测工具集（16+ 工具）
│   │   └── config.py             # 全局配置
│   ├── alembic/                  # 数据库迁移
│   ├── tests/                    # 测试用例
│   └── Dockerfile
├── frontend/                      # Next.js 前端服务
│   ├── src/
│   │   ├── app/                  # App Router 页面
│   │   │   ├── tasks/            #   任务管理与详情
│   │   │   ├── findings/         #   漏洞发现列表
│   │   │   └── settings/         #   系统设置
│   │   ├── components/           # UI 组件
│   │   │   ├── execution/        #   搜索树可视化、思考链面板
│   │   │   ├── dashboard/        #   仪表盘
│   │   │   ├── findings/         #   漏洞详情
│   │   │   └── ui/               #   通用 UI 组件
│   │   ├── hooks/                # React Hooks
│   │   ├── lib/                  # API 客户端 & 工具库
│   │   ├── stores/               # Zustand 状态管理
│   │   └── types/                # TypeScript 类型定义
│   └── Dockerfile
├── crawlergo/                     # 深度爬虫 Sidecar
│   ├── api_wrapper.py            #   Flask HTTP API 包装
│   └── Dockerfile                #   Chromium + crawlergo 二进制
├── poc-sandbox/                   # PoC 隔离沙箱
│   ├── sandbox_worker.py         #   FastAPI + RestrictedPython
│   └── Dockerfile                #   只读文件系统 + 资源限制
├── mitmproxy/                     # 流量捕获 Sidecar
│   ├── addon.py                  #   请求/响应 → Redis pub/sub
│   └── Dockerfile
├── docker-compose.yml             # 8 服务容器编排
└── Makefile                       # 开发命令集合
```

## 核心技术解析

### LATS + ReAct 混合搜索引擎

传统漏洞扫描器使用线性管线（枚举 → 测试 → 报告），存在两个问题：
1. 无法根据中间结果调整策略（如发现 WAF 后无法智能绕过）
2. 搜索空间爆炸时无法智能分配预算

Argus 采用 **LATS（Language Agent Tree Search）** 架构解决这两个问题：

```
MCTS Loop:
  1. Select   — UCB1 策略选择最有价值的搜索节点
  2. Expand   — LLM 生成 2-4 个候选探索方向
  3. Execute  — ReAct 循环执行具体验证（Thought → Action → Observation）
  4. Backprop — 将奖励信号沿路径回传，更新节点价值估计
  5. Evaluate — 检查终止条件（发现漏洞 / 预算耗尽 / 全部穷尽）
```

**奖励信号设计**：
- 确认漏洞: +0.4 ~ +1.0（按严重性分级）
- 发现有价值线索: +0.1 ~ +0.3（鼓励继续深挖）
- 无信息增益: -0.03（轻微惩罚，鼓励换方向）
- 明确死路: -0.15（鼓励回溯）

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
| `http_requester` | HTTP 请求构造与发送 | L1 |
| `dir_scanner` | 目录与路径扫描 | L1 |
| `sql_injection` | SQL 注入检测（时间盲注、报错注入等） | L2 |
| `ssrf_detector` | SSRF 漏洞检测（DNS rebinding、协议切换） | L2 |
| `auth_tester` | 认证绕过测试（JWT 伪造、空密码等） | L2 |
| `payload_mutator` | Payload 变异绕过 WAF | L1 |
| `nuclei_scanner` | Nuclei PoC 扫描已知 CVE | L2 |
| `port_scanner` | 端口探测与服务发现 | L1 |
| `subdomain_enum` | 子域名枚举 | L1 |
| `render_page` | Playwright 页面渲染（提取 JS 动态路由） | L1 |
| `interact_page` | 浏览器表单交互（填充、点击、提交） | L2 |
| `deep_crawl` | crawlergo 深度爬虫 | L1 |
| `analyze_traffic` | 查询 mitmproxy 捕获的浏览器流量 | L1 |
| `run_poc` | 隔离沙箱执行 Python PoC 代码 | L2 |
| `proxy_flows` | 分析代理流量中的安全问题 | L1 |
| `browser_request` | 浏览器级别 HTTP 请求（带 Cookie/Session） | L1 |

> 风险等级：L1 = 被动/信息收集，L2 = 主动验证/可能触发目标异常

## 环境变量配置

| 变量 | 必需 | 默认值 | 说明 |
|------|------|--------|------|
| `ANTHROPIC_API_KEY` | 是 | - | Anthropic Claude API 密钥 |
| `JWT_SECRET` | 生产环境必需 | `argus-dev-secret-key-2024` | JWT 签名密钥 |
| `DATABASE_URL` | 否 | `postgresql+asyncpg://argus:argus_dev_password@postgres:5432/argus` | PostgreSQL 连接串 |
| `REDIS_URL` | 否 | `redis://redis:6379/0` | Redis 连接地址 |
| `NATS_URL` | 否 | `nats://nats:4222` | NATS 消息总线地址 |
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
make dev        # 启动后端开发服务器（热重载）
make migrate    # 执行数据库迁移
make test       # 运行测试套件（含覆盖率）
make lint       # 代码质量检查（ruff）
make format     # 代码格式化
make build      # 构建 Docker 镜像
make up         # 启动所有服务
make down       # 停止所有服务
```

### 添加新工具

1. 在 `backend/app/tools/` 下创建工具文件，继承 `BaseTool`：

```python
from app.tools.base import BaseTool, ExecutionContext

class MyNewTool(BaseTool):
    name = "my_tool"
    description = "工具描述"
    risk_level = "L1"  # L1: 被动, L2: 主动

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        # 实现工具逻辑
        return {"success": True, "data": result}
```

2. 在 `backend/app/tools/__init__.py` 中注册工具
3. 在 `backend/app/agents/lats/prompts.py` 中添加工具描述供 Agent 使用
4. 在 `backend/app/agents/lats/actions.py` 中添加执行逻辑

### 数据库迁移

```bash
# 创建新迁移
cd backend && alembic revision --autogenerate -m "description"

# 执行迁移
alembic upgrade head

# 回滚一步
alembic downgrade -1
```

## Agent 工作流程

```mermaid
graph TD
    A[Recon 侦察] -->|收集目标信息| B[Init Tree 初始化搜索树]
    B --> C{MCTS Select 选择节点}
    C -->|UCB1 策略| D[Expand 生成候选方向]
    D --> E[ReAct Execute 执行验证]

    E --> F{Thought}
    F -->|推理| G[Action 选择工具]
    G --> H[Observation 观察结果]
    H -->|继续| F
    H -->|完成/回溯| I[Compute Reward]

    I --> J[Backpropagate 回传奖励]
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
- 数据库密码同理，**生产环境必须使用强密码**

## 常见问题

**Q: 启动后前端无法访问？**
A: 确认所有容器健康：`docker compose ps`。前端依赖后端启动完成，通常需要等待 30-60 秒。

**Q: Agent 不执行任何动作？**
A: 检查 `ANTHROPIC_API_KEY` 是否正确配置。查看后端日志：`docker logs argus-backend --tail 100`。

**Q: PoC 执行报 "Import not allowed"？**
A: 沙箱仅允许以下模块：`requests`, `urllib3`, `base64`, `json`, `hashlib`, `re`, `time`, `socket`, `struct`, `urllib`, `http`, `collections`, `itertools`, `string`, `binascii`, `zlib`。修改 `poc-sandbox/sandbox_worker.py` 中的 `ALLOWED_IMPORTS` 可扩展白名单。

**Q: crawlergo 返回空结果？**
A: 目标站点可能阻止了 Chromium 访问。检查容器日志：`docker logs argus-crawlergo --tail 50`。

**Q: 如何增加搜索深度？**
A: 调整 LATS 配置参数：搜索树最大深度、每节点最大步数、MCTS 迭代次数等，位于 `backend/app/agents/lats/graph.py`。

## License

MIT License

---

<p align="center">
  <sub>Built with care for Security Researchers</sub>
</p>
