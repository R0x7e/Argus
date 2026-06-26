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
  <strong>English</strong> | <a href="./README.md">中文</a>
</p>

---

## Overview

**Argus** is an LLM-driven multi-agent vulnerability mining system designed for SRC (Security Response Center) scenarios. The system adopts a **LATS (Language Agent Tree Search) + ReAct** hybrid architecture, using Monte Carlo Tree Search (MCTS) to intelligently explore the vulnerability space. Combined with Playwright browser engine, mitmproxy traffic analysis, crawlergo deep crawling, and an isolated PoC sandbox, Argus achieves fully automated vulnerability discovery from reconnaissance to verification.

Unlike traditional scanners that rely on fixed rules or signature databases, Argus leverages LLM reasoning to generate vulnerability hypotheses, adaptively construct payloads, and intelligently backtrack dead-end paths — mimicking the thought process of real security researchers.

## Demo

<p align="center">
  <img src="./img/1.gif" alt="Argus Demo" width="100%"/>
</p>

## Key Features

| Feature | Description |
|---------|-------------|
| **LATS + ReAct Hybrid** | MCTS guides exploration direction, ReAct loop executes concrete verification — far more efficient than linear pipelines |
| **MCTS Smart Search** | Wilson UCB selection, reward backpropagation, auto-pruning — allocates limited search budget to the most promising directions |
| **Multi-Type Detection** | SQL Injection, XSS, SSRF, LFI, RCE, IDOR, SSTI, Auth Bypass, Information Disclosure, and more |
| **Playwright Browser Engine** | Dynamic rendering for SPA/modern sites, form interaction, JS event triggering |
| **mitmproxy Traffic Capture** | Real-time capture of hidden API calls during browser interaction |
| **crawlergo Deep Crawl** | Chromium-based deep crawler with auto JS event triggering and form filling |
| **Isolated PoC Sandbox** | RestrictedPython + Docker dual-layer isolation for safe PoC execution |
| **Adaptive Payload Mutation** | WAF detection + payload mutation bypass (encoding, case switching, comments, etc.) |
| **Real-time Event Stream** | WebSocket-pushed agent reasoning and tool execution status with live search tree visualization |
| **Auto Report Generation** | Structured vulnerability reports with reproduction steps and remediation advice |
| **14 Security Tools** | Covering passive recon, active probing, and PoC execution with 4-level risk control |

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                      Frontend (Next.js 15 + React 19)                  │
│         TanStack Query + Zustand + WebSocket Live Search Tree          │
└─────────────────────────────────┬────────────────────────────────────┘
                                  │ REST API / WebSocket (SSE)
┌─────────────────────────────────▼────────────────────────────────────┐
│                        Backend (FastAPI + LangGraph)                   │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                  LATS + ReAct Hybrid Search Engine               │  │
│  │                                                                 │  │
│  │   ┌───────────┐    ┌────────────────┐    ┌──────────────────┐   │  │
│  │   │   Recon   │───▶│  MCTS Select   │───▶│  ReAct Executor  │   │  │
│  │   │           │    │ (Node Select)  │    │ (Think-Act-Observe)│   │  │
│  │   └───────────┘    └────────┬───────┘    └────────┬─────────┘   │  │
│  │                             │                     │             │  │
│  │                    ┌────────▼───────┐    ┌────────▼─────────┐   │  │
│  │                    │    Expand      │    │   Backpropagate  │   │  │
│  │                    │(Node Expansion)│    │  (Reward Signal)  │   │  │
│  │                    └────────────────┘    └────────┬─────────┘   │  │
│  │                                                   │             │  │
│  │                                          ┌────────▼─────────┐   │  │
│  │                                          │    Reporter      │   │  │
│  │                                          │(Report Generation)│   │  │
│  │                                          └──────────────────┘   │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌──────────────────── Security Tools ─────────────────────────────┐  │
│  │ HTTP Req | SQLi | SSRF | XSS | Auth Test | Payload Mutation ...│  │
│  └─────────────────────────────────────────────────────────────────┘  │
└───────┬──────────────┬──────────────┬──────────────┬─────────────────┘
        │              │              │              │
┌───────▼──────┐ ┌────▼─────┐ ┌─────▼──────┐ ┌────▼──────┐
│ PostgreSQL 16│ │  Redis 7 │ │    NATS    │ │ Sidecar   │
│  (Storage)   │ │(Cache/Q) │ │ (Msg Bus)  │ │  Services │
└──────────────┘ └──────────┘ └────────────┘ └───────────┘
                                                    │
                                    ┌───────────────┼───────────────┐
                                    │               │               │
                              ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐
                              │ mitmproxy │  │ crawlergo │  │PoC Sandbox│
                              │ (Traffic) │  │(Deep Crawl)│  │(Code Exec)│
                              └───────────┘  └───────────┘  └───────────┘
```

## Quick Start

### Prerequisites

- Docker & Docker Compose (v2.0+)
- At least 4GB available RAM (Chromium + crawlergo are memory-intensive)
- AI API Key (Anthropic Claude)

### Launch

```bash
# Clone the project
git clone <repo-url> argus && cd argus

# Configure API Key
export ANTHROPIC_API_KEY="sk-ant-..."

# Build and start all services (8 containers)
docker compose up -d

# Check all service status
docker compose ps
```

### Service Ports

| Service | Port | Description |
|---------|------|-------------|
| Web UI | http://localhost:3000 | Main interface (task management, search tree visualization, reports) |
| Backend API | http://localhost:8000 | RESTful API + WebSocket event stream |
| API Docs | http://localhost:8000/docs | Swagger UI interactive documentation |
| mitmproxy | 8080 (internal) | HTTP proxy (browser traffic capture) |
| crawlergo | 7777 (internal) | Deep crawl API |
| PoC Sandbox | 9090 (internal) | Isolated code execution API |
| PostgreSQL | 5432 (internal) | Database (user/pass: argus/argus_dev_password) |
| Redis | 6379 (internal) | Cache & message queue |
| NATS | 4222 (internal) | JetStream message bus |

### Usage

1. Visit `http://localhost:3000` and register an account
2. Navigate to **Settings** and configure your LLM API Key
3. Create a scan task with the target URL (e.g., `https://target.example.com`)
4. Start the task and monitor in real-time:
   - Search tree expansion (MCTS node selection & expansion)
   - Agent reasoning chain (Thought → Action → Observation loop)
   - Tool execution results and reward signals
5. Reports auto-generated upon vulnerability confirmation

## Project Structure

```
argus/
├── backend/                          # Python backend service
│   ├── app/
│   │   ├── agents/                   # Multi-agent system
│   │   │   ├── lats/                # LATS core engine
│   │   │   │   ├── graph.py          #   LangGraph state graph
│   │   │   │   ├── search_tree.py    #   MCTS search tree (Wilson UCB, backprop, pruning)
│   │   │   │   ├── react_executor.py #   ReAct loop executor (concurrent pool)
│   │   │   │   ├── expansion_engine.py # Discovery-driven dynamic expansion
│   │   │   │   ├── shared_knowledge.py # Cross-branch shared knowledge
│   │   │   │   ├── multi_level_prober.py # Multi-level prober (Level 0 fast probe)
│   │   │   │   ├── reward.py         #   Reward function (signal design)
│   │   │   │   ├── actions.py        #   Action space definition & execution
│   │   │   │   ├── param_fuzzer.py   #   Parameter fuzzing
│   │   │   │   ├── payload_library.py #   Payload library
│   │   │   │   └── prompts.py        #   Agent prompt templates
│   │   │   ├── nodes/                # LangGraph nodes
│   │   │   │   ├── orchestrator.py   #   Orchestrator (recon & planning)
│   │   │   │   ├── hypothesizer.py   #   Hypothesis generator
│   │   │   │   ├── verifier.py       #   Verifier
│   │   │   │   └── reporter.py       #   Report generator
│   │   │   ├── prompts/              # Agent system prompts
│   │   │   ├── llm.py               # LLM client (multi-provider)
│   │   │   ├── model_router.py      # Model router (budget-aware)
│   │   │   ├── token_budget.py      # Token budget management
│   │   │   ├── state.py             # Shared blackboard & state definitions
│   │   │   ├── emit.py              # Event emitter
│   │   │   └── routing.py           # Graph routing logic
│   │   ├── api/v1/                   # REST API routes
│   │   │   ├── tasks.py             #   Task CRUD + state control
│   │   │   ├── findings.py          #   Vulnerability findings query
│   │   │   ├── events.py            #   Event stream (SSE)
│   │   │   ├── ws.py                #   WebSocket real-time push
│   │   │   ├── reports.py           #   Report management
│   │   │   ├── settings.py          #   LLM provider configuration
│   │   │   ├── system.py            #   System health check
│   │   │   ├── steps.py             #   Agent execution steps
│   │   │   └── auth.py              #   Authentication routes
│   │   ├── core/                     # Core infrastructure
│   │   │   ├── auth.py              #   JWT authentication
│   │   │   ├── security.py          #   Security middleware
│   │   │   ├── database.py          #   Async database engine
│   │   │   ├── redis.py             #   Redis client
│   │   │   ├── nats_client.py       #   NATS JetStream client
│   │   │   ├── event_bus.py         #   Event bus
│   │   │   ├── encryption.py        #   API Key encrypted storage
│   │   │   ├── playwright_manager.py #  Playwright browser pool
│   │   │   ├── proxy_client.py      #   mitmproxy traffic subscription
│   │   │   ├── crawlergo_client.py  #   crawlergo deep crawl client
│   │   │   ├── poc_sandbox_client.py #  PoC sandbox client
│   │   │   ├── middleware.py        #   Request middleware
│   │   │   └── exceptions.py        #   Custom exceptions
│   │   ├── models/                   # SQLAlchemy ORM models
│   │   ├── schemas/                  # Pydantic data models
│   │   ├── services/                 # Business logic layer
│   │   │   ├── agent_runner.py      #   Agent async lifecycle management
│   │   │   ├── task_service.py      #   Task state machine
│   │   │   ├── finding_service.py   #   Finding persistence
│   │   │   ├── report_service.py    #   Report service
│   │   │   └── event_service.py     #   Event persistence
│   │   ├── tools/                    # Security tools (14 tools)
│   │   ├── templates/                # Jinja2 report templates
│   │   └── config.py                 # Global config (pydantic-settings)
│   ├── alembic/                      # Database migrations
│   ├── tests/                        # Test suite
│   └── Dockerfile
├── frontend/                         # Next.js frontend service
│   ├── src/
│   │   ├── app/                      # App Router pages
│   │   │   ├── tasks/               #   Task management & details
│   │   │   ├── findings/            #   Vulnerability findings list
│   │   │   ├── settings/            #   System settings (LLM provider config)
│   │   │   └── login/               #   Login & registration
│   │   ├── components/               # UI components
│   │   │   ├── execution/           #   Search tree visualization, reasoning chain panel
│   │   │   ├── dashboard/           #   Dashboard
│   │   │   ├── findings/            #   Vulnerability details
│   │   │   ├── tasks/               #   Task list
│   │   │   ├── monitor/             #   Monitor panel
│   │   │   └── ui/                  #   Common UI components
│   │   ├── hooks/                    # React Hooks
│   │   ├── lib/                      # API client & utilities
│   │   ├── stores/                   # Zustand state management
│   │   └── types/                    # TypeScript type definitions
│   └── Dockerfile
├── crawlergo/                        # Deep crawl sidecar
│   ├── api_wrapper.py               #   FastAPI HTTP API wrapper
│   └── Dockerfile                    #   Chromium + crawlergo binary
├── poc-sandbox/                      # PoC isolated sandbox
│   ├── sandbox_worker.py            #   FastAPI + RestrictedPython
│   └── Dockerfile                    #   Read-only filesystem + resource limits
├── mitmproxy/                        # Traffic capture sidecar
│   ├── addon.py                      #   Request/Response → Redis pub/sub
│   └── Dockerfile
├── scripts/                          # Initialization scripts
│   └── init_db.sql                   #   Database initialization SQL
├── docker-compose.yml                # 8-service container orchestration
├── Makefile                          # Development commands
└── .env.example                      # Environment variable template
```

## Core Technology

### LATS + ReAct Hybrid Search Engine

Traditional vulnerability scanners use a linear pipeline (enumerate → test → report), which has two problems:
1. Cannot adapt strategy based on intermediate findings (e.g., smart WAF bypass)
2. Cannot intelligently allocate budget when the search space explodes

Argus solves these with **LATS (Language Agent Tree Search)**:

```
MCTS Loop:
  1. Select   — Adaptive multi-factor selection (Wilson UCB + diversity + recency + prior)
  2. Execute  — ReAct loop for concrete verification (Thought → Action → Observation)
  3. Expand   — Discovery-driven dynamic expansion (new endpoints, WAF rules, parameter inference)
  4. Backprop — Propagate reward signals along the path, update node value estimates
  5. Evaluate — Check termination conditions (vuln found / budget exhausted / all exhausted / consecutive dry runs)
```

**Reward Signal Design**:
- Confirmed vulnerability: +0.4 ~ +1.0 (severity-based)
- Valuable clue found: +0.1 ~ +0.3 (encourage deeper exploration)
- No information gain: -0.03 (mild penalty, encourage direction switch)
- Dead end confirmed: -0.15 (encourage backtracking)

**Cross-Branch Shared Knowledge**:
- Endpoint fingerprints, WAF rules, and vulnerability signals sync across search branches in real-time
- Eliminates information silos between independent ReAct agents
- Supports graveyard node revival (re-exploring pruned nodes when signals emerge)

### PoC Sandbox Security Model

PoC code executes in a multi-layer isolated environment:

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| AST | RestrictedPython compile check | Block dangerous syntax (import *, exec, etc.) |
| Import | Whitelist | Allow only requests, json, hashlib, etc. (15 modules) |
| Runtime | Guard functions | Control attribute access, subscript, iteration |
| Container | Docker read_only + tmpfs + resource limits | Read-only FS, 512MB RAM, 1 CPU core |
| Network | allowed_hosts restriction | Only allow access to specified targets |

### Security Tools

| Tool | Function | Risk Level |
|------|----------|------------|
| `http_requester` | HTTP request builder & sender | L0 |
| `dir_scanner` | Directory & path scanning | L0 |
| `subdomain_enum` | Subdomain enumeration | L0 |
| `port_scanner` | Port discovery & service detection | L0 |
| `payload_mutator` | Payload mutation for WAF bypass | L0 |
| `proxy_flows` | Query mitmproxy-captured browser traffic | L0 |
| `deep_crawl` | crawlergo deep crawling | L0 |
| `nuclei_scanner` | Nuclei PoC scanning for known CVEs | L1 |
| `sql_injection` | SQL injection detection (time-based, error-based) | L1 |
| `ssrf_detector` | SSRF detection (DNS rebinding, protocol switching) | L1 |
| `auth_tester` | Authentication bypass testing (JWT forgery, empty password) | L1 |
| `browser_request` | Browser-level HTTP requests (with Cookie/Session) | L1 |
| `browser_interact` | Browser form interaction (fill, click, submit) | L2 |
| `run_poc` | Isolated sandbox Python PoC execution | L2 |

> Risk Levels: L0 = Read-only/passive scan, L1 = Active probing/limited write, L2 = Real exploit, L3 = High-risk destructive

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | Yes | - | Anthropic Claude API key (also configurable via frontend settings) |
| `JWT_SECRET` | Production | `your-super-secret-key-change-in-production` | JWT signing secret |
| `DATABASE_URL` | No | `postgresql+asyncpg://argus:argus_dev_password@localhost:5432/argus` | PostgreSQL connection string |
| `REDIS_URL` | No | `redis://localhost:6379/0` | Redis connection URL |
| `NATS_URL` | No | `nats://localhost:4222` | NATS message bus URL |
| `ENCRYPTION_KEY` | No | Derived from JWT_SECRET | Fernet encryption key (for API Key encrypted storage) |
| `MITMPROXY_URL` | No | `http://mitmproxy:8080` | mitmproxy proxy address |
| `CRAWLERGO_URL` | No | `http://crawlergo:7777` | crawlergo deep crawl API URL |
| `POC_SANDBOX_URL` | No | `http://poc-sandbox:9090` | PoC sandbox executor URL |
| `SIDECAR_SECRET` | No | - | Sidecar shared secret (for internal service authentication) |
| `TASK_TIMEOUT_SECONDS` | No | `3600` | Task execution global timeout (seconds) |
| `DEBUG` | No | `false` | Debug mode |
| `LOG_LEVEL` | No | `INFO` | Log level (DEBUG/INFO/WARNING/ERROR) |

## Development

### Local Development

```bash
# Start infrastructure (database, Redis, NATS)
docker compose up -d postgres redis nats

# Backend development (hot reload)
cd backend
pip install -e .
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend development (hot reload)
cd frontend
npm install
npm run dev
```

### Common Commands

```bash
make dev        # Start backend dev server (hot reload)
make migrate    # Run database migrations
make test       # Run test suite (with coverage)
make lint       # Code quality checks (ruff)
make format     # Code formatting
make build      # Build Docker images
make up         # Start all services
make down       # Stop all services
```

### Adding a New Tool

1. Create a tool file in `backend/app/tools/`, inheriting from `BaseTool`:

```python
from app.tools.base import BaseTool, ExecutionContext, RiskLevel

class MyNewTool(BaseTool):
    name = "my_tool"
    description = "Tool description"
    risk_level = RiskLevel.L1  # L0: read-only, L1: active probing, L2: exploit

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        # Implement tool logic
        return {"success": True, "data": result}
```

2. Register the tool in `backend/app/tools/__init__.py` in `_register_all_tools()`
3. Add tool description in `backend/app/agents/lats/prompts.py` for agent usage
4. Add execution logic in `backend/app/agents/lats/actions.py`

### Database Migrations

```bash
# Create new migration
cd backend && alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback one step
alembic downgrade -1
```

## Agent Workflow

```mermaid
graph TD
    A[Recon] -->|Collect target info| B[Init Tree]
    B --> C{MCTS Select Node}
    C -->|UCB strategy| D[Expand Candidates]
    D --> E[ReAct Execute]

    E --> F{Thought}
    F -->|Reason| G[Action: Select Tool]
    G --> H[Observation: Result]
    H -->|Continue| F
    H -->|Done/Backtrack| I[Compute Reward]

    I --> J[Backpropagate]
    J --> K{Termination?}
    K -->|Vuln confirmed| L[Reporter]
    K -->|Budget exhausted| L
    K -->|Continue search| C
    K -->|Branch exhausted| M[Prune]
    M --> C
```

## Tech Stack

### Backend
- **Framework**: FastAPI + Uvicorn
- **AI/Agent**: LangGraph (LATS + ReAct) + Anthropic Claude
- **Database**: PostgreSQL 16 + SQLAlchemy (async)
- **Cache**: Redis 7
- **Messaging**: NATS (JetStream)
- **Auth**: JWT (python-jose)
- **Migrations**: Alembic

### Frontend
- **Framework**: Next.js 15 (App Router)
- **UI**: React 19 + Tailwind CSS
- **State**: Zustand + TanStack Query
- **Icons**: Lucide React
- **Real-time**: WebSocket

## Security Notice

- Argus is intended for **authorized security testing only** (SRC vulnerability mining, authorized penetration testing)
- Ensure you have **written authorization** from the target before use
- PoC sandbox has multi-layer isolation, but long-term production deployment is not recommended
- Default JWT_SECRET is for development only — **must be changed in production**
- Configure a separate `ENCRYPTION_KEY` for API Key encrypted storage
- Database password should also use a **strong password in production**

## FAQ

**Q: Frontend not accessible after startup?**
A: Ensure all containers are healthy: `docker compose ps`. Frontend depends on backend, usually takes 30-60 seconds.

**Q: Agent doesn't perform any actions?**
A: Check if `ANTHROPIC_API_KEY` is configured correctly. View backend logs: `docker logs argus-backend --tail 100`.

**Q: PoC execution reports "Import not allowed"?**
A: Sandbox only allows: `requests`, `urllib3`, `base64`, `json`, `hashlib`, `re`, `time`, `socket`, `struct`, `urllib`, `http`, `collections`, `itertools`, `string`, `binascii`, `zlib`. Modify `ALLOWED_IMPORTS` in `poc-sandbox/sandbox_worker.py` to extend the whitelist.

**Q: crawlergo returns empty results?**
A: Target site may block Chromium. Check container logs: `docker logs argus-crawlergo --tail 50`.

**Q: How to increase search depth?**
A: Adjust LATS parameters in `backend/app/agents/lats/graph.py`: max tree depth, max steps per node, MCTS iteration count, etc.

## License

MIT License

---

<p align="center">
  <sub>Built with care for Security Researchers</sub>
</p>
