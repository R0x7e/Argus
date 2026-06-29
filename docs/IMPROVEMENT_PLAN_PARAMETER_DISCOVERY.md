# Argus 漏洞挖掘精准度与覆盖率全面改进方案

> 基于任务 `c30cb533` 深度根因分析的完整改进设计
> 状态: 设计阶段
> 覆盖: 参数发现、Recon增强、漏洞类型关联、晋升机制、预算优化、多端点探索

---

## 目录

1. [改进概览与问题-方案映射](#1-改进概览与问题-方案映射)
2. [方案A: 深层页面侦察引擎 (PageContentExtractor)](#2-方案a-深层页面侦察引擎-pagecontentextractor)
3. [方案B: 多源参数发现管线 (ParamDiscoveryPipeline)](#3-方案b-多源参数发现管线-paramdiscoverypipeline)
4. [方案C: 上下文感知漏洞类型分类器 (ContextAwareVulnClassifier)](#4-方案c-上下文感知漏洞类型分类器-contextawarevulnclassifier)
5. [方案D: 参数有效性预验证 (ParamExistenceValidator)](#5-方案d-参数有效性预验证-paramexistencevalidator)
6. [方案E: MultiLevelProber 晋升/终止逻辑重设计](#6-方案e-multilevelprober-晋升终止逻辑重设计)
7. [方案F: 跨类型动态扩展引擎 (CrossTypeExpansionEngine)](#7-方案f-跨类型动态扩展引擎-crosstypeexpansionengine)
8. [方案G: 智能预算分配与僵尸节点清理](#8-方案g-智能预算分配与僵尸节点清理)
9. [方案H: 节点复活与类型重评估机制](#9-方案h-节点复活与类型重评估机制)
10. [方案I: 多端点攻击面初始化](#10-方案i-多端点攻击面初始化)
11. [LangGraph 图结构最终变更](#11-langgraph-图结构最终变更)
12. [实施优先级与依赖关系](#12-实施优先级与依赖关系)

---

## 1. 改进概览与问题-方案映射

| # | 根因 | 严重度 | 方案 | 核心变更 |
|---|------|--------|------|----------|
| R1 | `_infer_params_from_url` 参数推断失败 | **致命** | B + C | 多源参数发现管线 + 上下文感知分类器 |
| R2 | Recon 阶段未解析页面表单 | **致命** | A | 新增 PageContentExtractor 深层侦察 |
| R3 | 参数→漏洞类型关联断裂 | **致命** | C + F | 上下文感知分类 + 跨类型扩展引擎 |
| R4 | MultiLevelProber 晋升完全失效 | **严重** | D + E | 参数验证 + 晋升/终止阈值重设计 |
| R5 | Token 预算浪费在僵尸节点 | **严重** | G + H | 智能预算分配 + 节点复活机制 |
| R6 | 单页面聚焦，忽略多端点 | **中等** | I | 多端点攻击面初始化 |

---

## 2. 方案A: 深层页面侦察引擎 (PageContentExtractor)

### 2.1 问题

当前 Recon 阶段只做目录扫描 (HTTP HEAD/GET 确认存在性)，**不获取和解析页面内容**。导致 `forms_found=0, pages_crawled=0, params_found=0`。

### 2.2 设计

新增 `PageContentExtractor` 组件，在 Recon 阶段对目标端点及其可达页面进行深度内容提取。

```python
# 新文件: backend/app/core/page_content_extractor.py

@dataclass
class PageContent:
    """页面内容解析结果"""
    url: str
    status_code: int
    html_size: int
    title: str = ""
    # 表单
    forms: list[FormInfo] = field(default_factory=list)
    # 所有 input/select/textarea 参数
    input_params: list[str] = field(default_factory=list)
    # JavaScript 中提取的端点
    js_endpoints: list[str] = field(default_factory=list)
    # <a> 链接（用于递归爬取）
    links: list[str] = field(default_factory=list)
    # 注释中的线索
    html_comments: list[str] = field(default_factory=list)
    # 页面类型标记
    page_type: str = "unknown"  # login, form, api_doc, error, static, normal


class PageContentExtractor:
    """
    深层页面侦察引擎

    核心职责:
    1. 使用 Playwright 渲染目标页面 (SPA 兼容)
    2. 提取 HTML 表单、input 参数、JS 端点
    3. 递归爬取可达链接 (可控深度)
    4. 将提取结果写入 SharedKnowledge + attack_surface
    """

    def __init__(self, playwright_manager, max_depth: int = 2, max_pages: int = 20):
        self._browser = playwright_manager
        self._max_depth = max_depth
        self._max_pages = max_pages

    async def extract(
        self, url: str, context: ExecutionContext
    ) -> list[PageContent]:
        """
        深度提取目标页面及其可达子页面的内容。
        返回按爬取顺序排列的页面内容列表。
        """
        # 1. 打开浏览器页面
        # 2. 渲染并等待 JS 执行完成
        # 3. 提取: 表单 / input参数 / JS端点 / 链接 / 注释
        # 4. 去重后递归爬取链接 (max_depth 限制)
        # 5. 汇总返回
        ...

    def _extract_forms_v2(self, html: str, page_url: str) -> list[FormInfo]:
        """
        增强版表单提取 (替代 orchestrator._extract_forms):
        - 正则提取 <form> 块
        - 提取所有 <input>/<textarea>/<select> 的 name 属性
        - 推断表单用途 (login/search/upload/command)
        - 记录 method (GET/POST) 和 action
        """
        ...

    def _classify_page_type(self, content: PageContent) -> str:
        """
        页面类型分类:
        - login: 包含 password 类型 input
        - form: 包含非 hidden 的 input
        - api_doc: 包含大量 JSON/endpoint 描述
        - error: 状态码 4xx/5xx
        - static: 纯 HTML 无交互元素
        - normal: 默认
        """
        ...
```

### 2.3 Recon 阶段集成

修改 `lats_recon_node` (graph.py:106)，在 Recon 完成后强制调用 `PageContentExtractor`:

```python
# graph.py lats_recon_node 变更

async def lats_recon_node(state: dict) -> dict:
    # ... 现有侦察逻辑 (目录扫描、子域名枚举等) ...

    # [新增] 深层页面内容提取
    extractor = PageContentExtractor(
        playwright_manager=bb.playwright_manager,
        max_depth=2,
        max_pages=20,
    )
    page_contents = await extractor.extract(target_url, exec_ctx)

    # [新增] 将表单参数注入 attack_surface
    for pc in page_contents:
        for form in pc.forms:
            for param_name in form.params:
                attack_surface.add_param(
                    endpoint=pc.url,
                    param_name=param_name,
                    source="form_extraction",
                    form_method=form.method,
                    form_action=form.action,
                )

    # [新增] 将 JS 端点注入
    for pc in page_contents:
        for js_ep in pc.js_endpoints:
            attack_surface.add_endpoint(
                url=js_ep,
                source="js_extraction",
            )

    return {
        **state,
        "page_contents": page_contents,  # 供后续节点使用
        "attack_surface": attack_surface,
        ...
    }
```

### 2.4 预期效果

- Pikachu `rce_ping.php` 的表单 `<input name="ipaddress">` + `<input name="submit">` 将在 Recon 阶段被发现
- `forms_found` 从 0 变为 >=1
- `params_found` 从 0 变为包含 `ipaddress` 和 `submit`
- 不再依赖 URL 文件名猜测参数

---

## 3. 方案B: 多源参数发现管线 (ParamDiscoveryPipeline)

### 3.1 问题

`_infer_params_from_url` (graph.py:257-313) 是**唯一**的参数发现来源。它仅通过 URL 文件名分词匹配固定映射表——覆盖范围极其有限。

### 3.2 设计

将参数发现从一个函数升级为**多源融合管线**:

```python
# 新文件: backend/app/core/param_discovery.py

@dataclass
class ParamCandidate:
    """参数候选项"""
    name: str
    vuln_types: list[str]           # 关联的漏洞类型
    confidence: float               # 置信度 0.0-1.0
    source: str                     # 来源标记
    source_detail: str = ""         # 来源详情
    endpoint: str = ""              # 所属端点


class ParamDiscoveryPipeline:
    """
    多源参数发现管线

    按优先级融合以下来源:
    1. 【最高优先级】Form Extraction — 页面 HTML 表单直接提取 (confidence=1.0)
    2. 【高优先级】 URL Query String — URL 自带查询参数 (confidence=0.95)
    3. 【中优先级】 JS Endpoint Extraction — JS 文件中的 API 调用 (confidence=0.7)
    4. 【中优先级】 LLM Semantic Inference — LLM 根据页面内容推断隐含参数 (confidence=0.6)
    5. 【低优先级】 URL Filename Heuristic — 文件名分词映射 (confidence=0.3)
    6. 【最低优先级】 Generic Fallback — 通用参数补充 (confidence=0.1)
    """

    def __init__(self, llm_client: LLMClient | None = None):
        self._llm = llm_client
        self._param_hints = _build_extended_param_hints()

    async def discover(
        self,
        url: str,
        page_contents: list[PageContent] | None = None,
        shared_knowledge: SharedKnowledge | None = None,
    ) -> list[ParamCandidate]:
        """
        融合所有来源，返回去重排序后的参数候选列表。
        """
        candidates: list[ParamCandidate] = []

        # 来源1: 表单提取 (最高置信度)
        if page_contents:
            candidates.extend(self._from_forms(page_contents))

        # 来源2: URL 查询参数
        candidates.extend(self._from_url_query(url))

        # 来源3: JS 端点提取
        if page_contents:
            candidates.extend(self._from_js_endpoints(page_contents))

        # 来源4: LLM 语义推断 (仅在表单/查询参数为空时触发)
        if not candidates and self._llm:
            llm_params = await self._from_llm_inference(url, page_contents)
            candidates.extend(llm_params)

        # 来源5: URL 文件名启发式 (降级为低置信度)
        heuristic_params = self._from_url_heuristic(url)
        for hp in heuristic_params:
            # 如果已有同名校验过的参数，跳过
            if not any(c.name == hp.name and c.confidence > 0.5 for c in candidates):
                hp.confidence = 0.3  # 降低置信度
                candidates.append(hp)

        # 来源6: 通用参数补充 (仅在没有其他来源时)
        if not candidates:
            candidates.extend(self._generic_fallback(url))

        return self._deduplicate_and_sort(candidates)

    async def _from_llm_inference(
        self, url: str, page_contents: list[PageContent] | None
    ) -> list[ParamCandidate]:
        """
        使用 LLM 根据页面上下文推断可能的隐藏参数。

        输入:
        - 页面标题、表单结构、页面文本片段 (2000 字符)
        - URL 路径语义

        输出 (JSON):
        [
          {"param_name": "ipaddress", "reasoning": "页面提示输入IP地址，表单name为ipaddress", "vuln_types": ["rce", "ssrf"]},
          {"param_name": "submit", "reasoning": "表单提交按钮", "vuln_types": []}
        ]
        """
        ...

    def _from_forms(self, page_contents: list[PageContent]) -> list[ParamCandidate]:
        """从页面表单提取参数 (confidence=1.0)"""
        ...

    def _from_url_query(self, url: str) -> list[ParamCandidate]:
        """从 URL 查询字符串提取参数 (confidence=0.95)"""
        ...

    def _from_js_endpoints(self, page_contents: list[PageContent]) -> list[ParamCandidate]:
        """从 JS 文件提取 API 端点参数 (confidence=0.7)"""
        ...

    def _from_url_heuristic(self, url: str) -> list[ParamCandidate]:
        """扩展版 URL 文件名启发式 (原 _infer_params_from_url 的增强版)"""
        # 扩展映射表，增加更多关键词
        ...

    def _generic_fallback(self, url: str) -> list[ParamCandidate]:
        """通用参数回退 (极低置信度，仅在无其他来源时使用)"""
        ...

    def _deduplicate_and_sort(
        self, candidates: list[ParamCandidate]
    ) -> list[ParamCandidate]:
        """
        去重 + 排序:
        - 同名参数保留最高置信度的来源
        - 按 confidence × vuln_type_priority 降序排列
        """
        ...
```

### 3.3 扩展版参数映射表

```python
def _build_extended_param_hints() -> dict[str, dict]:
    """
    原 _infer_params_from_url 的 param_hints 扩展版

    新增覆盖:
    - URL 路径关键词 → 参数名
    - 中文拼音关键词
    - 框架特定参数
    - 通用命名约定
    """
    return {
        # === RCE 相关 ===
        "cmd":    {"params": ["cmd", "command", "exec"],     "vuln_types": ["rce"]},
        "exec":   {"params": ["cmd", "command", "exec"],     "vuln_types": ["rce"]},
        "ping":   {"params": ["ip", "host", "ipaddress", "address", "target"],
                   "vuln_types": ["rce", "ssrf"]},              # ← 新增！
        "shell":  {"params": ["cmd", "command"],              "vuln_types": ["rce"]},
        "run":    {"params": ["cmd", "command", "script"],    "vuln_types": ["rce"]},
        "eval":   {"params": ["code", "expression"],          "vuln_types": ["rce"]},

        # === 文件操作相关 ===
        "file":       {"params": ["file", "filename", "path"],     "vuln_types": ["lfi", "path_traversal"]},
        "upload":     {"params": ["file", "filename", "image"],    "vuln_types": ["file_upload", "rce"]},
        "download":   {"params": ["file", "filename", "path"],     "vuln_types": ["path_traversal"]},
        "include":    {"params": ["file", "page", "include"],      "vuln_types": ["lfi"]},
        "image":      {"params": ["file", "url", "src"],           "vuln_types": ["ssrf", "lfi"]},

        # === 认证/用户相关 ===
        "login":   {"params": ["username", "user", "password", "passwd", "pwd"],
                    "vuln_types": ["auth_bypass", "sql_injection"]},
        "user":    {"params": ["id", "user", "username", "uid"],   "vuln_types": ["idor", "auth_bypass"]},
        "admin":   {"params": ["id", "user", "token"],             "vuln_types": ["auth_bypass"]},
        "token":   {"params": ["token", "jwt", "auth"],            "vuln_types": ["auth_bypass"]},

        # === 数据查询相关 ===
        "search":  {"params": ["q", "query", "search", "keyword"], "vuln_types": ["xss", "sql_injection"]},
        "query":   {"params": ["q", "query", "id"],                "vuln_types": ["sql_injection", "xss"]},
        "id":      {"params": ["id", "uid", "user_id"],            "vuln_types": ["idor", "sql_injection", "xss"]},
        "list":    {"params": ["page", "limit", "offset", "order"], "vuln_types": ["idor", "sql_injection"]},

        # === 页面/模板相关 ===
        "page":    {"params": ["page", "p", "template"],           "vuln_types": ["lfi", "path_traversal"]},
        "url":     {"params": ["url", "link", "redirect", "next"],  "vuln_types": ["ssrf", "open_redirect"]},
        "redirect":{"params": ["url", "redirect", "next", "to"],    "vuln_types": ["open_redirect"]},
        "proxy":   {"params": ["url", "target", "host"],           "vuln_types": ["ssrf"]},

        # === 通用 ===
        "name":    {"params": ["name", "title", "subject"],        "vuln_types": ["xss", "sql_injection"]},
        "form":    {"params": [],                                   "vuln_types": ["xss", "sql_injection", "auth_bypass"]},
        "api":     {"params": ["id", "q", "page"],                  "vuln_types": ["idor", "sql_injection"]},
    }
```

### 3.4 调用点变更

在 `lats_init_tree_node` (graph.py:400) 中替换原有参数发现调用:

```python
# 旧:
# params = _infer_params_from_url(endpoint)

# 新:
pipeline = ParamDiscoveryPipeline(llm_client=_get_llm_client(task_id))
param_candidates = await pipeline.discover(
    url=endpoint,
    page_contents=state.get("page_contents"),
    shared_knowledge=state.get("shared_knowledge"),
)
# 只取置信度 >= 0.3 的参数作为种子
seeds = [pc for pc in param_candidates if pc.confidence >= 0.3]
```

---

## 4. 方案C: 上下文感知漏洞类型分类器 (ContextAwareVulnClassifier)

### 4.1 问题

当前参数→漏洞类型的关联存在两处断裂:
1. **初始化阶段**: `_infer_params_from_url` 的 `param_hints` 表将参数名映射到 vuln_types——映射表不完整
2. **扩展阶段**: `ExpansionEngine` 的子节点直接**继承父节点的 vuln_type**——即使新发现的参数应该关联到完全不同的漏洞类型

例如: 在 `auth_bypass` 节点中发现参数 `ipaddress`，子节点被标记为 `auth_bypass`——但它应该是 `rce`。

### 4.2 设计

新增独立的分类器组件，综合 URL 语义、参数语义、页面上下文三维信息。

```python
# 新文件: backend/app/core/vuln_classifier.py

@dataclass
class VulnTypeScore:
    vuln_type: str
    score: float         # 0.0-1.0
    reasoning: str       # 分类理由


class ContextAwareVulnClassifier:
    """
    上下文感知漏洞类型分类器

    输入三维信息:
    1. URL 语义: 路径片段 (/vul/rce/rce_ping.php → rce)
    2. 参数语义: 参数名含义 (ipaddress → rce, ssrf)
    3. 页面上下文: 页面标题/表单标签/提示文本
    """

    # URL 路径片段 → 漏洞类型的强信号映射
    URL_VULN_SIGNALS: dict[str, list[str]] = {
        "rce":     ["rce"],
        "sqli":    ["sql_injection"],
        "sql":     ["sql_injection"],
        "xss":     ["xss"],
        "ssrf":    ["ssrf"],
        "lfi":     ["lfi"],
        "fileinclude": ["lfi", "path_traversal"],
        "upload":  ["file_upload"],
        "csrf":    ["csrf"],
        "idor":    ["idor"],
        "burteforce": ["auth_bypass"],
        "overpermission": ["idor", "auth_bypass"],
        "xxe":     ["xxe"],
        "unser":   ["deserialization"],
        "ssti":    ["ssti"],
    }

    # 参数名 → 漏洞类型的强信号映射
    PARAM_VULN_SIGNALS: dict[str, list[str]] = {
        "ipaddress": ["rce", "ssrf"],
        "ip":        ["rce", "ssrf"],
        "host":      ["rce", "ssrf"],
        "target":    ["rce", "ssrf"],
        "cmd":       ["rce"],
        "command":   ["rce"],
        "exec":      ["rce"],
        "code":      ["rce", "ssti"],
        "file":      ["lfi", "path_traversal", "file_upload"],
        "filename":  ["lfi", "path_traversal"],
        "path":      ["lfi", "path_traversal"],
        "url":       ["ssrf", "open_redirect"],
        "link":      ["ssrf", "open_redirect"],
        "redirect":  ["open_redirect"],
        "id":        ["idor", "sql_injection", "xss"],
        "uid":       ["idor"],
        "user_id":   ["idor"],
        "q":         ["xss", "sql_injection"],
        "query":     ["xss", "sql_injection"],
        "search":    ["xss", "sql_injection"],
        "keyword":   ["xss", "sql_injection"],
        "name":      ["xss", "sql_injection"],
        "username":  ["auth_bypass", "sql_injection"],
        "password":  ["auth_bypass"],
        "token":     ["auth_bypass"],
        "submit":    [],  # 提交按钮，无直接漏洞关联
    }

    @classmethod
    def classify(
        cls,
        url: str,
        param_name: str,
        parent_vuln_type: str | None = None,
        page_content: PageContent | None = None,
        shared_knowledge: SharedKnowledge | None = None,
    ) -> list[VulnTypeScore]:
        """
        分类入口: 融合三维信号，返回排序后的漏洞类型得分列表。

        核心逻辑:
        1. URL 语义得分 (weight=0.40)
        2. 参数语义得分 (weight=0.40)
        3. 页面上下文得分 (weight=0.15)
        4. 父节点类型调整 (weight=0.05)
        """
        scores: dict[str, float] = {}

        # 1. URL 语义
        url_signals = cls._extract_url_vuln_signals(url)
        for vt, weight in url_signals:
            scores[vt] = scores.get(vt, 0) + weight * 0.40

        # 2. 参数语义
        param_signals = cls.PARAM_VULN_SIGNALS.get(param_name.lower(), [])
        if not param_signals:
            # 参数名不在映射表中→尝试LLM推断
            param_signals = cls._infer_param_vuln_types(param_name)
        for vt in param_signals:
            scores[vt] = scores.get(vt, 0) + 0.40 / max(len(param_signals), 1)

        # 3. 页面上下文
        if page_content:
            ctx_signals = cls._extract_page_context_signals(page_content)
            for vt, weight in ctx_signals:
                scores[vt] = scores.get(vt, 0) + weight * 0.15

        # 4. 父节点类型 (微弱调整)
        if parent_vuln_type and parent_vuln_type not in scores:
            scores[parent_vuln_type] = 0.05

        # 排序返回
        sorted_scores = sorted(
            [VulnTypeScore(vt, min(s, 1.0), cls._build_reasoning(vt, param_name, url))
             for vt, s in scores.items()],
            key=lambda x: x.score, reverse=True,
        )
        return sorted_scores

    @classmethod
    def _extract_url_vuln_signals(cls, url: str) -> list[tuple[str, float]]:
        """
        从 URL 路径中提取漏洞类型信号。
        路径越具体，信号越强。

        例如:
        /vul/rce/rce_ping.php → [("rce", 0.9)]  # 强信号
        /api/user/info         → []                # 无信号
        """
        import re
        path = url.split("?")[0].lower()
        segments = re.split(r'[/_.-]', path)

        signals = []
        for seg in segments:
            if seg in cls.URL_VULN_SIGNALS:
                # 信号强度与路径深度和匹配次数相关
                strength = 0.7 + 0.1 * min(segments.count(seg), 3)
                for vt in cls.URL_VULN_SIGNALS[seg]:
                    signals.append((vt, strength))
        return signals

    @classmethod
    def _extract_page_context_signals(
        cls, page_content: PageContent
    ) -> list[tuple[str, float]]:
        """从页面标题/表单标签/提示文本中提取漏洞类型信号"""
        ...

    @classmethod
    def _infer_param_vuln_types(cls, param_name: str) -> list[str]:
        """当参数名不在映射表中时，使用启发式规则推断"""
        ...
```

### 4.3 调用点变更

**初始化阶段** (graph.py `lats_init_tree_node`):
```python
# 旧: vuln_types 直接来自 param_hints 表
# 新:
classifier = ContextAwareVulnClassifier()
for param in param_candidates:
    vuln_scores = classifier.classify(
        url=endpoint,
        param_name=param.name,
        page_content=pc_for_url,
    )
    # 取 score >= 0.3 的类型创建节点
    for vs in vuln_scores:
        if vs.score >= 0.3:
            tree.create_node(param=param.name, vuln_type=vs.vuln_type, ...)
```

**扩展阶段** (expansion_engine.py):
```python
# 旧: child.vuln_type = parent.vuln_type (直接继承)
# 新:
for discovery in new_discoveries:
    vuln_scores = ContextAwareVulnClassifier.classify(
        url=discovery.endpoint,
        param_name=discovery.param_name,
        parent_vuln_type=parent.vuln_type,  # 仅作为弱信号
        page_content=page_content_for_url,
    )
    # 为 score >= 0.3 的每种类型创建独立的子节点
    for vs in vuln_scores:
        if vs.score >= 0.3:
            tree.add_child(parent, vuln_type=vs.vuln_type, ...)
```

---

## 5. 方案D: 参数有效性预验证 (ParamExistenceValidator)

### 5.1 问题

当前 MultiLevelProber 的 Level 0 分类规则 (DESIGN_SEARCH_ARCHITECTURE.md 4.5节) 存在一个逻辑漏洞:

```
IF |probe_len - baseline_len| == 0 for all probes
   AND probe_status == baseline_status
   AND no anomaly detected
   → KILLED (端点对参数完全无响应)
```

但实际上，当参数**在应用后端根本不存在**时(如 `cmd` 参数在 Pikachu RCE 页面)，探测结果也是"全无差异"。当前实现将这种情况错误地归类为 `LOW_SIGNAL` (保留但不晋升) 而非 `KILLED`。这导致了 78 个僵尸节点在 8 个周期中累积。

### 5.2 设计

在 Level 0 探测之前，先执行参数**存在性验证** —— 测试该参数名是否被后端实际处理。

```python
# 新文件: backend/app/core/param_existence_validator.py

@dataclass
class ExistenceResult:
    param_name: str
    exists: bool
    confidence: float
    evidence: str
    recommended_alternatives: list[str]  # 如果不存在，建议替代参数名


class ParamExistenceValidator:
    """
    参数存在性预验证器

    对猜测出的参数名进行快速验证，判断其是否被后端实际处理。
    使用零 LLM 调用的纯 HTTP 探测。
    """

    async def validate(
        self, url: str, param_name: str, context: ExecutionContext
    ) -> ExistenceResult:
        """
        三步验证法:
        1. 发送空值 vs 随机垃圾值 → 观察响应差异
        2. 发送极端长值 vs 正常值 → 观察截断/错误
        3. 如果 param_name 可能是同义词，尝试变体检测

        返回: 参数是否存在 + 置信度
        """

    async def suggest_alternatives(
        self, url: str, failed_param: str, page_content: PageContent | None
    ) -> list[str]:
        """
        当参数被判定为不存在时，从页面上下文中建议替代参数名。
        利用:
        - 页面 HTML 中的 name 属性
        - LLM 语义推断 (仅在此处使用 LLM，且仅 1 次调用)
        """
```

### 5.3 Level 0 探测增强

整合进 MultiLevelProber 的 Level 0:

```
增强后 Level 0 流程:
  步骤 0: 参数存在性验证 [新增]
    → 发送 3 组探测请求测试参数是否存在
    → IF 参数不存在:
        → 尝试 suggest_alternatives 找到正确参数
        → IF 找到替代参数:
            → 以替代参数创建新 SEED 节点 (vuln_type 保持)
            → 当前节点 KILLED_WITH_REDIRECT
        → ELSE:
            → KILLED_PARAM_NOT_FOUND

  步骤 1: 基线请求 (不变)
  步骤 2: 探测字符注入 (不变)
  步骤 3: 通用 payload 注入 (不变)

  分类规则增强:
    IF KILLED_PARAM_NOT_FOUND:
      → 不是进入 LOW_SIGNAL，而是真的 KILLED
      → 但保留在 Graveyard 中，当相同 endpoint 发现新参数时可复活
```

### 5.4 关键: 不存在参数的节点必须被 KILL

```python
# multi_level_prober.py 中的变更

def _classify_level0_result(self, result: Level0ProbeResult) -> NodeStatus:
    """
    增强版 Level 0 分类
    """
    # [新增] 参数不存在 → 直接 KILL (不走 LOW_SIGNAL)
    if result.existence_check and not result.existence_check.exists:
        if result.existence_check.recommended_alternatives:
            # 记录替代参数到节点 metadata 供 ExpansionEngine 使用
            return NodeStatus.KILLED_PARAM_NOT_FOUND
        return NodeStatus.KILLED_PARAM_NOT_FOUND

    # 原有规则 (但阈值更严格)
    if result.baseline_status == 404:
        return NodeStatus.KILLED

    # 全无差异 → KILLED (不再进 LOW_SIGNAL)
    if (result.all_probes_baseline and not result.any_anomaly):
        return NodeStatus.KILLED_NO_RESPONSE

    # 有信号 → PROMOTED
    if (result.status_differs or result.len_differs or result.time_anomaly):
        return NodeStatus.PROMOTED

    return NodeStatus.KILLED
```

---

## 6. 方案E: MultiLevelProber 晋升/终止逻辑重设计

### 6.1 问题

原 Level 0 分类规则的 `ELSE → KILLED` 分支在代码实现中实际映射到了 `LOW_SIGNAL`——导致 `killed=0, promoted=0` 但 `low_signal=78`。晋升管道完全堵塞。

### 6.2 新分类规则表

| 条件 | 原行为 | 新行为 | 理由 |
|------|--------|--------|------|
| 参数不存在 (方案D验证) | LOW_SIGNAL | **KILLED_PARAM_NOT_FOUND** | 猜测的参数无效→不应保留 |
| 端点 404 | KILLED | KILLED | 不变 |
| 全无差异 + 无异常 | LOW_SIGNAL | **KILLED_NO_RESPONSE** | 参数存在但无任何响应差异→死路 |
| 响应长度差异 > 5% | PROMOTED | PROMOTED | 不变 |
| 响应状态码差异 | PROMOTED | PROMOTED | 不变 |
| 响应时间异常 > 2000ms | PROMOTED | PROMOTED | 不变 |
| WAF 指纹检测到 | PROMOTED | PROMOTED + 同时创建 bypass 子节点 | 增强: WAF→自动创建 bypass 探索分支 |
| 响应体包含已知漏洞关键词 | LOW_SIGNAL | **PROMOTED_HIGH** | 增强: 强信号直接高优先级 |
| 错误消息泄漏 | LOW_SIGNAL | **PROMOTED** | 增强 |

### 6.3 僵尸节点自动清理

```python
# 在 evaluate_node 中新增僵尸节点检测

def _prune_zombie_nodes(tree: SearchTree, max_zombie_ratio: float = 0.6) -> int:
    """
    僵尸节点定义:
    - 状态为 LOW_SIGNAL 或 SEED
    - 连续 3 个周期未被选中
    - value == 0.0 且 visits == 0

    清理策略:
    - 保留在 Graveyard (可复活)
    - 释放相关资源配额
    - 每周期最多清理 total_nodes × 0.3 个
    """
    ...
```

---

## 7. 方案F: 跨类型动态扩展引擎 (CrossTypeExpansionEngine)

### 7.1 问题

当前 `ExpansionEngine` 的子节点创建逻辑:

```python
# expansion_engine.py 当前逻辑 (推断)
child = SearchNode(
    vuln_type=parent.vuln_type,  # ← 直接继承, 问题根源
    param=discovered_param,
    ...
)
```

这导致发现 `ipaddress` 时，如果父节点是 `auth_bypass`，子节点也只能是 `auth_bypass`。

### 7.2 设计

扩展引擎不再简单继承，而是对每个发现调用 `ContextAwareVulnClassifier`:

```python
# expansion_engine.py 变更

async def _create_expansion_nodes(
    self, parent: SearchNode, discoveries: list[Discovery],
    tree: SearchTree, url: str, page_content: PageContent | None,
) -> list[SearchNode]:
    """
    跨类型扩展: 为每个发现创建多种漏洞类型的子节点。
    """
    new_nodes = []

    for disc in discoveries:
        # 调用分类器获取所有相关的漏洞类型
        vuln_scores = ContextAwareVulnClassifier.classify(
            url=url,
            param_name=disc.param_name or "",
            parent_vuln_type=parent.vuln_type,  # 仅作弱参考
            page_content=page_content,
        )

        # 为 score >= 0.3 的每种类型创建独立节点
        created_count = 0
        for vs in vuln_scores:
            if vs.score < 0.3 or created_count >= 3:
                break

            # 去重检查: 同类型+同参数+同endpoint 是否已存在
            if tree.has_node(vuln_type=vs.vuln_type, param=disc.param_name, endpoint=url):
                continue

            node = tree.add_child(
                parent=parent,
                vuln_type=vs.vuln_type,
                param=disc.param_name,
                endpoint=url,
                status=NodeStatus.SEED,
                prior_value=vs.score * 0.5,  # 分类器得分转化先验价值
                metadata={
                    "source": "cross_type_expansion",
                    "classifier_score": vs.score,
                    "classifier_reasoning": vs.reasoning,
                },
            )
            new_nodes.append(node)
            created_count += 1

    return new_nodes
```

**效果**: 在 Pikachu 案例中，当 `auth_bypass` 节点发现表单参数 `ipaddress` 后，ExpansionEngine 会调用分类器，分类器根据:
- URL 语义: `/vul/rce/rce_ping.php` → rce (score=0.9)
- 参数语义: `ipaddress` → rce + ssrf (score=0.8)

创建两个子节点: `vuln_type=rce, param=ipaddress` 和 `vuln_type=ssrf, param=ipaddress`。**RCE 节点终于有了正确的参数。**

---

## 8. 方案G: 智能预算分配与僵尸节点清理

### 8.1 问题

500K token 预算在 8 个周期中消耗殆尽，其中:
- 约 60% 的 LLM 调用发生在无信号的僵尸节点上
- ReAct step 0 每次消耗 ~2,000 tokens (system prompt + user prompt)
- 每个 react_step LLM 调用平均 ~2,500 tokens (上下文不断累积)

### 8.2 分级预算分配

```python
# 增强 token_budget.py

class TieredBudgetManager:
    """
    分级预算管理器

    将总预算按优先级分配:
    ┌─────────────────┬──────────┬─────────────────────────────┐
    │ 层级             │ 占比     │ 用途                        │
    ├─────────────────┼──────────┼─────────────────────────────┤
    │ TIER_1 (PROMOTED)│   50%    │ 已验证有信号的节点深度探索   │
    │ TIER_2 (HIGH_SIG)│   25%    │ 高置信度信号 → Full ReAct   │
    │ TIER_3 (SEED)    │   15%    │ 新种子节点 Level 0/1 探测   │
    │ TIER_4 (RESERVE) │   10%    │ 预留: 发现新参数/复活节点    │
    └─────────────────┴──────────┴─────────────────────────────┘

    每个 Tier 独立追踪消耗，超限则暂停该 Tier 的 LLM 调用。
    """

    def can_allocate(self, tier: str, estimated_tokens: int) -> bool:
        """检查指定层级是否还有剩余配额"""
        ...

    def allocate(self, tier: str, actual_tokens: int) -> None:
        """记录实际消耗"""
        ...
```

### 8.3 ReAct 上下文共享 (Token 节省)

```python
# react_executor.py 变更

class SharedReactContext:
    """
    同 endpoint 的多个 ReAct Agent 共享基础上下文。

    当前: 每个 ReAct Agent 的 system prompt 包含完整的侦察结果 (~800 tokens)
    优化: 将侦察结果移到共享上下文，各 Agent 只引用不重复传输
    """

    def __init__(self, endpoint_url: str, recon_summary: str):
        self.endpoint_url = endpoint_url
        self.recon_summary = recon_summary  # 只传一次
        self.waf_discoveries: list[str] = []    # 累积的 WAF 发现
        self.param_behaviors: dict[str, dict] = {}  # 参数行为缓存

    def build_prompt(self, node_specific: dict) -> str:
        """
        构建精简 prompt:
        - 共享上下文只包含端点摘要 (200 tokens)
        - 节点特定信息包含参数+漏洞类型+当前步骤 (300 tokens)
        - 总 prompt 从 ~2,500 → ~500 tokens
        """
        ...
```

### 8.4 成本预估

```
优化前 (500K budget, 166 calls):
  平均每次: 500,000 / 166 ≈ 3,012 tokens/call
  实际有用调用: ~64 (3个finding的react = ~12 + 种子探测~52)
  浪费比例: ~61%

优化后:
  分级预算确保 50% 用于 PROMOTED 节点
  prompt 压缩: 3,012 → 800 tokens/call
  同等预算可支持: 500,000 / 800 ≈ 625 次有效调用 (3.7x)
```

---

## 9. 方案H: 节点复活与类型重评估机制

### 9.1 问题

搜索树中 RCE 节点 (`vuln_type=rce, param=cmd`) 在 Cycle 1 被标记为 `exhausted`，价值 -0.370，8 个周期中从未被重新考虑。即使后期发现了正确的 `ipaddress` 参数，该节点也永远死了。

### 9.2 设计

```python
# search_tree.py 新增

class NodeResurrectionEngine:
    """
    节点复活引擎

    触发条件: SharedKnowledge 出现新信息时，检查 Graveyard 中的节点是否值得复活。

    复活规则:
    1. 同 endpoint + 同 vuln_type → 新参数被发现 → 复活并更换参数
    2. 同 endpoint + 同参数 → 新 vuln_type 信号 → 复活并追加类型
    3. 同 endpoint → WAF 绕过被发现 → 复活并附带绕过方法
    """

    def check_resurrection(
        self,
        graveyard: list[SearchNode],
        new_discoveries: list[Discovery],
        shared_knowledge: SharedKnowledge,
        tree: SearchTree,
    ) -> list[SearchNode]:
        """
        检查 Graveyard 节点是否可以复活。

        核心逻辑 (以 Pikachu 案例为例):
        - Graveyard 中有: vuln_type=rce, param=cmd, endpoint=rce_ping.php (exhausted)
        - 新发现: param=ipaddress 来自表单解析
        - 复活: 创建 vuln_type=rce, param=ipaddress, endpoint=rce_ping.php (新节点)
        - 原 exhausted 节点标记为 KILLED_WRONG_PARAM (不再尝试复活)
        """
        resurrected = []

        for dead_node in graveyard:
            # 条件1: 死因是"参数不存在"或"全无响应"
            if dead_node.status not in (
                NodeStatus.EXHAUSTED,
                NodeStatus.KILLED_NO_RESPONSE,
                NodeStatus.KILLED_PARAM_NOT_FOUND,
            ):
                continue

            # 条件2: 同一 endpoint 有新参数被发现
            new_params_for_endpoint = [
                d for d in new_discoveries
                if d.endpoint == dead_node.endpoint
                and d.type == DiscoveryType.NEW_PARAM
            ]

            if not new_params_for_endpoint:
                continue

            # 条件3: 新参数与该节点的 vuln_type 相关
            for disc in new_params_for_endpoint:
                vuln_scores = ContextAwareVulnClassifier.classify(
                    url=dead_node.endpoint,
                    param_name=disc.param_name,
                )
                matching = [vs for vs in vuln_scores
                          if vs.vuln_type == dead_node.vuln_type and vs.score >= 0.5]

                if matching:
                    # 复活! 用正确的参数创建新节点
                    new_node = tree.add_child(
                        parent=dead_node.parent,  # 挂回原父节点
                        vuln_type=dead_node.vuln_type,
                        param=disc.param_name,
                        endpoint=dead_node.endpoint,
                        status=NodeStatus.SEED,
                        prior_value=matching[0].score * 0.7,
                        metadata={
                            "resurrected_from": dead_node.id,
                            "resurrection_reason": f"新参数 {disc.param_name} 匹配 {dead_node.vuln_type}",
                        },
                    )
                    resurrected.append(new_node)
                    break

        return resurrected
```

### 9.3 调用时机

在 `lats_expand_node` (graph.py:989) 的 ExpansionEngine 执行之后:

```python
async def lats_expand_node(state: dict) -> dict:
    # ... 现有扩展逻辑 ...

    # [新增] Graveyard 复活检查
    resurrection_engine = NodeResurrectionEngine()
    resurrected = resurrection_engine.check_resurrection(
        graveyard=tree.graveyard,
        new_discoveries=discoveries,
        shared_knowledge=knowledge,
        tree=tree,
    )

    if resurrected:
        emit("nodes_resurrected", {
            "count": len(resurrected),
            "nodes": [n.to_dict() for n in resurrected],
        })

    return {
        **state,
        "tree": tree,
        "resurrected_nodes": resurrected,
    }
```

---

## 10. 方案I: 多端点攻击面初始化

### 10.1 问题

当前 `lats_init_tree_node` 只围绕**单个**目标 URL 创建攻击面。任务 `c30cb533` 中 Recon 发现了 123 个目录/页面（覆盖 Pikachu 的全部功能），但搜索树只聚焦于 `rce_ping.php`。

这意味着:
- SQL 注入端点 (`sqli_id.php`, `sqli_str.php` 等) 从未被探测
- XSS 端点 (`xss_reflected_get.php` 等) 从未被探测
- 如果目标 URL 选错了（选了没有漏洞的页面），整个扫描就废了

### 10.2 设计

```python
# graph.py lats_init_tree_node 变更

async def lats_init_tree_node(state: dict) -> dict:
    # ... 现有逻辑 ...

    # [新增] 策略判断: web_broad 模式下展开多端点
    if scan_mode == "web_broad" or task_config.get("multi_endpoint", False):
        attack_surface = _expand_to_multi_endpoints(
            attack_surface=attack_surface,
            recon_dirs=recon_result.get("dirs", []),
            page_contents=state.get("page_contents", []),
            max_endpoints=10,  # 最多 10 个独立端点
        )

    # ... 继续创建搜索树 ...


def _expand_to_multi_endpoints(
    attack_surface: AttackSurface,
    recon_dirs: list[str],
    page_contents: list[PageContent],
    max_endpoints: int,
) -> AttackSurface:
    """
    将攻击面从单端点扩展为多端点。

    端点优先级:
    1. 有表单/参数的页面 (来自 PageContentExtractor)     weight=1.0
    2. URL 路径包含漏洞关键词 (sqli, xss, rce, ssrf...)  weight=0.8
    3. 状态码 200 + 非静态资源                           weight=0.5
    4. 状态码 403/401 (可能包含认证绕过)                  weight=0.4
    5. 其余目录                                           weight=0.2

    选择 Top-N 个端点，每个端点独立创建种子节点。
    """
    ...
```

### 10.3 多端点树结构调整

```
原结构:
  root
    ├── endpoint=rce_ping.php, param=cmd,     vt=rce
    ├── endpoint=rce_ping.php, param=id,      vt=sql_injection
    └── ...

新结构:
  root
    ├── endpoint=rce_ping.php    ← 端点分组节点
    │   ├── param=ipaddress,     vt=rce          ← 正确参数!
    │   ├── param=ipaddress,     vt=ssrf
    │   └── param=submit,        vt=auth_bypass
    ├── endpoint=sqli_id.php     ← 另一个端点
    │   ├── param=id,            vt=sql_injection
    │   └── param=id,            vt=idor
    ├── endpoint=xss_reflected_get.php
    │   └── ...
    └── ...
```

---

## 11. LangGraph 图结构最终变更

综合所有方案后的最终图结构:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        LATS v3 LangGraph                                 │
│                                                                          │
│  ┌────────┐    ┌──────────────┐    ┌──────────────┐                      │
│  │ Recon  │───▶│ DeepExtract  │───▶│ MultiSeed    │  ← 方案A + 方案I     │
│  │(增强)  │    │(PageContent  │    │(多端点初始化) │                      │
│  │        │    │ Extractor)   │    │              │                      │
│  └────────┘    └──────────────┘    └──────┬───────┘                      │
│                                           │                              │
│                          ┌────────────────┼────────────────┐             │
│                          ▼                ▼                ▼             │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                        主循环 (×N)                              │    │
│  │                                                                 │    │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │    │
│  │  │AdaptiveSelect│───▶│ParamValidate │───▶│MultiLevel    │      │    │
│  │  │(6-factor)    │    │(Existence    │    │Prober        │      │    │
│  │  │              │    │ Validator)   │    │(v3增强分类)   │      │    │
│  │  └──────────────┘    └──────┬───────┘    └──────┬───────┘      │    │
│  │                             │                   │               │    │
│  │                    ┌────────▼──────────┐        │               │    │
│  │                    │ 参数不存在?        │        │               │    │
│  │                    │ →AlternativeSuggest│       │               │    │
│  │                    │ →KILL + Graveyard │        │               │    │
│  │                    └───────────────────┘        │               │    │
│  │                                                │               │    │
│  │  ┌─────────────────────────────────────────────▼───────────┐  │    │
│  │  │              ProbeOrExecute (路由)                      │  │    │
│  │  │                                                        │  │    │
│  │  │  KILLED → 跳过    PROMOTED → LLMProbe                  │  │    │
│  │  │  HIGH_SIGNAL → Full React (Tier-2 预算)                │  │    │
│  │  │  SEED/LOW → 保留候选池                                  │  │    │
│  │  └─────────────────────────┬──────────────────────────────┘  │    │
│  │                            │                                  │    │
│  │  ┌─────────────────────────▼──────────────────────────────┐  │    │
│  │  │              CrossType Expand (方案F)                   │  │    │
│  │  │                                                        │  │    │
│  │  │  发现→ContextAwareClassifier→多类型子节点                │  │    │
│  │  │  + NodeResurrectionEngine (方案H)                       │  │    │
│  │  │  + SharedKnowledge 同步                                 │  │    │
│  │  └─────────────────────────┬──────────────────────────────┘  │    │
│  │                            │                                  │    │
│  │  ┌─────────────────────────▼──────────────────────────────┐  │    │
│  │  │              Evaluate (v3增强)                          │  │    │
│  │  │                                                        │  │    │
│  │  │  + TieredBudget 检查 (方案G)                            │  │    │
│  │  │  + 僵尸节点清理 (方案E)                                  │  │    │
│  │  │  + 复活节点重新入队                                      │  │    │
│  │  └─────────────────────────┬──────────────────────────────┘  │    │
│  │                            │                                  │    │
│  │              ┌─────────────┼─────────────┐                   │    │
│  │              ▼             ▼             ▼                   │    │
│  │         [continue]   [vuln_found]   [budget_exhausted]       │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌──────────┐                                                        │
│  │ Reporter │←───────────────────────────────────────────────────────│
│  └──────────┘                                                        │
└──────────────────────────────────────────────────────────────────────┘
```

**新增节点**:
- `DeepExtract`: PageContentExtractor 集成 (方案A)
- `ParamValidate`: 参数存在性验证 (方案D)

**变更节点**:
- `Recon`: 增加深层页面抓取 (方案A)
- `MultiSeed` (原 InitTree): 多端点初始化 + 多源参数发现 (方案B+I)
- `AdaptiveSelect`: 选择逻辑不变，但受益于节点质量提升
- `MultiLevelProber`: 增强分类规则 (方案E)
- `Expand`: CrossType + Resurrection (方案F+H)
- `Evaluate`: TieredBudget + 僵尸清理 (方案G+E)

---

## 12. 实施优先级与依赖关系

```
Phase 1 (基础 — 1-2周)
├── 方案A: PageContentExtractor          ← 无依赖, 立即可做
├── 方案D: ParamExistenceValidator       ← 依赖方案A的表单提取结果
└── 方案B: ParamDiscoveryPipeline        ← 依赖方案A+D的输出

Phase 2 (核心 — 2-3周)
├── 方案C: ContextAwareVulnClassifier    ← 依赖方案B的参数候选
├── 方案E: MultiLevelProber 重设计       ← 依赖方案D的验证结果
└── 方案F: CrossTypeExpansionEngine      ← 依赖方案C的分类器

Phase 3 (优化 — 1-2周)
├── 方案G: TieredBudgetManager           ← 依赖方案E的节点分级
├── 方案H: NodeResurrectionEngine        ← 依赖方案F的扩展+Graveyard
└── 方案I: 多端点攻击面                  ← 依赖方案A的PageContentExtractor

Phase 4 (验证)
└── 在 Pikachu 目标上A/B对比测试
    ├── 原系统: RCE 漏检
    └── 新系统: RCE 检出 + 多端点覆盖
```

### 关键依赖链

```
PageContentExtractor (A)
    ├──▶ ParamDiscoveryPipeline (B)
    │       └──▶ ContextAwareVulnClassifier (C)
    │               └──▶ CrossTypeExpansionEngine (F)
    │                       └──▶ NodeResurrectionEngine (H)
    └──▶ ParamExistenceValidator (D)
            └──▶ MultiLevelProber (E)
                    └──▶ TieredBudgetManager (G)
```

### 预期效果

| 指标 | 当前 (c30cb533) | 改进后 |
|------|----------------|--------|
| Recon 表单发现 | forms_found=0 | forms_found>=1 (ipaddress+submit) |
| 参数覆盖率 | cmd (错误), id, name... | ipaddress(置信度1.0), submit(1.0) |
| RCE 节点参数 | param=cmd (错误) | param=ipaddress (正确) |
| 晋升率 | promoted=0 (8周期) | promoted>=1 (Cycle 1) |
| 僵尸节点比例 | 78/120 = 65% | < 20% |
| Token 浪费比 | ~61% | < 20% |
| 有效 LLM 调用 | ~64/166 | ~500/625 |
| RCE 检出 | ❌ 漏检 | ✓ 检出 (Pikachu 预期) |
| 多端点覆盖 | 1 端点 | ≤10 端点 |
| Graveyard 复活 | 0 次 | 预期 ≥1 次 |
