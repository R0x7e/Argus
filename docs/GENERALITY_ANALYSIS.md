# 改进方案通用性分析

> 对 `IMPROVEMENT_PLAN_PARAMETER_DISCOVERY.md` 中 9 个方案在不同网站类型下的适应性评估

---

## 1. 网站类型矩阵

选取 10 种典型目标类型，覆盖安全测试中常见的攻击面形态:

| # | 类型 | 典型特征 | 示例 | 对Argus的挑战 |
|---|------|---------|------|--------------|
| T1 | **传统服务端渲染** | HTML表单, GET/POST, URL路由含语义 | Pikachu, DVWA, 企业内网PHP应用 | 基线场景 |
| T2 | **SPA (React/Vue/Angular)** | JS动态渲染, API调用, 虚拟DOM, hash路由 | 现代SaaS后台, 管理面板 | 无静态HTML表单, 参数在JS闭包中 |
| T3 | **REST API** | JSON请求/响应, Bearer token, Swagger/OpenAPI | 微服务API, 移动端后端 | 无HTML页面, 参数通过API文档暴露 |
| T4 | **GraphQL** | 单一端点, POST-only, schema内省 | GitHub API v4, 企业GraphQL网关 | 参数结构完全不同(introspection query) |
| T5 | **CMS平台** | 插件生态, 已知路由规则, 数据库驱动 | WordPress, Drupal, Joomla | 参数可预测但需插件特定知识 |
| T6 | **静态站点** | 纯HTML/JS, 无服务端参数处理 | 文档站, 博客, Landing Page | 根本无漏洞, 需快速识别并跳过 |
| T7 | **认证后应用** | 登录态, CSRF token, 多角色权限 | SaaS后台, 网银, 企业OA | 参数不可直接访问, 需模拟登录态 |
| T8 | **WAF保护站点** | 请求过滤, 频率限制, IP封禁 | 金融/政府站点 | 参数探测被拦截, 需代理轮换 |
| T9 | **WebSocket/实时应用** | WS连接, 双向消息, 非HTTP参数 | 聊天应用, 实时仪表盘 | 参数不在HTTP请求中, 自定义协议 |
| T10 | **混合型** | 传统页面+SPA+API混用 | 大型企业应用 | 多种类型共存, 需自适应切换 |

---

## 2. 逐方案通用性评估

### 2.1 方案A: PageContentExtractor

**核心假设**: 目标有 HTML 页面, 页面包含可解析的表单或链接。

| 网站类型 | 适用性 | 分析 |
|---------|--------|------|
| T1 传统渲染 | ★★★★★ 完全适用 | 正则提取 `<form>`+`<input>` 直接命中 |
| T2 SPA | ★★★☆☆ 部分适用 | Playwright 渲染后可提取 DOM, 但表单可能是动态生成的事件处理器, 没有 `<form>` 标签 |
| T3 REST API | ★☆☆☆☆ 基本失效 | 无 HTML 页面, 需要在 Recon 阶段检测到 `Content-Type: application/json` 时自动切换到 API 模式 |
| T4 GraphQL | ★☆☆☆☆ 基本失效 | 同 T3 |
| T5 CMS | ★★★★☆ 适用 | 已知 CMS 路由结构可辅助 |
| T6 静态站点 | ★★★★★ 适用(快速判定) | 提取后立即判定为 `page_type=static` → 跳过深度扫描 |
| T7 认证后 | ★★☆☆☆ 受阻 | Playwright 可维持登录态, 但需要会话初始化 |
| T8 WAF | ★★☆☆☆ 受阻 | 页面提取本身可能触发WAF |
| T9 WebSocket | ★☆☆☆☆ 不适用 | 无传统页面概念 |
| T10 混合型 | ★★★☆☆ 部分适用 | 对传统部分有效, SPA部分受限 |

**通用性评级: ★★★☆☆ (中等)**

**通用化增强**:
```python
# page_content_extractor.py 增加策略模式

class PageExtractionStrategy(ABC):
    """页面提取策略 — 按网站类型自动切换"""

    @abstractmethod
    async def extract(self, url: str, response: httpx.Response) -> PageContent: ...

class HTMLFormStrategy(PageExtractionStrategy):
    """传统 HTML 表单提取 (T1, T5, T6)"""
    ...

class SPADOMStrategy(PageExtractionStrategy):
    """
    SPA DOM 提取 (T2):
    - Playwright 全渲染
    - 监听 network requests 获取 API 调用
    - 从 React/Vue devtools 全局变量提取路由
    - 解析 JS bundle 中的 fetch/axios 调用
    """
    ...

class APIDocStrategy(PageExtractionStrategy):
    """
    API 文档提取 (T3):
    - 检测 /docs, /swagger.json, /openapi.json
    - 解析 OpenAPI/Swagger schema
    - 提取所有 endpoint + method + parameter
    """
    ...

class GraphQLIntrospectionStrategy(PageExtractionStrategy):
    """
    GraphQL 内省提取 (T4):
    - 发送 __schema introspection query
    - 提取所有 Query/Mutation 字段及参数
    """
    ...
```

**策略自动选择**:
```python
STRATEGY_DETECTORS = [
    (lambda r: 'application/json' in r.headers.get('content-type','') 
     and _is_graphql_response(r), GraphQLIntrospectionStrategy()),
    (lambda r: _has_openapi_spec(r), APIDocStrategy()),
    (lambda r: _is_spa(r), SPADOMStrategy()),
    (lambda r: True, HTMLFormStrategy()),  # fallback
]
```

---

### 2.2 方案B: ParamDiscoveryPipeline

**核心假设**: 参数可以通过多种来源推断, 其中表单提取是最高置信度来源。

| 网站类型 | 适用性 | 分析 |
|---------|--------|------|
| T1 传统 | ★★★★★ | 6 源全通路 |
| T2 SPA | ★★★★☆ | 表单源受限, JS端点源+LLM推理增强 |
| T3 REST API | ★★★★☆ | API文档源+URL查询源+LLM推理, 缺少表单源 |
| T4 GraphQL | ★★★★☆ | introspection 替代表单源, 其他源可用 |
| T5 CMS | ★★★★★ | 表单源+已知规则融合 |
| T6 静态 | ★★★★★ | 快速判定无参数, 节省预算 |
| T7 认证后 | ★★★☆☆ | 需要先建立会话再发现 |
| T8 WAF | ★★★☆☆ | 探测请求可能触发WAF |
| T9 WebSocket | ★★☆☆☆ | 需扩展WS消息解析源 |
| T10 混合 | ★★★★☆ | 多源融合天然适配混合型 |

**通用性评级: ★★★★☆ (较高)**

**管道本身已经是多源的, 通用性较好。** 主要盲区是 WebSocket 和非 HTTP 协议。

**通用化增强**:
```python
# 增加来源7: WebSocket 消息参数提取
async def _from_websocket_messages(self, ws_url: str) -> list[ParamCandidate]:
    """连接到 WebSocket, 监听服务端推送的消息格式, 提取参数名"""
    ...

# 增加来源8: 已知框架/插件参数知识库
def _from_known_framework(self, detected_tech: list[str]) -> list[ParamCandidate]:
    """
    根据技术栈指纹加载已知参数:
    - WordPress: wp_nonce, post_id, action, page_id...
    - Laravel: _token, _method...
    - Spring: csrf, page, size, sort...
    """
    ...
```

---

### 2.3 方案C: ContextAwareVulnClassifier

**核心假设**: 漏洞类型可以通过 URL 路径语义 + 参数名语义推断。

| 网站类型 | 适用性 | 分析 |
|---------|--------|------|
| T1 传统 | ★★★★☆ | URL路径+参数名直接覆盖 |
| T2 SPA | ★★★☆☆ | SPA的hash路由(`#/user/123`)不经过服务端, URL语义较弱 |
| T3 REST API | ★★★★☆ | RESTful路径(`/api/users/{id}`)语义极强 |
| T4 GraphQL | ★★☆☆☆ | 单一端点`/graphql`, URL语义完全失效, 需转移到参数名+类型系统推断 |
| T5 CMS | ★★★★☆ | `/wp-admin/admin-ajax.php?action=...` — action参数强信号 |
| T6 静态 | ★★★★★ | 判定无类型, 快速终止 |
| T7 认证后 | ★★★★☆ | 与T1类似, 但额外考虑权限上下文 |
| T8 WAF | ★★★★☆ | 分类本身不产生HTTP请求, 不受WAF影响 (离线分类) |
| T9 WebSocket | ★☆☆☆☆ | URL和参数语义模型完全不同 |
| T10 混合 | ★★★☆☆ | 需要分区域切换分类策略 |

**通用性评级: ★★★☆☆ (中等偏上)**

**最大盲区: GraphQL 和 SPA hash路由下 URL 语义消失。**

**通用化增强**:
```python
class ContextAwareVulnClassifier:

    # [新增] GraphQL 类型系统推断
    @classmethod
    def _from_graphql_type(cls, field_name: str, type_name: str, 
                           args: list[dict]) -> list[VulnTypeScore]:
        """
        从 GraphQL schema 推断漏洞类型:
        - Mutation { updateUserPassword(oldPassword, newPassword) } → auth_bypass
        - Query { searchUsers(q) } → sql_injection / xss
        - Field: File { url } → ssrf
        """
        ...

    # [新增] 请求/响应结构推断
    @classmethod
    def _from_api_signature(cls, method: str, path: str, 
                            request_body_schema: dict, 
                            response_schema: dict) -> list[VulnTypeScore]:
        """
        从 OpenAPI/JSON Schema 推断漏洞类型:
        - GET /users/{id} (param: id: integer) → idor
        - POST /search (body: {q: string}) → xss, sql_injection
        - POST /upload (body: {file: binary}) → file_upload
        """
        ...

    # URL 语义权重自适应
    URL_SEMANTIC_WEIGHT = {
        "traditional": 0.40,   # T1: URL 路径强信号
        "spa_hash":    0.15,   # T2: hash路由弱信号
        "rest_api":    0.45,   # T3: RESTful 极强信号
        "graphql":     0.05,   # T4: 几乎无信号 → 转移到参数/类型
        "cms":         0.35,   # T5: 混合信号
        "unknown":     0.30,   # 默认
    }
```

---

### 2.4 方案D: ParamExistenceValidator

**核心假设**: 参数存在性可以通过发送不同值并观察响应差异来判定。

| 网站类型 | 适用性 | 分析 |
|---------|--------|------|
| T1 传统 | ★★★★★ | 参数注入HTTP请求直接生效 |
| T2 SPA | ★★★★☆ | 需要 Playwright 发送, 否则CSR不处理查询参数 |
| T3 REST API | ★★★★★ | 完全适用 |
| T4 GraphQL | ★★★★☆ | 需要适配为 GraphQL variables 注入 |
| T5 CMS | ★★★★★ | 完全适用 |
| T6 静态 | ★★★★★ | 快速判定无服务端处理 |
| T7 认证后 | ★★★☆☆ | 需要携带认证token/header |
| T8 WAF | ★★☆☆☆ | 探测请求被WAF拦截时, 无法区分"参数不存在"和"被WAF拦截" |
| T9 WebSocket | ★★☆☆☆ | 需要WS消息协议适配 |
| T10 混合 | ★★★★☆ | 自适应切换 |

**通用性评级: ★★★★☆ (较高)**

**最大盲区: WAF 环境下无法区分"不存在"和"被拦截"。**

**通用化增强**:
```python
class ParamExistenceValidator:

    async def validate(self, url, param_name, context, 
                       transport_type: str = "auto") -> ExistenceResult:
        """
        增强: 根据传输类型选择适配的验证策略
        """
        if transport_type == "auto":
            transport_type = self._detect_transport(url, context)

    def _detect_transport(self, url, context) -> str:
        """检测目标的参数传输方式: http_query, http_body, graphql_var, ws_message, ..."""
        ...

    async def _validate_graphql(self, endpoint, field_name, arg_name, context):
        """GraphQL 参数存在性: 发送包含/不包含该参数的合法 query, 对比错误信息"""
        ...

    async def _validate_with_waf_awareness(self, ...):
        """
        WAF 感知的验证:
        - 如果所有探测返回 403 → 标记为 WAF_BLOCKED (特殊状态, 不入 KILL)
        - 使用 WAF bypass 技巧 (大小写变体, 编码, 参数污染) 重试
        - 如果 bypass 后仍然无差异 → 可能是参数不存在
        """
        ...
```

---

### 2.5 方案E: MultiLevelProber 晋升逻辑重设计

**核心假设**: Level 0 快速探测可以区分 KILL/PROMOTED。

| 网站类型 | 适用性 | 分析 |
|---------|--------|------|
| T1-T5,T7,T10 | ★★★★★ | 分类逻辑本身与站点类型无关, 是纯算法改进 |
| T6 静态 | ★★★★★ | 快速KILL, 极佳 |
| T8 WAF | ★★★☆☆ | 全返回403→需特殊处理(标记WAF而非KILL) |
| T9 WebSocket | ★★☆☆☆ | 探测协议不同 |

**通用性评级: ★★★★☆ (较高)**

**这是纯算法改进, 通用性天然好。** 新增的分类规则(参数不存在→KILL, 全无差异→KILL)是针对探测结果的逻辑判断, 与网站类型解耦。

---

### 2.6 方案F: CrossTypeExpansionEngine

**核心假设**: ContextAwareVulnClassifier 能给出跨类型建议。

| 网站类型 | 适用性 | 分析 |
|---------|--------|------|
| 所有类型 | 继承方案C的通用性 | ExpansionEngine 本身是框架, 通用性取决于分类器 |

**通用性评级: 继承方案C (★★★☆☆ → ★★★★☆ 随方案C增强而提升)**

---

### 2.7 方案G: 智能预算分配

**核心假设**: 不同开发阶段的节点价值不同。

| 网站类型 | 适用性 | 分析 |
|---------|--------|------|
| 所有类型 | ★★★★★ | 预算管理完全与网站类型无关, 纯资源调度优化 |
| T6 静态 | ★★★★★ | PROMOTED=0 → Tier-1 预算自动释放给 Tier-3/4 |

**通用性评级: ★★★★★ (完全通用)**

---

### 2.8 方案H: 节点复活

**核心假设**: Graveyard 中的节点在 SharedKnowledge 出现新信号时可以复活。

| 网站类型 | 适用性 | 分析 |
|---------|--------|------|
| 所有类型 | ★★★★★ | 复活逻辑基于节点属性匹配, 与站点类型无关 |

**通用性评级: ★★★★★ (完全通用)**

---

### 2.9 方案I: 多端点攻击面

**核心假设**: 目标站点有多个可探测的功能页面。

| 网站类型 | 适用性 | 分析 |
|---------|--------|------|
| T1 传统 | ★★★★★ | 多页面应用天然适用 |
| T2 SPA | ★★★★☆ | 需通过路由表发现端点, 而非 `<a>` 链接 |
| T3 REST API | ★★★★★ | OpenAPI spec 直接列出所有端点 |
| T4 GraphQL | ★★★★☆ | introspection → 多个 Query/Mutation → 每个字段是一个"端点" |
| T5 CMS | ★★★★★ | 已知路由结构 |
| T6 静态 | ★☆☆☆☆ | 无功能端点 → 自动跳过 (预算节省) |
| T7 认证后 | ★★★★☆ | 需按角色分组端点 |
| T8 WAF | ★★★☆☆ | 端点扫描可能触发速率限制 |
| T9 WebSocket | ★★☆☆☆ | 非HTTP端点概念不同 |
| T10 混合 | ★★★★★ | 多种端点来源融合 |

**通用性评级: ★★★★☆ (较高)**

---

## 3. 综合通用性评分

```
方案     T1  T2  T3  T4  T5  T6  T7  T8  T9  T10 | 均值   趋势
─────────────────────────────────────────────────┼──────────────
A(提取)   5   3   1   1   4   5   2   2   1   3   | 2.7   ← 需最大增强
B(参数)   5   4   4   4   5   5   3   3   2   4   | 3.9   ↑ 较好
C(分类)   4   3   4   2   4   5   4   4   1   3   | 3.4   ← 需增强
D(验证)   5   4   5   4   5   5   3   2   2   4   | 3.9   ↑ 较好
E(晋升)   5   5   5   5   5   5   4   3   2   5   | 4.4   ↑ 优秀
F(扩展)  (继承C)                                  | 3.4   ← 随C增强
G(预算)   5   5   5   5   5   5   5   5   5   5   | 5.0   ↑ 完美
H(复活)   5   5   5   5   5   5   5   5   5   5   | 5.0   ↑ 完美
I(多端)   5   4   5   4   5   1   4   3   2   5   | 3.8   ↑ 较好
─────────────────────────────────────────────────┼──────────────
加权均值                                           | 4.0
```

**关键结论**:
- **方案G(H预算) 和方案H(复活) 是"零假设"方案** — 完全通用, 在任何网站类型下都能正确运作
- **方案A(PageContentExtractor) 通用性最低 (2.7)** — 对传统HTML表单有强依赖, 需要最大的泛化增强
- **方案C(ContextAwareVulnClassifier) 对GraphQL/SPA存在盲区 (T2=3, T4=2)** — 需要增加API结构推断和GraphQL类型系统推断

---

## 4. 通用化增强路线图

### 4.1 方案A 增强: 策略模式多出口提取

这是通用性提升的**最大杠杆点**。当前设计假设"目标有HTML页面", 需要扩展为"目标有可交互的界面层":

```
PageContentExtractor (重构)
    │
    ├── HTMLFormStrategy          ← 传统HTML表单 (T1, T5, T6, T10)
    ├── SPADOMStrategy            ← SPA JS渲染 (T2)
    │     ├── 监听 XHR/fetch 调用
    │     ├── 解析 React Router / Vue Router
    │     └── 从打包JS中提取API端点
    ├── OpenAPIStrategy           ← Swagger/OpenAPI (T3)
    │     ├── GET /swagger.json
    │     ├── 解析 paths, methods, parameters, schemas
    │     └── 提取 requestBody JSON Schema
    ├── GraphQLIntrospectStrategy ← GraphQL 内省 (T4)
    │     ├── POST __schema{types{name,fields{name,args{name}}}}
    │     └── 提取 Query/Mutation field + args
    ├── CMSPluginStrategy         ← CMS 插件感知 (T5)
    │     ├── WP: 扫描 /wp-content/plugins/*
    │     ├── Drupal: 扫描 /modules/*
    │     └── 加载已知插件路由/参数规则
    └── StaticSiteStrategy        ← 纯静态判定 (T6)
          └── 快速判定无交互 → 标记 skip
```

**策略检测**: Recon 阶段先发送一个探测请求, 根据响应特征自动选择策略:

```python
STRATEGY_SELECTOR = [
    # 1. GraphQL 检测
    (lambda r: _detect_graphql(r), GraphQLIntrospectStrategy()),
    # 2. OpenAPI 检测
    (lambda r: _detect_openapi(r), OpenAPIStrategy()),
    # 3. SPA 检测 (大量JS, 空<body>, react/vue root元素)
    (lambda r: _detect_spa(r), SPADOMStrategy()),
    # 4. CMS 检测 (WordPress/Drupal meta tags, generator headers)
    (lambda r: _detect_cms(r), CMSPluginStrategy()),
    # 5. 静态站点检测 (无form, 无input, 无script含XHR)
    (lambda r: _detect_static(r), StaticSiteStrategy()),
    # 6. 默认: 传统HTML
    (lambda r: True, HTMLFormStrategy()),
]
```

### 4.2 方案C 增强: 多模态漏洞类型推断

```
ContextAwareVulnClassifier (增强)
    │
    └── 信号源扩展:
        ├── URL路径语义 (原有, 权重自适应)
        ├── HTTP方法语义 [新增]
        │     PUT/PATCH → idor, mass_assignment
        │     DELETE → idor
        │     OPTIONS → info_disclosure
        ├── 参数名语义 (原有, 扩展映射表)
        ├── 参数类型语义 [新增]
        │     type=integer, name=*id* → idor
        │     type=string, name=*url* → ssrf
        │     type=file   → file_upload
        ├── API Schema语义 [新增: T3/T4]
        │     GraphQL: field type + args → 推断
        │     OpenAPI: requestBody schema → 推断
        ├── 页面内容语义 (原有, 扩展)
        └── 响应结构语义 [新增]
              response包含{error, stack_trace} → error_leak
              response包含{sql, query} → sql_injection
              response包含{file, path} → lfi/path_traversal
```

### 4.3 认证态感知 [新增增强]

当前所有方案均假设"无认证或认证不需要特殊处理"。对于 T7(认证后应用):

```python
class AuthAwareSession:
    """
    认证感知会话管理

    对于需要登录的目标:
    1. Recon 阶段: 检测 302→/login, 401→触发认证流程
    2. 支持手动提供 Cookie/Token/凭据
    3. 支持自动检测登录表单并尝试常见弱口令
    4. 多角色会话: admin/user/guest 分别探索 (权限视角的漏洞)
    """
    ...
```

### 4.4 WAF 自适应 [新增增强]

对于 T8(WAF 保护站点):

```python
class WAFAwareProber:
    """
    WAF 感知的探测层

    问题: ParamExistenceValidator 发3组探测请求→全返回403
    当前行为: 无法区分"403=参数不存在"和"403=WAF拦截"

    增强:
    1. WAF 检测: 发已知触发WAF的payload(如<script>alert(1)</script>) vs 正常请求
       → 如果正常请求也返回403 → 目标被WAF保护
    2. WAF 指纹: 匹配 Cloudflare/AWS WAF/ModSecurity 响应特征
    3. WAF bypass 参数探测:
       - 大小写变体: IpAddress, IPADDRESS
       - HTTP参数污染: ipaddress=1&ipaddress=2
       - Content-Type 切换: form-urlencoded → multipart → JSON
       - 分块传输
    4. 降级策略: 探测失败→标记WAF而非KILL→进入WAF专项bypass分支
    """
    ...
```

---

## 5. 方案假设总结

| 方案 | 核心假设 | 通用性 | 失效场景 | 修复方法 |
|------|---------|--------|---------|---------|
| A | 目标有HTML页面 | ★★☆ | GraphQL/API/WS | 策略模式多出口 |
| B | 参数可通过多源推断 | ★★★★ | WS/自定义协议 | 增加来源7+8 |
| C | URL+参数名含语义 | ★★★☆ | GraphQL/hash路由 | 增加schema推断 |
| D | HTTP参数注入可判定 | ★★★★ | WAF混淆 | WAF感知验证 |
| E | 探测结果可分类 | ★★★★ | WAF全拦截 | WAF状态处理 |
| F | 继承C的假设 | ★★★☆ | 同C | 同C |
| G | 无 | ★★★★★ | — | — |
| H | 无(基于数据匹配) | ★★★★★ | — | — |
| I | 目标有多端点 | ★★★★ | 单页/静态 | 单页检测后跳过 |

**底线: 方案G(预算)+H(复活)是"零假设"方案, 方案A(提取)+C(分类)需要最大的泛化投资。**

---

## 6. 场景化适配策略

```
                    ┌─────────────────────────┐
                    │   目标URL输入             │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │  Recon: 发送探测请求      │
                    │  检测 Content-Type       │
                    │  检测 HTML/JSON/GraphQL  │
                    └───────────┬─────────────┘
                                │
              ┌─────────────────┼─────────────────────┐
              ▼                 ▼                     ▼
    ┌─────────────────┐ ┌──────────────┐ ┌──────────────────────┐
    │ application/json│ │ text/html    │ │ text/html + SPA标志   │
    │ + graphql字段   │ │ + <form>标签  │ │ (空body, JS bundle)   │
    └────────┬────────┘ └──────┬───────┘ └──────────┬───────────┘
             │                 │                    │
             ▼                 ▼                    ▼
    ┌─────────────────┐ ┌──────────────┐ ┌──────────────────────┐
    │ GraphQL策略      │ │ HTMLForm策略  │ │ SPADOM策略           │
    │ • introspection  │ │ • 正则提取    │ │ • Playwright渲染     │
    │ • type→vuln推断  │ │ • 表单参数    │ │ • 拦截network请求    │
    │ • 字段级端点     │ │ • 链接跟踪    │ │ • JS bundle解析      │
    └────────┬────────┘ └──────┬───────┘ └──────────┬───────────┘
             │                 │                    │
             └─────────────────┼────────────────────┘
                               │
                               ▼
                    ┌─────────────────────────┐
                    │  ParamDiscoveryPipeline  │
                    │  (策略无关, 接收各来源)    │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │  ContextAwareClassifier  │
                    │  (根据source类型调权重)   │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │  后续流程 (方案D-H)      │
                    │  (基本与网站类型无关)     │
                    └─────────────────────────┘
```

---

## 7. 最终结论

### 通用性评级

| 维度 | 评分 | 说明 |
|------|------|------|
| **传统Web应用 (T1/T5/T10)** | ★★★★★ | 完全覆盖, 9个方案全通路 |
| **SPA (T2)** | ★★★★☆ | 方案A需SPA策略, 其余8个方案直接适用 |
| **REST API (T3)** | ★★★★☆ | 方案A需OpenAPI策略, 方案C需URL模式扩展 |
| **GraphQL (T4)** | ★★★☆☆ | 方案A+C需要最大的策略增强 |
| **静态站点 (T6)** | ★★★★★ | 快速识别→跳过, 预算零浪费 |
| **认证后 (T7)** | ★★★★☆ | 需要认证会话管理增强 |
| **WAF保护 (T8)** | ★★★☆☆ | 需要WAF感知探测层 |
| **WebSocket (T9)** | ★★☆☆☆ | 需要全新的传输层适配 |

### 整体判断

**方案具有较好的通用性, 但不是"开箱即用"的万能方案。** 核心原因:

1. **方案A+C 对"交互界面层"有假设** — 当前假设是HTML表单, 需要策略模式扩展为多界面类型
2. **9个方案中 7个(78%)在大多数网站类型下适用** — 仅A和C需要显著的泛化投资
3. **G+H是真正的"零假设"方案** — 预算调度+节点复活完全不依赖网站类型
4. **管线设计中的多源融合天然提供了退化容错** — 即使某个来源失效(如无HTML表单), 其他来源(URL查询/LLM推理/API文档)仍可接续

推荐的泛化实施顺序: **G+H 立即实施 → A策略模式扩展 → C多模态增强 → WAF/认证/WS适配**
