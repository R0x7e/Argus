"""
深层页面侦察引擎 (v3)

策略模式多出口页面内容提取器。

支持六种策略自动检测和切换:
- HTMLFormStrategy:      传统HTML表单提取 (PHP/JSP/ASP.NET等)
- SPADOMStrategy:        SPA JS动态渲染提取 (React/Vue/Angular)
- OpenAPIStrategy:       Swagger/OpenAPI文档解析 (REST API)
- GraphQLIntrospectStrategy: GraphQL内省查询 (GraphQL API)
- StaticSiteStrategy:    纯静态站点快速判定跳过
- CMSPluginStrategy:     CMS插件感知 (WordPress/Drupal等)

核心流程:
  Recon 阶段 → send probe request → detect site type → select strategy
  → extract page content → output PageContent list

解决根本问题: Recon 阶段 forms_found=0, pages_crawled=0, params_found=0
"""

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ──── 数据结构 ────

@dataclass
class FormInfo:
    """表单信息"""
    action: str = ""
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    form_type: str = "unknown"  # login, search, upload, command, normal
    has_file_input: bool = False
    has_password_input: bool = False


@dataclass
class PageContent:
    """页面内容解析结果"""
    url: str
    status_code: int
    html_size: int
    title: str = ""
    # 表单
    forms: list[FormInfo] = field(default_factory=list)
    # 所有 input/select/textarea 参数名
    input_params: list[str] = field(default_factory=list)
    # JS 中提取的 API 端点
    js_endpoints: list[str] = field(default_factory=list)
    # <a> 链接 (用于递归爬取)
    links: list[str] = field(default_factory=list)
    # HTML 注释中的线索
    html_comments: list[str] = field(default_factory=list)
    # 页面类型标记
    page_type: str = "unknown"  # login, form, api_doc, error, static, spa, normal
    # 响应头
    response_headers: dict[str, str] = field(default_factory=dict)
    # 技术栈指纹
    tech_fingerprint: list[str] = field(default_factory=list)
    # 原始HTML片段(用于后续分析)
    body_preview: str = ""


# ──── 抽象策略基类 ────

class PageExtractionStrategy(ABC):
    """页面提取策略抽象基类"""

    name: str = "base"

    @abstractmethod
    async def can_handle(self, response, url: str) -> bool:
        """判断此策略是否适用"""
        ...

    @abstractmethod
    async def extract(
        self, url: str, response, context: Any = None
    ) -> PageContent:
        """执行页面内容提取"""
        ...

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """从HTML提取所有<a>链接"""
        links = set()
        for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            href = m.group(1)
            if href.startswith("javascript:") or href.startswith("#"):
                continue
            if href.startswith("/"):
                from urllib.parse import urljoin
                href = urljoin(base_url, href)
            elif not href.startswith("http"):
                from urllib.parse import urljoin
                href = urljoin(base_url, href)
            links.add(href)
        return sorted(links)[:50]

    def _extract_forms(self, html: str) -> list[FormInfo]:
        """从HTML提取所有表单信息 (增强版)"""
        forms = []
        form_pattern = re.compile(
            r'<form[^>]*>(.*?)</form>',
            re.IGNORECASE | re.DOTALL,
        )
        action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
        method_pattern = re.compile(r'method=["\']([^"\']+)["\']', re.IGNORECASE)
        input_pattern = re.compile(
            r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        type_pattern = re.compile(r'type=["\']([^"\']+)["\']', re.IGNORECASE)

        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            form_body = form_match.group(1)
            action_m = action_pattern.search(form_html)
            method_m = method_pattern.search(form_html)
            action = action_m.group(1) if action_m else ""
            method = method_m.group(1).upper() if method_m else "GET"
            params = input_pattern.findall(form_body)

            # 检测表单类型
            has_password = "password" in form_body.lower()
            has_file = "file" in form_body.lower()

            form_type = "normal"
            if has_password:
                form_type = "login"
            elif has_file:
                form_type = "upload"
            elif any(kw in (form_body + form_html).lower()
                     for kw in ["search", "query", "keyword"]):
                form_type = "search"
            elif any(kw in (form_body + form_html).lower()
                     for kw in ["cmd", "command", "exec", "ping", "ip"]):
                form_type = "command"

            forms.append(FormInfo(
                action=action,
                method=method,
                params=params,
                form_type=form_type,
                has_file_input=has_file,
                has_password_input=has_password,
            ))

        return forms

    def _extract_comments(self, html: str) -> list[str]:
        """提取HTML注释"""
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        return [c.strip()[:200] for c in comments if c.strip()][:20]

    def _detect_tech(self, html: str, headers: dict[str, str]) -> list[str]:
        """检测技术栈指纹"""
        tech = []
        html_lower = html.lower()

        # 服务器头
        server = headers.get("server", "").lower()
        if "apache" in server:
            tech.append("apache")
        if "nginx" in server:
            tech.append("nginx")
        if "iis" in server:
            tech.append("iis")
        if "cloudflare" in server:
            tech.append("cloudflare")

        # PHP
        if "php" in html_lower or "x-powered-by: php" in str(headers).lower():
            tech.append("php")

        # 框架指纹
        if "wp-content" in html_lower or "wordpress" in html_lower:
            tech.append("wordpress")
        if "drupal" in html_lower:
            tech.append("drupal")
        if "laravel" in html_lower or "csrf-token" in html_lower:
            tech.append("laravel")
        if "react" in html_lower or "_reactRoot" in html_lower or "react-dom" in html_lower:
            tech.append("react")
        if "vue" in html_lower or "v-bind" in html_lower or "v-for" in html_lower:
            tech.append("vue")
        if "angular" in html_lower or "ng-app" in html_lower or "ng-controller" in html_lower:
            tech.append("angular")

        # JS框架
        if "jquery" in html_lower:
            tech.append("jquery")
        if "bootstrap" in html_lower:
            tech.append("bootstrap")

        return tech

    def _classify_page_type(self, content: PageContent) -> str:
        """页面类型分类"""
        if content.status_code in (404, 410):
            return "error"
        if content.status_code in (500, 502, 503):
            return "error"

        has_forms = len(content.forms) > 0
        has_inputs = len(content.input_params) > 0
        has_links = len(content.links) > 0
        is_html = content.html_size > 100

        if not is_html:
            return "api_doc" if content.status_code == 200 else "error"

        if has_forms:
            for form in content.forms:
                if form.form_type == "login":
                    return "login"
                if form.form_type == "command":
                    return "form"
            return "form"

        if has_inputs:
            return "form"

        if has_links:
            return "normal"

        return "static"


# ──── 具体策略实现 ────

class HTMLFormStrategy(PageExtractionStrategy):
    """
    传统HTML表单提取策略

    适用: text/html Content-Type + <form>标签
    方法: 正则提取表单、input、链接、注释
    """

    name = "html_form"

    async def can_handle(self, response, url: str) -> bool:
        ct = response.headers.get("content-type", "")
        return "text/html" in ct

    async def extract(
        self, url: str, response, context: Any = None
    ) -> PageContent:
        html = response.text
        forms = self._extract_forms(html)
        all_params: list[str] = []
        for f in forms:
            all_params.extend(f.params)

        content = PageContent(
            url=url,
            status_code=response.status_code,
            html_size=len(html),
            title=self._extract_title(html),
            forms=forms,
            input_params=list(dict.fromkeys(all_params)),  # 去重保序
            js_endpoints=[],
            links=self._extract_links(html, url),
            html_comments=self._extract_comments(html),
            response_headers=dict(response.headers),
            tech_fingerprint=self._detect_tech(html, dict(response.headers)),
            body_preview=html[:2000],
        )
        content.page_type = self._classify_page_type(content)
        return content

    def _extract_title(self, html: str) -> str:
        m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip()[:200] if m else ""


class SPADOMStrategy(PageExtractionStrategy):
    """
    SPA JS渲染提取策略

    适用: 检测到React/Vue/Angular + 少量静态HTML
    方法: Playwright全渲染 → 拦截network → 提取DOM → 解析JS bundle

    NOTE: 完整实现需要Playwright浏览器。当前提供基于静态检测的降级实现，
    生产环境应通过 playwright_manager 获取渲染后的页面。
    """

    name = "spa_dom"

    async def can_handle(self, response, url: str) -> bool:
        html = response.text.lower() if hasattr(response, 'text') else ""
        spa_indicators = [
            '<div id="root">', '<div id="app">',
            'react', 'vue', 'angular',
            '__NEXT_DATA__', '__NUXT__',
            'webpack', 'bundle.js', 'chunk',
        ]
        score = sum(1 for ind in spa_indicators if ind in html)
        return score >= 2

    async def extract(
        self, url: str, response, context: Any = None
    ) -> PageContent:
        html = response.text if hasattr(response, 'text') else ""

        # 尝试从JS bundle中提取API端点
        js_endpoints = self._extract_api_from_js(html)

        content = PageContent(
            url=url,
            status_code=response.status_code,
            html_size=len(html),
            title="SPA: use Playwright for full render",
            forms=[],  # SPA表单是动态的，静态HTML中通常没有
            input_params=[],
            js_endpoints=js_endpoints,
            links=self._extract_links(html, url),
            html_comments=self._extract_comments(html),
            response_headers=dict(response.headers) if hasattr(response, 'headers') else {},
            tech_fingerprint=self._detect_tech(html, dict(response.headers) if hasattr(response, 'headers') else {}),
            body_preview=html[:2000],
        )
        content.page_type = "spa"

        # 将JS端点也作为链接加入
        for ep in js_endpoints:
            if ep not in content.links:
                content.links.append(ep)

        return content

    def _extract_api_from_js(self, html: str) -> list[str]:
        """从JS代码中提取API端点"""
        endpoints = set()
        # fetch/axios调用
        for m in re.finditer(r"""(?:fetch|axios\.\w+)\s*\(\s*["']([^"']+)["']""", html):
            endpoints.add(m.group(1))
        # $http (Angular)
        for m in re.finditer(r"""\$http\.\w+\s*\(\s*["']([^"']+)["']""", html):
            endpoints.add(m.group(1))
        # XMLHttpRequest.open
        for m in re.finditer(r"""\.open\s*\(\s*["']\w+["']\s*,\s*["']([^"']+)["']""", html):
            endpoints.add(m.group(1))
        return sorted(endpoints)[:30]


class OpenAPIStrategy(PageExtractionStrategy):
    """
    OpenAPI/Swagger 文档解析策略

    适用: Content-Type: application/json + OpenAPI结构
    方法: 解析 /docs, /swagger.json, /openapi.json → 提取全部endpoint+param
    """

    name = "openapi"

    async def can_handle(self, response, url: str) -> bool:
        ct = response.headers.get("content-type", "")
        if "application/json" not in ct:
            return False
        try:
            import json
            body = response.json() if hasattr(response, 'json') else json.loads(response.text)
            return ("openapi" in body or "swagger" in body or
                    "paths" in body or "info" in body)
        except Exception:
            return False

    async def extract(
        self, url: str, response, context: Any = None
    ) -> PageContent:
        import json
        body = response.json() if hasattr(response, 'json') else json.loads(response.text)

        paths = body.get("paths", {})
        forms: list[FormInfo] = []
        all_params: list[str] = []
        js_endpoints: list[str] = []

        for path, methods in paths.items():
            js_endpoints.append(path)
            if isinstance(methods, dict):
                for method, details in methods.items():
                    if isinstance(details, dict):
                        params = details.get("parameters", [])
                        for p in params:
                            if isinstance(p, dict):
                                pname = p.get("name", "")
                                if pname:
                                    all_params.append(pname)
                        # requestBody 参数
                        rb = details.get("requestBody", {})
                        if isinstance(rb, dict):
                            rb_content = rb.get("content", {})
                            for ct_key, ct_val in rb_content.items():
                                if isinstance(ct_val, dict):
                                    schema = ct_val.get("schema", {})
                                    if isinstance(schema, dict):
                                        props = schema.get("properties", {})
                                        for prop_name in props:
                                            all_params.append(prop_name)

        content = PageContent(
            url=url,
            status_code=response.status_code,
            html_size=len(response.text) if hasattr(response, 'text') else 0,
            title=body.get("info", {}).get("title", "API Documentation"),
            forms=forms,
            input_params=list(dict.fromkeys(all_params)),
            js_endpoints=js_endpoints,
            links=js_endpoints,
            html_comments=[],
            response_headers=dict(response.headers) if hasattr(response, 'headers') else {},
            tech_fingerprint=["openapi"],
            body_preview=response.text[:2000] if hasattr(response, 'text') else "",
        )
        content.page_type = "api_doc"
        return content


class GraphQLIntrospectStrategy(PageExtractionStrategy):
    """
    GraphQL 内省查询策略

    适用: /graphql 端点 + JSON响应 + data.__schema
    方法: POST __schema introspection query → 提取Query/Mutation/fields
    """

    name = "graphql_introspect"

    async def can_handle(self, response, url: str) -> bool:
        ct = response.headers.get("content-type", "")
        if "application/json" not in ct:
            return False
        text = response.text if hasattr(response, 'text') else ""
        return '"data"' in text and ('"__schema"' in text or '"__typename"' in text)

    async def extract(
        self, url: str, response, context: Any = None
    ) -> PageContent:
        """
        发送GraphQL introspection query获取完整schema。

        注意: introspection在生产环境中通常被禁用。
        如果不可用，退回到从错误消息中推断。
        """
        import json
        import httpx

        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name fields { name args { name type { name kind } } } }
            mutationType { name fields { name args { name type { name kind } } } }
            types { name kind fields { name args { name type { name kind } } } }
          }
        }
        """

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    url,
                    json={"query": introspection_query},
                    headers={"Content-Type": "application/json"},
                )
                schema = resp.json()
        except Exception:
            schema = {}

        all_params: list[str] = []
        js_endpoints: list[str] = []

        data = schema.get("data", {}).get("__schema", {})
        for type_key in ("queryType", "mutationType"):
            type_data = data.get(type_key, {})
            if isinstance(type_data, dict):
                for field in type_data.get("fields", []):
                    field_name = field.get("name", "")
                    if field_name:
                        js_endpoints.append(f"{type_key}:{field_name}")
                    for arg in field.get("args", []):
                        arg_name = arg.get("name", "")
                        if arg_name:
                            all_params.append(arg_name)

        content = PageContent(
            url=url,
            status_code=200,
            html_size=len(json.dumps(schema)) if schema else 0,
            title="GraphQL API",
            forms=[],
            input_params=list(dict.fromkeys(all_params)),
            js_endpoints=js_endpoints,
            links=js_endpoints,
            html_comments=[],
            response_headers={},
            tech_fingerprint=["graphql"],
            body_preview=json.dumps(schema)[:2000] if schema else "",
        )
        content.page_type = "api_doc"
        return content


class StaticSiteStrategy(PageExtractionStrategy):
    """
    纯静态站点策略

    适用: 无表单、无input、无JS框架、无API端点
    方法: 快速判定 → 标记为static → 跳过深度扫描
    """

    name = "static_site"

    async def can_handle(self, response, url: str) -> bool:
        """总是返回True作为fallback，但extract中会判定是否真的为静态"""
        return True

    async def extract(
        self, url: str, response, context: Any = None
    ) -> PageContent:
        html = response.text if hasattr(response, 'text') else ""
        ct = response.headers.get("content-type", "") if hasattr(response, 'headers') else ""

        # 快速判定: 如果不是HTML，直接标记为static
        if "text/html" not in ct:
            return PageContent(
                url=url, status_code=response.status_code,
                html_size=len(html) if html else 0,
                page_type="static",
                response_headers=dict(response.headers) if hasattr(response, 'headers') else {},
            )

        # 检查是否有交互元素
        forms = self._extract_forms(html)
        has_inputs = bool(re.search(r'<(?:input|textarea|select)\b', html, re.IGNORECASE))
        has_js_interaction = bool(re.search(
            r'(?:fetch|XMLHttpRequest|axios|\.post\(|\.get\()',
            html,
        ))

        if not forms and not has_inputs and not has_js_interaction:
            return PageContent(
                url=url,
                status_code=response.status_code,
                html_size=len(html),
                title="Static Page",
                page_type="static",
                links=self._extract_links(html, url),
                response_headers=dict(response.headers) if hasattr(response, 'headers') else {},
                tech_fingerprint=self._detect_tech(html, dict(response.headers) if hasattr(response, 'headers') else {}),
            )

        # 不是纯静态，委托给HTMLFormStrategy
        fallback = HTMLFormStrategy()
        content = await fallback.extract(url, response, context)
        return content


# ──── 策略选择器 ────

STRATEGY_REGISTRY: list[PageExtractionStrategy] = [
    GraphQLIntrospectStrategy(),
    OpenAPIStrategy(),
    SPADOMStrategy(),
    HTMLFormStrategy(),
    StaticSiteStrategy(),  # fallback, always last
]


# ──── PageContentExtractor (主入口) ────

class PageContentExtractor:
    """
    深层页面侦察引擎 (主入口)

    使用策略模式自动检测目标类型并提取页面内容。

    Usage:
        extractor = PageContentExtractor()
        contents = await extractor.extract(url, httpx_response)
        for pc in contents:
            print(f"{pc.url}: {len(pc.forms)} forms, {len(pc.input_params)} params")
    """

    def __init__(
        self,
        max_depth: int = 2,
        max_pages: int = 20,
        strategies: list[PageExtractionStrategy] | None = None,
    ):
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._strategies = strategies or STRATEGY_REGISTRY

    async def extract_single(
        self, url: str, response, context: Any = None
    ) -> PageContent:
        """
        提取单个页面的内容。
        自动选择最佳策略。
        """
        for strategy in self._strategies:
            try:
                if await strategy.can_handle(response, url):
                    logger.debug(
                        "PageContentExtractor: using %s for %s",
                        strategy.name, url,
                    )
                    return await strategy.extract(url, response, context)
            except Exception as e:
                logger.warning("Strategy %s failed for %s: %s", strategy.name, url, e)
                continue

        # 最终fallback: 空内容
        return PageContent(
            url=url,
            status_code=response.status_code if hasattr(response, 'status_code') else 0,
            html_size=0,
            page_type="unknown",
        )

    async def extract(
        self,
        url: str,
        initial_response,
        context: Any = None,
    ) -> list[PageContent]:
        """
        深度提取目标页面及其可达子页面的内容。

        1. 提取目标页面
        2. 爬取可达链接 (max_depth限制)
        3. 去重汇总返回
        """
        import httpx

        results: list[PageContent] = []
        visited: set[str] = {url}
        queue: list[tuple[str, int]] = [(url, 0)]

        while queue and len(results) < self._max_pages:
            current_url, depth = queue.pop(0)

            try:
                if current_url == url and initial_response:
                    resp = initial_response
                else:
                    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                        resp = await client.get(current_url)

                content = await self.extract_single(current_url, resp, context)
                results.append(content)

                # 如果页面是static/error，不继续爬取其链接
                if content.page_type in ("static", "error"):
                    continue
                if depth >= self._max_depth:
                    continue

                # 递归爬取链接
                for link in content.links[:10]:  # 每个页面最多跟踪10个链接
                    if link not in visited and len(results) < self._max_pages:
                        visited.add(link)
                        queue.append((link, depth + 1))

            except Exception as e:
                logger.warning("Failed to extract %s: %s", current_url, e)
                continue

        return results


# ──── 便捷函数 ────

def extract_forms_from_html(html: str) -> list[FormInfo]:
    """便捷函数: 从HTML字符串中提取表单 (无需策略选择)"""
    strategy = HTMLFormStrategy()
    return strategy._extract_forms(html)


def extract_links_from_html(html: str, base_url: str) -> list[str]:
    """便捷函数: 从HTML字符串中提取链接"""
    strategy = HTMLFormStrategy()
    return strategy._extract_links(html, base_url)
