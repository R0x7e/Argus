"""
Orchestrator 节点

LangGraph 图中的总指挥节点。负责：
1. 首次运行时调用侦察工具（子域名枚举、端口扫描、目录扫描）分析目标
2. 将工具结果交给 LLM 生成结构化目标画像和攻击面
3. 评估当前进度，决定下一步行动
4. 当达到最大迭代或有足够发现时，决定结束
"""
import re
import json
import logging
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.agents.emit import emit
from app.agents.llm import LLMClient
from app.agents.prompts.orchestrator import ORCHESTRATOR_SYSTEM_PROMPT
from app.agents.state import SlotStatus, VulnHuntState
from app.tools.base import ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)

_llm_client: LLMClient | None = None



# ──── P0: 链接分类与评分系统 ────

# 静态资源后缀 (在提取阶段直接过滤)
_STATIC_ASSET_PATTERN = re.compile(
    r'\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|pdf|zip|mp4|webp|webm)'
    r'(\?|#|$)', re.IGNORECASE
)

# 链接类别定义及基础优先级
_LINK_CATEGORY_PRIORITY: dict[str, float] = {
    "vuln_page": 1.0,
    "api_endpoint": 0.9,
    "auth_page": 0.85,
    "dynamic_page": 0.8,
    "form_handler": 0.75,
    "admin_page": 0.7,
    "static_page": 0.5,
    "config_leak": 0.3,
    "static_asset": 0.0,   # 直接过滤
}

# 漏洞关键词 (URL 路径明确暗示漏洞类型)
_VULN_PATH_KEYWORDS = [
    'sqli', 'sql', 'xss', 'rce', 'cmd', 'exec', 'upload', 'fileinclude',
    'fi_local', 'fi_remote', 'ssrf', 'csrf', 'xxe', 'ssti', 'unser',
    'overpermission', 'idor', 'burteforce', 'brute', 'infoleak',
    'unsafedownload', 'unsafeupload', 'urlredirect', 'dir',
]

# 配置/版本控制路径模式
_CONFIG_PATH_PATTERNS = [
    '.git/', '.gitconfig', '.env', '.svn/', '.hg/', '.bzr/',
    'dockerfile', 'docker-compose', '.htaccess', '.htpasswd',
    'robots.txt', 'sitemap', 'composer.lock', 'package-lock',
    'yarn.lock', 'Gemfile.lock', '.DS_Store', 'backup', 'dump',
    'phpinfo', 'info.php', 'test.php',
]


def _classify_link(link: str) -> str:
    """将链接分类到预定义类别"""
    link_lower = link.lower()

    # 静态资源 (直接过滤)
    if _STATIC_ASSET_PATTERN.search(link):
        return "static_asset"

    # 配置/版本控制泄露
    if any(p in link_lower for p in _CONFIG_PATH_PATTERNS):
        return "config_leak"

    # 漏洞测试页面 (路径含 vul/ 或已知漏洞关键词)
    if '/vul/' in link_lower or '/vuln/' in link_lower:
        return "vuln_page"
    if any(f'/{kw}' in link_lower or link_lower.startswith(f'{kw}/')
           for kw in _VULN_PATH_KEYWORDS):
        return "vuln_page"

    # API 端点
    if any(seg in link_lower for seg in ('/api/', '/ajax/', '/rest/', '/graphql', '/rpc/')):
        return "api_endpoint"

    # 认证页面
    if any(kw in link_lower for kw in ('login', 'signin', 'auth', 'register', 'signup')):
        return "auth_page"

    # 管理页面
    if any(kw in link_lower for kw in ('admin', 'manage', 'dashboard', 'config', 'setting')):
        return "admin_page"

    # 动态页面 (含文件扩展名)
    if re.search(r'\.(php|asp|aspx|jsp|py|pl|cgi|do|action|cfm|rb)(\?|#|$)', link, re.I):
        return "dynamic_page"

    # 表单处理器
    if any(kw in link_lower for kw in ('submit', 'post', 'save', 'update', 'delete', 'create')):
        return "form_handler"

    # 其余有扩展名的视为静态页面
    if '.' in link.split('/')[-1]:
        return "static_page"

    # 无扩展名但有目录结构
    if '/' in link:
        return "form_handler"  # 可能是 RESTful 端点

    return "static_page"


def _score_link(link: str, category: str) -> float:
    """对链接进行质量评分 (0.0-1.0)"""
    base = _LINK_CATEGORY_PRIORITY.get(category, 0.3)
    link_lower = link.lower()

    # 加分项
    if '?' in link:
        base += 0.1                          # 带 query string → 高度可注入
    if any(p in link_lower for p in ('id=', 'q=', 'cmd=', 'file=', 'url=', 'page=')):
        base += 0.1                          # 常见注入参数
    if re.search(r'\.(php|asp|aspx|jsp|py)(\?|#|$)', link, re.I):
        base += 0.05                         # 动态脚本语言

    # 减分项
    if link.count('/') <= 1 and category not in ('vuln_page', 'auth_page'):
        base -= 0.1                          # 浅路径 → 大概率不是注入点
    if link_lower in ('/', '/index.php', '/index.html', '/index.asp'):
        base = max(0.3, base - 0.3)          # 首页本身不是好注入目标

    return max(0.0, min(1.0, base))


def _classify_and_score_links(all_links: list[str]) -> dict:
    """对所有链接分类并评分，返回分组排序后的结构化结果"""
    import collections

    categorized: dict[str, list[dict]] = collections.defaultdict(list)

    for link in all_links:
        cat = _classify_link(link)
        if cat == "static_asset":
            continue
        score = _score_link(link, cat)
        categorized[cat].append({"link": link, "score": round(score, 2)})

    # 每类内部按评分降序
    for cat in categorized:
        categorized[cat].sort(key=lambda x: x["score"], reverse=True)

    return dict(categorized)


def _extract_smart_body_snippets(html: str, max_snippets: int = 8) -> list[str]:
    """智能提取页面的关键区域片段 (替代粗暴的 body[:3000])"""
    snippets = []
    html_lower = html.lower()

    # 1. 提取所有 <form> 区域
    for m in re.finditer(r'<form[^>]*>.*?</form>', html, re.I | re.DOTALL):
        snippet = m.group(0)[:500]
        snippets.append(f"[FORM] {snippet}")
        if len(snippets) >= max_snippets:
            break

    # 2. 提取包含 input/textarea/select 的区域 (非 form 内的)
    if len(snippets) < max_snippets:
        for m in re.finditer(
            r'(<(?:input|textarea|select)[^>]*name=["\'][^"\']+["\'][^>]*>)', html, re.I
        ):
            snippet = m.group(0)[:300]
            if snippet not in str(snippets):
                snippets.append(f"[INPUT] {snippet}")
            if len(snippets) >= max_snippets:
                break

    # 3. 提取注释中的敏感信息
    if len(snippets) < max_snippets:
        for m in re.finditer(r'<!--(.*?)-->', html, re.I | re.DOTALL):
            comment = m.group(1).strip()
            if len(comment) > 10 and any(
                kw in comment.lower() for kw in ('todo', 'fix', 'hack', 'debug', 'password',
                                                  'secret', 'key', 'sql', 'query')
            ):
                snippets.append(f"[COMMENT] {comment[:300]}")
            if len(snippets) >= max_snippets:
                break

    # 4. 提取 JavaScript 中的端点引用
    if len(snippets) < max_snippets:
        js_matches = re.findall(
            r'''(?:fetch|axios\.\w+|\.post|\.get|\.ajax)\s*\(\s*["']([^"']+)["']''',
            html, re.I
        )
        for js_url in js_matches[:3]:
            snippets.append(f"[JS_ENDPOINT] {js_url}")

    return snippets


def _extract_links(html: str) -> list[str]:
    """从 HTML 中提取所有链接路径 (P0: 分类评分版, 不排序)

    L1-fix: 保留 query string — 旧实现用 split("?")[0] 丢弃了 query,
    导致下游 _extract_params_from_links 永远解析不到参数(params 恒为 0)。
    """
    links = set()
    for match in re.finditer(r'(?:href|action|src)=["\']([^"\'#]+)["\']', html, re.IGNORECASE):
        link = match.group(1)
        if link.startswith(("javascript:", "mailto:", "data:", "tel:")):
            continue

        # P5: 静态资源在提取阶段即过滤
        if _STATIC_ASSET_PATTERN.search(link):
            continue

        # 保留带 query string 的完整链接 (供 params 提取)
        if link.startswith("/") or link.startswith("http"):
            links.add(link)
        # P5: 相对路径 — 含有文件扩展名或目录结构的都保留
        elif "/" in link or "." in link:
            links.add(link)

    return list(links)  # 不排序, 由分类器排序


def _extract_forms(html: str) -> list[dict]:
    """从 HTML 中提取表单信息（action + 参数名 + method）

    L1-fix: 旧正则强制要求 action="..." 属性, 但 DVWA/Pikachu 等单页靶机
    表单常无 action (默认提交当前页) → forms 恒为 0。
    改为匹配 <form ...>...</form> 整块, action 缺失时默认空字符串
    (由调用方按 current page URL 解析)。
    """
    forms = []
    form_pattern = re.compile(
        r'<form([^>]*)>(.*?)</form>',
        re.IGNORECASE | re.DOTALL,
    )
    input_pattern = re.compile(
        r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    method_pattern = re.compile(r'method=["\']([^"\']+)["\']', re.IGNORECASE)
    action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)

    for form_match in form_pattern.finditer(html):
        form_tag = form_match.group(1) or ""
        form_body = form_match.group(2) or ""
        action_m = action_pattern.search(form_tag)
        action = action_m.group(1) if action_m else ""
        method_m = method_pattern.search(form_tag)
        method = method_m.group(1).upper() if method_m else "GET"
        params = input_pattern.findall(form_body)
        if action or params:
            forms.append({
                "action": action,
                "method": method,
                "params": params,
                "form_fields": list(params),  # L2 完整表单字段集
            })
    return forms


def _extract_params_from_links(links: list[str]) -> list[dict]:
    """从 URL 列表中提取参数名"""
    from urllib.parse import parse_qs, urlparse
    params = []
    for link in links:
        if "?" not in link and "=" not in link:
            continue
        try:
            parsed = urlparse(link) if link.startswith("http") else urlparse(f"http://x{link}")
            qs = parse_qs(parsed.query)
            for name in qs:
                params.append({"url": link.split("?")[0], "name": name, "sample_value": qs[name][0]})
        except Exception:
            continue
    return params


def _get_llm_client() -> LLMClient:
    """获取或创建 LLM 客户端单例"""
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client


def _build_execution_context(state: VulnHuntState) -> ExecutionContext:
    """从状态中构建工具执行上下文"""
    task_id = state["task_id"]
    bb = state["blackboard"]

    # 从 task_config 或 target_profile 中提取目标 URL
    task_config = state.get("task_config", {}) or {}
    target_url = task_config.get("target_url", "")

    if not target_url and bb.target_profile:
        target_url = bb.target_profile.get("base_url", "")

    parsed = urlparse(target_url)
    host = parsed.hostname or "localhost"

    return ExecutionContext(
        task_id=task_id,
        target_host=host,
        timeout=60,
        max_retries=2,
        allowed_hosts=[host],
    )


def _derive_scan_origin(target_url: str) -> str:
    """L1-fix: 计算 dir_scan 的扫描基点 — 剥离文件名, 取所在目录。

    避免把单页脚本(如 .../sqli_id.php)当目录爆破,
    产生 "sqli_id.php/.git" 这类 PATH_INFO bogus 目录。

    - http://h/a/b/sqli_id.php → http://h/a/b
    - http://h/a/b/            → http://h/a/b
    - http://h/a               → http://h (无路径)
    - 含 query 的同样剥离 query
    """
    try:
        parsed = urlparse(target_url)
    except Exception:
        return target_url.rstrip("/") or target_url
    path = parsed.path or "/"
    # 取最后一段, 若像文件名(含 .) 则上一级
    last_seg = path.rstrip("/").rsplit("/", 1)[-1]
    if "." in last_seg:
        base_path = path.rsplit("/", 1)[0]  # 去掉文件名段
        if not base_path:
            base_path = ""
    else:
        base_path = path.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}{base_path}"


async def _run_recon_tool(tool_name: str, params: dict, context: ExecutionContext) -> dict:
    """安全执行侦察工具，捕获异常"""
    from app.tools import tool_registry

    tool = tool_registry.get(tool_name)
    if tool is None:
        return {"success": False, "error": f"工具 {tool_name} 未注册"}

    if tool.risk_level > RiskLevel.L0:
        return {"success": False, "error": f"侦察阶段仅允许 L0 工具，{tool_name} 为 {tool.risk_level.name}"}

    try:
        result = await tool.execute(params, context)
        return result
    except Exception as e:
        logger.warning("侦察工具 %s 执行异常: %s", tool_name, str(e))
        return {"success": False, "error": str(e)}


async def _run_reconnaissance(state: VulnHuntState) -> dict:
    """
    执行侦察阶段：对目标 URL 进行深度侦察

    SRC 模式下不做子域名枚举和端口扫描，但增加：
    1. 目录扫描 + 首页探测（第一层）
    2. 递归抓取首页链接（第二层，最多 15 个页面）
    3. 收集所有发现的参数名和表单
    """
    import asyncio
    import re

    context = _build_execution_context(state)
    target_host = context.target_host
    task_config = state.get("task_config", {}) or {}
    target_url = task_config.get("target_url", f"http://{target_host}")

    recon_results = {
        "subdomains": [],
        "open_ports": [],
        "directories": [],
        "homepage_info": {},
        "crawled_pages": [],
        "parameters": [],
        "forms": [],
        "tools_run": [],
        "errors": [],
    }

    # === 第一层：目录扫描 + 首页请求 ===
    # L1-fix: dir_scan 不能把单页 target_url 当 base — 否则 wordlist 拼到
    # ".../sqli_id.php/.git" 产生 bogus 目录 (Pikachu 对任意路径回 200)。
    # 改为剥离文件名, 取所在目录作为扫描基点。
    scan_origin = _derive_scan_origin(target_url)

    recon_results["tool_health"] = {
        "dir_scan": "unknown", "deep_crawl": "unknown",
        "playwright": "unknown", "http": "unknown",
    }

    # 审计修正: Katana 与 dir_scan + http_request 并行执行
    tasks = [
        _run_recon_tool("dir_scan", {"base_url": scan_origin}, context),
        _run_recon_tool("http_request", {"url": target_url, "method": "GET"}, context),
        _run_recon_tool("katana_crawl", {
            "url": target_url, "depth": 2, "headless": True,
            "max_count": 200, "timeout": 90,
        }, context),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # 处理目录扫描结果
    dir_result = results[0]
    if isinstance(dir_result, dict) and dir_result.get("success"):
        found_paths = dir_result.get("found_paths", [])
        recon_results["directories"] = [p.get("path", p) if isinstance(p, dict) else p for p in found_paths]
        recon_results["tools_run"].append("dir_scan")
        recon_results["tool_health"]["dir_scan"] = "ok"
    elif isinstance(dir_result, dict):
        recon_results["errors"].append(f"dir_scan: {dir_result.get('error', 'unknown')}")
        recon_results["tool_health"]["dir_scan"] = f"failed:{dir_result.get('error', 'unknown')[:40]}"

    # 处理首页请求结果 — 并行收集 + 强制构建
    homepage_result = results[1]
    all_links_set: set[str] = set()
    all_forms: list[dict] = []
    all_params: list[dict] = []
    body = ""
    hp_status = 0
    hp_headers: dict = {}

    # 来源 1: http_request 工具
    if isinstance(homepage_result, dict) and homepage_result.get("success"):
        body = homepage_result.get("body", "") or ""
        hp_status = homepage_result.get("status_code", 0)
        hp_headers = homepage_result.get("headers", {}) or {}
        l1 = _extract_links(body) if body else []
        all_links_set.update(l1)
        if body:
            all_forms.extend(_extract_forms(body))
            all_params.extend(_extract_params_from_links(l1))
        logger.info("来源1 工具: %d links, %d forms", len(l1), len(all_forms))
        recon_results["tool_health"]["http"] = "ok"
    elif isinstance(homepage_result, dict):
        recon_results["errors"].append(f"http_request: {homepage_result.get('error', 'unknown')}")
        recon_results["tool_health"]["http"] = f"failed:{homepage_result.get('error', 'unknown')[:40]}"

    # 来源 2: httpx 直连 (始终执行, 补充工具层可能遗漏的链接)
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.get(target_url)
            if resp.status_code == 200:
                if not body:
                    body = resp.text
                    hp_status = resp.status_code
                    hp_headers = dict(resp.headers)
                l2 = _extract_links(resp.text)
                all_links_set.update(l2)
                all_forms.extend(_extract_forms(resp.text))
                all_params.extend(_extract_params_from_links(l2))
                logger.info("来源2 httpx: %d links (total unique: %d)", len(l2), len(all_links_set))
    except Exception as e:
        logger.warning("来源2 httpx 失败: %s", e)

    # 来源 3: Playwright DOM 渲染 (links 少时)
    if len(all_links_set) < 20:
        try:
            from app.core.playwright_manager import get_browser
            browser = get_browser()
            bctx = await browser.new_context(ignore_https_errors=True)
            page = await bctx.new_page()
            await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            pw_body = await page.content()
            l3 = _extract_links(pw_body)
            all_links_set.update(l3)
            all_forms.extend(_extract_forms(pw_body))
            all_params.extend(_extract_params_from_links(l3))
            await bctx.close()
            logger.info("来源3 Playwright DOM: %d links (total unique: %d)", len(l3), len(all_links_set))
            recon_results["tool_health"]["playwright"] = "ok"
            if not body:
                body = pw_body
        except Exception as e:
            logger.warning("来源3 Playwright 失败: %s", e)
            recon_results["tool_health"]["playwright"] = f"unavailable:{str(e)[:40]}"

    # 来源 4: Playwright JS 直接提取 (终极兜底, links < 5 时)
    if len(all_links_set) < 5:
        try:
            from app.core.playwright_manager import get_browser
            browser = get_browser()
            bctx = await browser.new_context(ignore_https_errors=True)
            page = await bctx.new_page()
            await page.goto(target_url, wait_until="networkidle", timeout=20000)
            js_links = await page.evaluate("""() => {
                const links = new Set();
                document.querySelectorAll('a[href]').forEach(a => {
                    const href = a.getAttribute('href');
                    if (href && !href.startsWith('javascript:') && !href.startsWith('#') && href.length > 1)
                        links.add(href);
                });
                document.querySelectorAll('form[action]').forEach(f => {
                    const action = f.getAttribute('action');
                    if (action && action.length > 1) links.add(action);
                });
                return [...links];
            }""")
            all_links_set.update(js_links or [])
            await bctx.close()
            logger.info("来源4 Playwright JS: %d links (total unique: %d)", len(js_links or []), len(all_links_set))
        except Exception as e:
            logger.warning("来源4 Playwright JS 失败: %s", e)

    # 强制构建 homepage_info — 即使链接少也构建
    all_links = list(all_links_set)
    categorized = _classify_and_score_links(all_links) if all_links else {}
    scored_links = []
    for cat_items in categorized.values():
        scored_links.extend(cat_items)
    scored_links.sort(key=lambda x: x["score"], reverse=True)
    top_scored_paths = [item["link"] for item in scored_links[:60]]
    smart_snippets = _extract_smart_body_snippets(body) if body else []

    recon_results["homepage_info"] = {
        "status_code": hp_status or (homepage_result.get("status_code") if isinstance(homepage_result, dict) else 0),
        "headers": hp_headers or (homepage_result.get("headers", {}) if isinstance(homepage_result, dict) else {}),
        "body_preview": body[:3000] if body else "",
        "smart_snippets": smart_snippets,
        "links": top_scored_paths[:50],
        "categorized_links": {cat: items[:60] for cat, items in categorized.items()},
        "total_links": len(all_links),
        "forms_count": len(all_forms),
        "params_count": len(all_params),
    }
    recon_results["forms"] = all_forms
    recon_results["parameters"] = all_params
    if isinstance(homepage_result, dict) and homepage_result.get("success"):
        recon_results["tools_run"].append("http_request")

    logger.info("首页提取完成: %d links, %d forms, %d params (categorized: %s)",
                len(all_links), len(all_forms), len(all_params),
                {cat: len(items) for cat, items in categorized.items()})

    # Katana 爬取结果处理 (results[2], 与 dir_scan + http_request 并行)
    katana_result = results[2] if len(results) > 2 else None
    if isinstance(katana_result, dict) and katana_result.get("success"):
        katana_urls = katana_result.get("urls", [])
        katana_forms = katana_result.get("forms", [])
        katana_js = katana_result.get("js_endpoints", [])
        katana_params = katana_result.get("params", [])

        # 注入 URL 到 crawled_pages
        for kurl in katana_urls[:150]:
            existing = [p for p in recon_results.get("crawled_pages", [])
                        if (isinstance(p, dict) and p.get("url") == kurl)]
            if not existing:
                recon_results.setdefault("crawled_pages", [])
                recon_results["crawled_pages"].append({"url": kurl, "source": "katana"})

        # 注入 JS 端点到 homepage_info.categorized_links (标准化后)
        if katana_js:
            homepage = recon_results.get("homepage_info", {})
            cat_links = homepage.setdefault("categorized_links", {})
            cat_links.setdefault("api_endpoint", [])
            for js_ep in katana_js[:30]:
                # URL 标准化
                from urllib.parse import urljoin as _urljoin
                norm_ep = _urljoin(target_url, js_ep)
                if not any(item.get("link") == norm_ep for item in cat_links["api_endpoint"]):
                    cat_links["api_endpoint"].append({"link": norm_ep, "score": 0.85})

        # 注入表单 (去重合并)
        for kf in katana_forms[:20]:
            existing = [f for f in recon_results.get("forms", [])
                        if f.get("action") == kf.get("action")]
            if not existing:
                recon_results.setdefault("forms", [])
                recon_results["forms"].append({
                    "action": kf["action"],
                    "method": kf.get("method", "GET"),
                    "params": kf.get("inputs", []),
                    "source": "katana",
                })

        # 注入参数名
        for pname in katana_params:
            recon_results.setdefault("parameters", [])
            if not any(isinstance(p, dict) and p.get("name") == pname
                       for p in recon_results["parameters"]):
                recon_results["parameters"].append({
                    "name": pname, "url": target_url, "source": "katana",
                })

        recon_results["tools_run"].append("katana_crawl")
        recon_results["tool_health"]["katana"] = "ok"
        logger.info(
            "Katana: %d URLs, %d JS endpoints, %d forms 注入",
            len(katana_urls), len(katana_js), len(katana_forms),
        )
    elif isinstance(katana_result, dict):
        recon_results["tool_health"]["katana"] = f"failed:{katana_result.get('error', 'unknown')[:40]}"
        logger.warning("Katana 失败 (非致命): %s", katana_result.get("error", "unknown")[:200])
    elif isinstance(katana_result, Exception):
        recon_results["tool_health"]["katana"] = f"exception:{str(katana_result)[:40]}"
        logger.warning("Katana 异常 (非致命): %s", str(katana_result)[:200])
    # === 第二层：递归抓取发现的链接（P0: 评分排序优先爬取高分端点, 最多 15 个） ===
    crawl_targets = []
    base_parsed = urlparse(target_url)
    for link in top_scored_paths[:15]:
        if link.startswith("/"):
            full_url = f"{base_parsed.scheme}://{base_parsed.netloc}{link}"
        elif link.startswith("http"):
            full_url = link
        else:
            # v2/L1-P1c: 用 urljoin 规范相对路径解析 — 治 R3 源头。
            # 旧实现 f"{target_url.rstrip('/')}/{link}" 直接拼, 产生
            # rce_ping.php/../../vul/x.php 这类 bogus 双重路径。
            # urljoin 会正确处理 . / .. / 当前 path。
            from urllib.parse import urljoin
            full_url = urljoin(target_url, link)
        if base_parsed.netloc not in full_url:
            continue
        if re.search(r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|ttf|pdf|zip)$', full_url, re.I):
            continue
        crawl_targets.append(full_url)

    if crawl_targets:
        crawl_tasks = [
            _run_recon_tool("http_request", {"url": url, "method": "GET"}, context)
            for url in crawl_targets[:15]
        ]
        crawl_results = await asyncio.gather(*crawl_tasks, return_exceptions=True)

        for i, cr in enumerate(crawl_results):
            if isinstance(cr, dict) and cr.get("success"):
                page_body = cr.get("body", "") or ""
                page_links = _extract_links(page_body)
                page_forms = _extract_forms(page_body)
                page_params = _extract_params_from_links(page_links)
                recon_results["crawled_pages"].append({
                    "url": crawl_targets[i],
                    "status": cr.get("status_code"),
                    "links_count": len(page_links),
                    "forms_count": len(page_forms),
                })
                # 合并新发现的链接和参数
                for link in page_links:
                    if link not in all_links:
                        all_links.append(link)
                recon_results["forms"].extend(page_forms)
                recon_results["parameters"].extend(page_params)

        recon_results["tools_run"].append("recursive_crawl")

    # === 第2.5层: Playwright 渲染参数提取 (v9: 遍历子页面) ===
    playwright_params = []
    playwright_forms = []
    try:
        from app.core.playwright_manager import get_browser
        browser = get_browser()
        pages_to_probe = [target_url] + [p.get("url", "") for p in recon_results.get("crawled_pages", [])[:5] if p.get("url")]
        for probe_url in pages_to_probe[:4]:
            try:
                bctx = await browser.new_context(ignore_https_errors=True)
                page = await bctx.new_page()
                await page.goto(probe_url, wait_until="domcontentloaded", timeout=10000)
                pw_inputs = await page.evaluate("""() => {
                    return [...document.querySelectorAll('input,textarea,select,button')]
                        .map(el => ({name: el.name || el.id, type: el.type || el.tagName.toLowerCase()}))
                        .filter(x => x.name);
                }""")
                for inp in (pw_inputs or [])[:20]:
                    playwright_params.append({"name": inp["name"], "type": inp["type"], "source": "playwright"})
                pw_forms = await page.evaluate("""() => {
                    return [...document.querySelectorAll('form')].map(f => ({
                        action: f.action, method: (f.method || 'GET').toUpperCase(),
                        inputs: [...f.querySelectorAll('input,textarea,select')].map(i => i.name || i.id).filter(Boolean)
                    }));
                }""")
                for fm in (pw_forms or [])[:5]:
                    playwright_forms.append(fm)
                    for pname in fm.get("inputs", []):
                        if not any(p.get("name") == pname for p in playwright_params):
                            playwright_params.append({"name": pname, "type": "form_input", "source": "playwright_form"})
                await bctx.close()
            except Exception:
                pass
        logger.info("Playwright params: %d from %d pages", len(playwright_params), len(pages_to_probe))
        if playwright_params:
            recon_results["parameters"].extend(playwright_params)
            recon_results["tools_run"].append("playwright_params")
        recon_results["tool_health"]["playwright"] = "ok"
        if playwright_forms:
            recon_results["forms"].extend(playwright_forms)
    except Exception as e:
        logger.warning("Playwright param extraction failed: %s", str(e))
        if recon_results.get("tool_health", {}).get("playwright") == "unknown":
            recon_results["tool_health"]["playwright"] = f"unavailable:{str(e)[:40]}"

    # 去重参数
    seen_params = set()
    unique_params = []
    for p in recon_results["parameters"]:
        key = f"{p.get('url', '')}:{p.get('name', '')}"
        if key not in seen_params:
            seen_params.add(key)
            unique_params.append(p)
    recon_results["parameters"] = unique_params[:100]

    # P2-1: deep_crawl (crawlergo) 深度爬取 — 自动触发 JS 事件和填充表单
    try:
        from app.tools import tool_registry
        deep_crawl_tool = tool_registry.get("deep_crawl")
        if deep_crawl_tool:
            dc_result = await deep_crawl_tool.execute({
                "url": target_url,
                "max_count": 500,
                "timeout": 60,
            }, context)
            if dc_result.get("success"):
                dc_urls = dc_result.get("urls", []) or []
                dc_forms = dc_result.get("forms", []) or []
                dc_params = dc_result.get("parameters", []) or []
                # 合并 deep_crawl 发现的 URL
                for u in dc_urls[:50]:
                    if isinstance(u, dict):
                        url_str = u.get("url", "")
                    elif isinstance(u, str):
                        url_str = u
                    else:
                        url_str = ""
                    if url_str and url_str not in all_links:
                        all_links.append(url_str)
                # 合并表单
                for fm in dc_forms[:20]:
                    if isinstance(fm, dict) and fm not in recon_results["forms"]:
                        recon_results["forms"].append(fm)
                # 合并参数
                for p in dc_params[:20]:
                    if isinstance(p, dict):
                        pname = p.get("name", "")
                    elif isinstance(p, str):
                        pname = p
                    else:
                        pname = ""
                    if pname:
                        p_entry = {"name": pname, "type": "deep_crawl", "source": "crawlergo"}
                        key = f":{pname}"
                        if key not in seen_params:
                            seen_params.add(key)
                            unique_params.append(p_entry)
                recon_results["tools_run"].append("deep_crawl")
                recon_results["tool_health"]["deep_crawl"] = "ok"
                logger.info("deep_crawl: %d URLs, %d forms, %d params",
                            len(dc_urls), len(dc_forms), len(dc_params))
    except Exception as e:
        logger.warning("deep_crawl 执行失败: %s", str(e))
        recon_results["tool_health"]["deep_crawl"] = f"failed:{str(e)[:40]}"
    recon_results["parameters"] = unique_params[:100]

    # 更新 homepage_info 中的 links 为完整集合
    recon_results["homepage_info"]["all_discovered_links"] = all_links[:100]

    logger.info(
        "侦察完成: %d 目录, %d 页面已爬取, %d 参数, %d 表单",
        len(recon_results["directories"]),
        len(recon_results["crawled_pages"]),
        len(recon_results["parameters"]),
        len(recon_results["forms"]),
    )

    return recon_results


async def orchestrator_node(state: VulnHuntState) -> dict:
    """
    总指挥节点

    根据黑板当前状态做出调度决策：
    - 若目标画像为空 → 调用侦察工具 + LLM 创建画像和攻击面
    - 若已有验证结果 → 评估进度，决定继续还是生成报告
    - 若达到最大迭代次数 → 转入报告阶段
    """
    bb = state["blackboard"]
    iteration = state["iteration_count"]
    max_iter = state["max_iterations"]
    task_id = state["task_id"]

    logger.info(
        "Orchestrator 启动 - 任务 [%s], 迭代 %d/%d",
        task_id,
        iteration,
        max_iter,
    )

    events = []

    await emit(task_id, "orchestrator", "agent_started", {
        "node": "orchestrator", "iteration": iteration,
    })

    # ---- 场景 1: 首次运行，目标画像为空 → 侦察 + 分析 ----
    if not bb.target_profile:
        logger.info("目标画像为空，执行侦察阶段...")

        await emit(task_id, "orchestrator", "tool_call", {
            "tool_name": "reconnaissance_suite",
            "params": {"tools": ["dir_scan", "http_request"]},
        })

        # Step 1: 执行侦察工具 (不变)
        recon_results = await _run_reconnaissance(state)

        await emit(task_id, "orchestrator", "tool_result", {
            "tool_name": "reconnaissance_suite",
            "success": True,
            "summary": f"发现 {len(recon_results['directories'])} 目录, "
                       f"{len(recon_results.get('crawled_pages', []))} 页面已爬取, "
                       f"{len(recon_results.get('parameters', []))} 参数, "
                       f"{len(recon_results.get('forms', []))} 表单",
        })

        recon_event_data = {
            "tools_run": recon_results["tools_run"],
            "dirs_found": len(recon_results["directories"]),
            "pages_crawled": len(recon_results.get("crawled_pages", [])),
            "params_found": len(recon_results.get("parameters", [])),
            "forms_found": len(recon_results.get("forms", [])),
            "homepage_status": recon_results["homepage_info"].get("status_code"),
            "errors": recon_results["errors"],
        }
        await emit(task_id, "orchestrator", "recon_complete", recon_event_data)
        events.append({
            "id": str(uuid.uuid4()),
            "agent": "orchestrator",
            "type": "recon_complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": recon_event_data,
        })

        task_config = state.get("task_config", {}) or {}
        target_url = task_config.get("target_url", "")

        # Step 2 (NEW): 工具驱动攻击面构造 — 零 LLM
        await emit(task_id, "orchestrator", "thinking", {
            "content": "正在基于侦察数据构造攻击面...",
        })

        from app.agents.lats.attack_surface_builder import build_attack_surface
        surface = await build_attack_surface(recon_results, target_url, task_id)

        await emit(task_id, "orchestrator", "progress", {
            "content": f"攻击面构造完成: {surface.total_endpoints} 端点 "
                       f"({surface.vuln_pages} vuln, {surface.auth_pages} auth, "
                       f"跳过 {surface.skipped_forbidden} forbidden, {surface.skipped_not_found} not_found)",
            "step": "attack_surface_built",
        })

        # Step 3 (NEW): LLM 仅提供策略建议 — 不创建端点
        await emit(task_id, "orchestrator", "thinking", {
            "content": "正在分析技术栈并生成策略建议...",
        })

        endpoint_summary = []
        for ep in surface.endpoints[:30]:
            endpoint_summary.append({
                "path": ep["path"],
                "score": round(ep.get("score", 0), 2),
                "category": ep.get("category", "unknown"),
                "compatible_vulns": ep.get("compatible_vuln_types", [])[:5],
                "has_forms": ep.get("has_forms", False),
            })

        smart_snippets = recon_results["homepage_info"].get("smart_snippets", [])
        snippets_text = "\n".join(f"  - {s[:300]}" for s in smart_snippets[:4]) if smart_snippets else "无"

        llm = _get_llm_client()
        advice_messages = [
            {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps({
                "task_id": task_id,
                "target": target_url,
                "tech_indicators": surface.recon_summary.get("tech_indicators", []),
                "server_header": str(
                    surface.recon_summary.get("headers", {}).get("Server", "")
                ),
                "top_endpoints": endpoint_summary,
                "total_endpoints": surface.total_endpoints,
                "vuln_pages": surface.vuln_pages,
                "auth_pages": surface.auth_pages,
                "forms": surface.forms[:5],
                "smart_snippets": snippets_text,
            }, ensure_ascii=False)},
        ]

        response_text = await llm.call(agent="orchestrator", messages=advice_messages, task_id=task_id)
        decision = _parse_orchestrator_response(response_text)

        await emit(task_id, "orchestrator", "progress", {
            "content": f"策略分析完成: {decision.get('strategy', 'unknown')}, "
                       f"focus: {decision.get('focus_vuln_types', [])}",
            "step": "strategy_advice",
        })

        # Step 4: 组装黑板 — 端点来自工具, 策略来自 LLM
        bb.target_profile = {
            "base_url": target_url,
            "tech_stack": decision.get("tech_stack", []),
            "framework": decision.get("framework", ""),
            "server": decision.get("server", ""),
            "waf": decision.get("waf", ""),
            "recon_data": {
                "directories": recon_results["directories"][:50],
                "homepage_info": recon_results["homepage_info"],
            },
        }

        bb.attack_surface = {
            "endpoints": surface.endpoints,  # ← 来自工具, 非 LLM
            "parameters": surface.parameters,
            "forms": surface.forms,
        }
        bb.focus_vuln_types = decision.get("focus_vuln_types", [])
        bb.slot_status["target_profile"] = SlotStatus.READY
        bb.slot_status["attack_surface"] = SlotStatus.READY
        bb.version += 1

        profiled_data = {
            "attack_surface_endpoints": len(surface.endpoints),
            "vuln_pages": surface.vuln_pages,
            "auth_pages": surface.auth_pages,
            "strategy": decision.get("strategy", "comprehensive_scan"),
            "focus_vuln_types": decision.get("focus_vuln_types", []),
            "next_action": "hypothesize",
        }
        await emit(task_id, "orchestrator", "target_profiled", profiled_data)
        events.append({
            "id": str(uuid.uuid4()),
            "agent": "orchestrator",
            "type": "target_profiled",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": profiled_data,
        })

        logger.info(
            "目标画像创建完成 (工具驱动攻击面): 策略=%s, 攻击面=%d端点 (%dvuln/%dauth)",
            decision.get("strategy"),
            len(surface.endpoints), surface.vuln_pages, surface.auth_pages,
        )

        await emit(task_id, "orchestrator", "agent_stopped", {"node": "orchestrator"})

        return {
            "blackboard": bb,
            "current_phase": "hypothesizing",
            "iteration_count": iteration,
            "events": events,
        }

    # ---- 场景 2: 达到最大迭代次数 → 结束 ----
    if iteration >= max_iter:
        logger.info("已达最大迭代次数 (%d)，转入报告阶段", max_iter)

        max_iter_data = {
            "iteration": iteration,
            "max_iterations": max_iter,
            "findings_count": len(bb.findings),
        }
        await emit(task_id, "orchestrator", "max_iterations_reached", max_iter_data)
        events.append({
            "id": str(uuid.uuid4()),
            "agent": "orchestrator",
            "type": "max_iterations_reached",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": max_iter_data,
        })

        await emit(task_id, "orchestrator", "agent_stopped", {"node": "orchestrator"})

        return {
            "blackboard": bb,
            "current_phase": "reporting",
            "iteration_count": iteration,
            "events": events,
        }

    # ---- 场景 3: 有验证结果 → 评估进度 ----
    findings_count = len(bb.findings)
    pending_hypotheses = [h for h in bb.hypotheses if h.status == "pending"]
    tested_hypotheses = [h for h in bb.hypotheses if h.status in ("confirmed", "rejected")]

    # 检测连续无新发现的轮次
    if findings_count > bb.last_findings_count:
        bb.dry_rounds = 0
    else:
        bb.dry_rounds += 1
    bb.last_findings_count = findings_count

    # 连续 2 轮无新发现 → 自动结束
    if bb.dry_rounds >= 2 and findings_count > 0:
        logger.info("连续 %d 轮无新发现，转入报告阶段", bb.dry_rounds)
        await emit(task_id, "orchestrator", "decision", {
            "next_action": "report",
            "reasoning": f"连续 {bb.dry_rounds} 轮无新发现，攻击面已基本穷尽",
            "iteration": iteration,
            "findings_count": findings_count,
        })
        await emit(task_id, "orchestrator", "agent_stopped", {"node": "orchestrator"})
        return {
            "blackboard": bb,
            "current_phase": "reporting",
            "iteration_count": iteration,
            "events": events,
        }

    progress_context = {
        "iteration": iteration,
        "max_iterations": max_iter,
        "findings_count": findings_count,
        "pending_hypotheses": len(pending_hypotheses),
        "tested_hypotheses": len(tested_hypotheses),
        "total_hypotheses": len(bb.hypotheses),
        "rejected_count": len(bb.rejected_hypotheses),
        "false_positives_count": len(bb.false_positives),
        "target_profile": bb.target_profile,
    }

    await emit(task_id, "orchestrator", "thinking", {
        "content": f"评估进度: {findings_count} 发现, {len(pending_hypotheses)} 待验证假设...",
    })

    messages = [
        {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT},
        {"role": "user", "content": (
            f"当前任务进度评估：\n"
            f"{json.dumps(progress_context, ensure_ascii=False, default=str)}\n\n"
            f"请决定下一步行动：\n"
            f"- 如果还有未验证假设，继续验证\n"
            f"- 如果需要更多假设，生成新假设\n"
            f"- 如果已有足够发现或迭代已满，生成报告\n"
            f"请输出 JSON 格式的决策。"
        )},
    ]

    llm = _get_llm_client()
    response_text = await llm.call(agent="orchestrator", messages=messages, task_id=task_id)
    decision = _parse_orchestrator_response(response_text)

    next_action = decision.get("next_action", "hypothesize")
    reasoning = decision.get("reasoning", "")

    if next_action in ("report", "done"):
        phase = "reporting"
    elif next_action in ("hypothesize", "recon"):
        phase = "hypothesizing"
    else:
        phase = "verifying"

    bb.version += 1

    decision_data = {
        "next_action": next_action,
        "reasoning": reasoning,
        "iteration": iteration,
        "findings_count": findings_count,
    }
    await emit(task_id, "orchestrator", "decision", decision_data)
    events.append({
        "id": str(uuid.uuid4()),
        "agent": "orchestrator",
        "type": "decision",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": decision_data,
    })

    logger.info(
        "Orchestrator 决策: next_action=%s, phase=%s, 推理=%s",
        next_action,
        phase,
        reasoning[:100],
    )

    await emit(task_id, "orchestrator", "agent_stopped", {"node": "orchestrator"})

    return {
        "blackboard": bb,
        "current_phase": phase,
        "iteration_count": iteration,
        "events": events,
    }


def _parse_orchestrator_response(response_text: str) -> dict:
    """解析 Orchestrator LLM 响应为字典，解析失败返回安全默认值"""
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        pass

    try:
        start = response_text.find("{")
        end = response_text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(response_text[start:end])
    except json.JSONDecodeError:
        pass

    logger.warning("无法解析 Orchestrator 响应，使用默认决策: %s", response_text[:200])
    return {
        "target_profile": {"tech_stack": ["unknown"]},
        "strategy": "comprehensive_scan",
        "next_action": "hypothesize",
        "reasoning": "响应解析失败，使用默认策略",
    }
