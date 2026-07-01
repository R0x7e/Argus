"""
端点能力统一模型 (v25)

替代分散的 _is_endpoint_injectable / _is_config_path / _prevalidate_endpoint 检查。
提供结构化的端点能力画像，作为所有下游决策（分支估值、MCTS 选择、扩张引擎）的唯一真相源。

核心理念：
- 每个端点有一个 EndpointCapability 实例
- VulnType×Endpoint 兼容性由声明式矩阵判定
- 所有需要端点信息的代码路径统一调用 get_endpoint_capability()
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ──── 端点能力判定规则表 ────

# 静态资源后缀
_STATIC_ASSET_SUFFIXES = (
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.mp4', '.webp',
)

# 版本控制路径前缀
_VERSION_CONTROL_PREFIXES = (
    '.git/', '.svn/', '.hg/', '.bzr/', '.gitconfig',
)

# 配置/密钥文件路径模式
_CONFIG_PATH_PATTERNS = (
    '.git/', '.gitconfig', '.env', '.svn/', '.hg/', '.bzr/',
    'dockerfile', 'docker-compose', '.htaccess', '.htpasswd',
    'robots.txt', 'sitemap', 'composer.lock', 'package-lock',
    'yarn.lock', 'Gemfile.lock', 'Pipfile.lock', '.DS_Store',
    'web.config', 'web.xml', 'server.xml', 'thumbs.db',
    '.project', '.classpath', '.settings/', 'backup', 'dump',
    'phpinfo', 'info.php', 'test.php', 'readme', 'changelog',
    'license', 'copying',
)

# 动态页面扩展名
_DYNAMIC_PAGE_EXTENSIONS = (
    '.php', '.asp', '.aspx', '.jsp', '.py', '.pl', '.cgi',
    '.do', '.action', '.cfm', '.rb',
)


@dataclass
class EndpointCapability:
    """端点完整能力画像 — 所有下游决策的唯一真相源"""

    # ── 标识 ──
    path: str = ""                     # "/vul/sqli/sqli_str.php"
    full_url: str = ""                 # "http://target:8765/vul/sqli/sqli_str.php"

    # ── 可访问性 ──
    accessibility: str = "unknown"     # accessible|redirect|auth_required|forbidden|not_found|server_error|timeout
    response_status: int = 0
    response_time_ms: int = 0

    # ── 内容分类 ──
    content_type: str = ""             # text/html|application/json|text/plain|...
    response_length: int = 0
    body_sample: str = ""              # 前 2KB 用于证据检测

    # ── 动态性判定 (由 _classify_capability 填充) ──
    is_dynamic_page: bool = False      # .php/.asp/.jsp 或含 <form>
    is_static_asset: bool = False      # .css/.js/.png 等
    is_config_path: bool = False       # .env|dockerfile|robots.txt 等
    is_version_control: bool = False   # .git/HEAD|.svn/entries 等
    is_directory_listing: bool = False # Apache directory index

    # ── 参数/表单 ──
    has_query_params: bool = False
    observed_params: list[str] = field(default_factory=list)
    has_forms: bool = False
    form_details: list[dict] = field(default_factory=list)

    # ── 技术线索 ──
    server_header: str = ""
    powered_by: str = ""
    tech_hints: list[str] = field(default_factory=list)

    # ── 漏洞类型兼容性 ──
    # None=允许全部, []=禁止全部, [...] = 仅允许指定类型
    allowed_vuln_types: list[str] | None = None

    def to_metadata(self) -> dict:
        """转为 SearchNode.endpoint_metadata 兼容格式"""
        return {
            "accessibility": self.accessibility,
            "is_config_path": self.is_config_path or self.is_version_control,
            "status": self.response_status,
            "response_time_ms": self.response_time_ms,
            "content_type": self.content_type,
            "has_forms": self.has_forms,
            "is_dynamic": self.is_dynamic_page,
            "allowed_vuln_types": self.allowed_vuln_types,
        }


def _classify_capability(path: str, status: int, body: str, content_type: str) -> EndpointCapability:
    """
    纯规则驱动的端点能力分类 (零 HTTP 请求, 零 LLM 调用)。

    基于路径语义、HTTP 状态码和响应体内容判定端点的所有 boolean 标志。
    """
    cap = EndpointCapability(path=path)
    cap.response_status = status
    cap.content_type = content_type
    cap.response_length = len(body)
    cap.body_sample = body[:2000]

    path_lower = path.lower()

    # ── 动态页面判定 ──
    if any(path_lower.endswith(ext) for ext in _DYNAMIC_PAGE_EXTENSIONS):
        cap.is_dynamic_page = True
    elif '?' in path:
        cap.is_dynamic_page = True
    elif body and ('<form' in body.lower() or '<input' in body.lower()):
        cap.is_dynamic_page = True

    # ── 静态资源判定 ──
    if any(path_lower.endswith(s) for s in _STATIC_ASSET_SUFFIXES):
        cap.is_static_asset = True
    elif content_type and 'image/' in content_type:
        cap.is_static_asset = True

    # ── 版本控制判定 ──
    if any(prefix in path_lower for prefix in _VERSION_CONTROL_PREFIXES):
        cap.is_version_control = True

    # ── 配置路径判定 ──
    if any(pattern in path_lower for pattern in _CONFIG_PATH_PATTERNS):
        cap.is_config_path = True

    # ── 目录列表判定 ──
    if status == 200 and body:
        dir_listing_signals = [
            'Index of /', 'Directory Listing', 'Parent Directory',
            '<title>Index of', 'Last modified</a>',
        ]
        if any(sig in body for sig in dir_listing_signals):
            cap.is_directory_listing = True

    # ── 表单检测 ──
    if body and '<form' in body.lower():
        cap.has_forms = True
        # 简单提取表单参数名
        import re as _re
        input_names = _re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', body, re.I)
        cap.observed_params = list(set(input_names))[:20]

    # ── Query params ──
    if '?' in path:
        cap.has_query_params = True
        from urllib.parse import parse_qs, urlparse
        try:
            parsed = urlparse(path if 'http' in path else f'http://x{path}')
            cap.observed_params = list(set(
                cap.observed_params + list(parse_qs(parsed.query).keys())
            ))
        except Exception:
            pass

    # ── 服务器头 ──
    cap.server_header = ""  # 由调用方从 HTTP response headers 中填入

    # ── 可访问性 ──
    cap.accessibility = _classify_accessibility(status)

    # ── 计算 allowed_vuln_types ──
    cap.allowed_vuln_types = _compute_allowed_vuln_types(cap)

    return cap


def _classify_accessibility(status: int) -> str:
    """HTTP 状态码 → 可访问性标签"""
    if status == 200:
        return "accessible"
    if status in (301, 302, 303, 307, 308):
        return "redirect"
    if status == 401:
        return "auth_required"
    if status == 403:
        return "forbidden"
    if status == 404:
        return "not_found"
    if status >= 500:
        return "server_error"
    if status == 0:
        return "timeout"
    return "unknown"


def _compute_allowed_vuln_types(cap: EndpointCapability) -> list[str] | None:
    """
    规则驱动的 vuln_type 允许列表计算。

    规则按优先级匹配，第一个命中即生效：
    1. 禁止类 (返回 [])
    2. 限定类 (返回特定类型列表)
    3. 全允许 (返回 None)
    """
    # 规则 1: forbidden/not_found/timeout → 禁止所有
    if cap.accessibility in ("forbidden", "not_found", "timeout"):
        return []

    # 规则 2: 静态资源 → 禁止所有
    if cap.is_static_asset:
        return []

    # 规则 3: 版本控制路径 → 仅 info_disclosure
    if cap.is_version_control:
        return ["info_disclosure"]

    # 规则 4: 配置路径 → 仅 info_disclosure
    if cap.is_config_path:
        return ["info_disclosure"]

    # 规则 5: 目录列表 → 仅 info_disclosure
    if cap.is_directory_listing:
        return ["info_disclosure"]

    # 规则 6: 纯文本内容 → 仅 info_disclosure
    if cap.content_type and 'text/plain' in cap.content_type and not cap.is_dynamic_page:
        return ["info_disclosure"]

    # 规则 7: 极短响应 → 仅 info_disclosure
    if cap.response_length < 100 and not cap.is_dynamic_page:
        return ["info_disclosure"]

    # 规则 8: redirect → 仅 open_redirect + auth_bypass
    if cap.accessibility == "redirect":
        return ["open_redirect", "auth_bypass"]

    # 规则 9: auth_required → 仅 auth_bypass
    if cap.accessibility == "auth_required":
        return ["auth_bypass"]

    # 规则 10: 动态页面 → 全允许
    if cap.is_dynamic_page:
        return None  # None = 全部允许

    # 规则 11: 有表单 → 全允许
    if cap.has_forms:
        return None

    # 规则 12: server_error → 仅 info_disclosure
    if cap.accessibility == "server_error":
        return ["info_disclosure"]

    # 默认: 保守 — 仅 info_disclosure + auth_bypass
    return ["info_disclosure", "auth_bypass"]


# ──── 异步端点能力探测 ────

async def get_endpoint_capability(
    path: str,
    base_url: str,
    force_refresh: bool = False,
    timeout: float = 5.0,
) -> EndpointCapability:
    """
    获取端点能力画像 — 统一的异步入口。

    优先从 HTTP 响应中获取真实数据，解析失败则回退到纯规则分类。
    所有调用点应通过此函数获取 EndpointCapability，确保一致性。
    """
    import httpx
    import time as _time

    full_url = base_url.rstrip("/") + "/" + path.lstrip("/")

    cap = EndpointCapability(path=path, full_url=full_url)

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            start = _time.monotonic()
            resp = await client.get(full_url)
            elapsed_ms = int((_time.monotonic() - start) * 1000)

            body = resp.text[:10000]
            content_type = resp.headers.get("content-type", "")
            server = resp.headers.get("server", "")
            powered_by = resp.headers.get("x-powered-by", "")

            # 构建带真实 HTTP 数据的 capability
            cap = _classify_capability(path, resp.status_code, body, content_type)
            cap.response_time_ms = elapsed_ms
            cap.full_url = full_url
            cap.server_header = server
            cap.powered_by = powered_by
            cap.body_sample = body[:2000]

            # 技术线索
            if "php" in powered_by.lower() or "php" in server.lower():
                cap.tech_hints.append("php")
            if "apache" in server.lower():
                cap.tech_hints.append("apache")
            if "nginx" in server.lower():
                cap.tech_hints.append("nginx")
            if "set-cookie" in str(resp.headers).lower():
                if "phpsessid" in str(resp.headers).lower():
                    cap.tech_hints.append("php_session")

            return cap

    except Exception:
        # 网络错误 → 回退到纯规则分类
        cap = _classify_capability(path, 0, "", "")
        cap.accessibility = "timeout"
        cap.response_status = 0
        cap.allowed_vuln_types = _compute_allowed_vuln_types(cap)
        return cap


def get_endpoint_capability_sync(
    path: str,
    base_url: str = "",
    status: int = 0,
    body: str = "",
    content_type: str = "",
    server_header: str = "",
) -> EndpointCapability:
    """
    同步版本的端点能力获取 — 当已有 HTTP 响应数据时使用。

    用于树初始化时的批量处理或已有响应数据的场景。
    """
    cap = _classify_capability(path, status, body, content_type)
    cap.server_header = server_header
    if base_url:
        cap.full_url = base_url.rstrip("/") + "/" + path.lstrip("/")
    return cap


# ──── 全局 LRU 缓存 ────

_capability_cache: dict[str, EndpointCapability] = {}
_CACHE_MAX_SIZE = 300


def cache_capability(base_url: str, path: str, cap: EndpointCapability) -> None:
    """将端点能力存入全局缓存"""
    key = f"{base_url}|{path}"
    if len(_capability_cache) >= _CACHE_MAX_SIZE:
        oldest = next(iter(_capability_cache))
        del _capability_cache[oldest]
    _capability_cache[key] = cap


def get_cached_capability(base_url: str, path: str) -> EndpointCapability | None:
    """从缓存中获取端点能力"""
    return _capability_cache.get(f"{base_url}|{path}")


def clear_capability_cache() -> None:
    """清空全局缓存"""
    _capability_cache.clear()


# ──── VulnType × Endpoint 兼容性矩阵 ────

# 声明式定义: 每种漏洞类型需要端点的什么前置条件
VULN_TYPE_REQUIREMENTS: dict[str, dict] = {
    "rce": {
        "base_value": 0.9,
        "requires_dynamic": True,
        "requires_params": True,
        "forbidden_on": ["is_config_path", "is_version_control",
                         "is_static_asset", "is_directory_listing"],
        "endpoint_hints": ["exec", "cmd", "ping", "shell", "run", "eval", "rce"],
        "param_hints": ["cmd", "exec", "command", "ping", "ip", "host", "addr",
                        "ipaddress", "address", "target", "input", "arg"],
    },
    "sql_injection": {
        "base_value": 0.8,
        "requires_dynamic": True,
        "requires_params": True,
        "forbidden_on": ["is_config_path", "is_version_control",
                         "is_static_asset", "is_directory_listing"],
        "endpoint_hints": ["sqli", "sql", "query", "search", "id", "user", "login",
                           "blind", "union", "select", "database", "db"],
        "param_hints": ["id", "q", "query", "search", "name", "username", "sort", "order", "uid"],
    },
    "xss": {
        "base_value": 0.5,
        "requires_dynamic": True,
        "requires_params": True,
        "forbidden_on": ["is_config_path", "is_version_control",
                         "is_static_asset", "is_directory_listing"],
        "endpoint_hints": ["xss", "search", "comment", "message", "post", "profile", "reflected", "dom", "stored"],
        "param_hints": ["q", "search", "name", "message", "comment", "input", "text", "keyword"],
    },
    "ssrf": {
        "base_value": 0.75,
        "requires_dynamic": True,
        "requires_params": True,
        "forbidden_on": ["is_config_path", "is_version_control",
                         "is_static_asset", "is_directory_listing"],
        "endpoint_hints": ["ssrf", "curl", "fetch", "proxy", "url", "link", "fgc"],
        "param_hints": ["url", "link", "callback", "redirect", "fetch", "proxy", "dest"],
    },
    "lfi": {
        "base_value": 0.65,
        "requires_dynamic": True,
        "requires_params": True,
        "forbidden_on": ["is_config_path", "is_version_control",
                         "is_static_asset", "is_directory_listing"],
        "endpoint_hints": ["file", "include", "page", "template", "load", "doc", "lfi", "fi_"],
        "param_hints": ["file", "path", "page", "include", "template", "doc"],
    },
    "path_traversal": {
        "base_value": 0.65,
        "requires_dynamic": True,
        "requires_params": True,
        "forbidden_on": ["is_config_path", "is_version_control",
                         "is_static_asset", "is_directory_listing"],
        "endpoint_hints": ["file", "download", "path", "dir", "folder"],
        "param_hints": ["file", "path", "dir", "folder", "download"],
    },
    "ssti": {
        "base_value": 0.65,
        "requires_dynamic": True,
        "requires_params": True,
        "forbidden_on": ["is_config_path", "is_version_control",
                         "is_static_asset", "is_directory_listing"],
        "endpoint_hints": ["template", "ssti", "render", "view"],
        "param_hints": ["template", "name", "message", "content", "text"],
    },
    "idor": {
        "base_value": 0.6,
        "requires_dynamic": True,
        "requires_params": True,
        "forbidden_on": ["is_config_path", "is_version_control",
                         "is_static_asset", "is_directory_listing"],
        "endpoint_hints": ["user", "account", "order", "profile", "api", "idor", "overpermission"],
        "param_hints": ["id", "uid", "user_id", "account", "order_id", "profile_id"],
    },
    "auth_bypass": {
        "base_value": 0.7,
        "requires_dynamic": False,
        "requires_params": False,
        "forbidden_on": ["is_static_asset"],
        "endpoint_hints": ["admin", "login", "auth", "manage", "dashboard", "burteforce", "bf_"],
        "param_hints": [],
    },
    "info_disclosure": {
        "base_value": 0.3,
        "requires_dynamic": False,
        "requires_params": False,
        "forbidden_on": [],
        "endpoint_hints": [".git", ".env", "backup", "config", "phpinfo", "dump",
                           "readme", "infoleak", "info"],
        "param_hints": [],
    },
    "open_redirect": {
        "base_value": 0.35,
        "requires_dynamic": True,
        "requires_params": True,
        "forbidden_on": ["is_config_path", "is_version_control", "is_static_asset"],
        "endpoint_hints": ["redirect", "url", "goto", "next", "return", "unsafere"],
        "param_hints": ["url", "redirect", "next", "return", "goto", "callback"],
    },
    "file_upload": {
        "base_value": 0.7,
        "requires_dynamic": True,
        "requires_params": True,
        "forbidden_on": ["is_config_path", "is_version_control",
                         "is_static_asset", "is_directory_listing"],
        "endpoint_hints": ["upload", "file", "image", "avatar", "attachment", "unsafeupload"],
        "param_hints": ["file", "image", "upload", "avatar", "attachment"],
    },
}


def is_vuln_type_compatible(vuln_type: str, capability: EndpointCapability) -> bool:
    """
    检查 vuln_type 是否与端点能力兼容。

    核心逻辑:
    0. forbidden/not_found/timeout → 不兼容任何类型
    1. allowed_vuln_types 显式约束
    2. forbidden_on 标志检查
    3. 前置条件检查 (动态页/参数)
    """
    # 0. 不可访问端点 → 不兼容
    if capability.accessibility in ("forbidden", "not_found", "timeout"):
        return False

    # 1. allowed_vuln_types 显式约束
    if capability.allowed_vuln_types is not None:
        if len(capability.allowed_vuln_types) == 0:
            return False
        if vuln_type not in capability.allowed_vuln_types:
            return False

    req = VULN_TYPE_REQUIREMENTS.get(vuln_type)
    if not req:
        return True

    # 2. forbidden_on 检查
    for flag in req.get("forbidden_on", []):
        if getattr(capability, flag, False):
            return False

    # 3. 前置条件检查
    if req.get("requires_dynamic") and not capability.is_dynamic_page:
        return False
    if req.get("requires_params") and not capability.has_query_params and not capability.has_forms:
        return False

    return True


def get_compatible_vuln_types(capability: EndpointCapability) -> list[str]:
    """返回端点支持的所有兼容漏洞类型 (按 base_value 降序)"""
    compatible = []
    for vt, req in VULN_TYPE_REQUIREMENTS.items():
        if is_vuln_type_compatible(vt, capability):
            compatible.append((vt, req.get("base_value", 0.4)))
    compatible.sort(key=lambda x: x[1], reverse=True)
    return [vt for vt, _ in compatible]


def estimate_branch_value_v2(
    vuln_type: str,
    param_name: str,
    capability: EndpointCapability,
    source: str = "",
    focus_vuln_types: list[str] | None = None,
) -> float:
    """
    语义感知的分支价值评估 v2。

    相比 v1 的核心改进:
    - 不兼容的 vuln_type × endpoint 组合直接返回 0.0
    - 端点路径语义匹配 → 高置信度加成
    - 参数名匹配加成
    """
    # 1. 兼容性检查 — 不兼容直接归零
    if not is_vuln_type_compatible(vuln_type, capability):
        return 0.0

    req = VULN_TYPE_REQUIREMENTS.get(vuln_type, {})
    base = req.get("base_value", 0.4)

    path_lower = capability.path.lower()

    # 2. 端点路径语义加成 — 路径含 vuln_type 关键词 → 强信号
    hints = req.get("endpoint_hints", [])
    matched = sum(1 for h in hints if h in path_lower)
    if matched >= 2:
        base += 0.13
    elif matched == 1:
        base += 0.06

    # 3. 参数名匹配加成
    param_hints = req.get("param_hints", [])
    if param_name and param_name.lower() in param_hints:
        base += 0.10

    # 4. 端点来源加成
    source_bonus = {
        "form": 0.05, "crawl": 0.03, "target_url": 0.08,
        "url_inferred": 0.06, "dir_scan": 0.0,
    }
    base += source_bonus.get(source, 0.0)

    # 5. 可访问性惩罚
    acc_penalty = {
        "accessible": 0.0, "redirect": -0.15,
        "auth_required": -0.10, "server_error": -0.25,
    }
    base += acc_penalty.get(capability.accessibility, -0.10)

    # 6. 表单/参数丰富度加成
    if capability.has_forms and capability.has_query_params:
        base += 0.04
    if len(capability.observed_params) >= 3:
        base += 0.03

    # 7. 任务目标对齐
    if focus_vuln_types and vuln_type in focus_vuln_types:
        base += 0.35

    return max(0.0, min(1.0, base))
