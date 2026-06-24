"""
JS 端点提取器

基于正则从 JavaScript 源代码中提取 API 端点路径。
用于侦察阶段发现 SPA 应用中硬编码的后端 API 路由。
"""

import re

_PATTERNS = [
    re.compile(r'''fetch\(\s*['"`](\/[^'"`\s]+)['"`]'''),
    re.compile(r'''axios\.(?:get|post|put|delete|patch)\(\s*['"`](\/[^'"`\s]+)['"`]'''),
    re.compile(r'''\.open\(\s*['"`][A-Z]+['"`]\s*,\s*['"`](\/[^'"`\s]+)['"`]'''),
    re.compile(r'''new\s+URL\(\s*['"`](\/[^'"`\s]+)['"`]'''),
    re.compile(r'''url\s*[:=]\s*['"`](\/(?:api|v[0-9]+|graphql|auth|admin|user|dashboard|internal)[^'"`\s]*?)['"`]'''),
    re.compile(r'''['"`](\/(?:api|v[0-9]+|graphql)\/?[^'"`\s]*?)['"`]'''),
]

_METHOD_HINT = re.compile(r'(GET|POST|PUT|DELETE|PATCH)', re.I)

_STATIC_SUFFIXES = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map")


def extract_endpoints_from_source(js_source: str) -> list[dict]:
    """
    从 JavaScript 源代码中提取 API 端点。

    Returns:
        [{"path": "/api/users", "method": "GET"}, ...]
    """
    if not js_source:
        return []

    seen: set[str] = set()
    results: list[dict] = []

    for pattern in _PATTERNS:
        for match in pattern.finditer(js_source):
            path = match.group(1)
            path = path.split("?")[0].split("#")[0]

            if len(path) < 2 or len(path) > 200:
                continue
            if path.endswith(_STATIC_SUFFIXES):
                continue
            if path in seen:
                continue

            seen.add(path)

            start = max(0, match.start() - 60)
            context_snippet = js_source[start:match.end() + 30]
            method_match = _METHOD_HINT.search(context_snippet)
            method = method_match.group(1).upper() if method_match else "GET"

            results.append({"path": path, "method": method})

    return results
