"""
端点路径标准化器 (v26)

解决 LLM-Orchestrator 在端点路径中附加注释、通配符、描述性文本的问题。
所有进入攻击面的端点路径必须通过此标准化器清洗。

核心能力:
- 移除 LLM 注释: "(source code extraction)", "(potential XSS)" 等
- 移除通配符: "/vul/*" → "/vul/"
- 验证 URL 格式: 拒绝包含空格、括号等非法字符的路径
- 归一化: 相对路径 → 绝对路径
"""

import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ──── LLM 注释模式 ────
# 这些是 LLM 经常附加到端点路径上的描述性文本

_LLM_COMMENT_PATTERNS = [
    # 英文括号注释
    (re.compile(r'\s*\(.*?\)\s*$'), ''),           # "(source code extraction)"
    (re.compile(r'\s*\(.*?\)'), ''),                # "(login form, potential XSS)"
    # 方括号
    (re.compile(r'\s*\[.*?\]\s*$'), ''),            # "[高危]"
    # 花括号
    (re.compile(r'\s*\{.*?\}\s*$'), ''),            # "{admin only}"
    # 冒号后缀描述 (英文)
    (re.compile(r'\s*:\s*(potential|possible|likely|suspected)\s+.*$', re.I), ''),
    (re.compile(r'\s*:\s*(login|admin|config|source|directory|auth|test|debug)\s*.*$', re.I), ''),
    # 双破折号注释
    (re.compile(r'\s*--\s*.*$'), ''),
    # 中文括号注释
    (re.compile(r'\s*（.*?）\s*$'), ''),
    # 斜杠星号
    (re.compile(r'/\*\s*$'), '/'),
    (re.compile(r'\*/\s*$'), ''),
    # 通配符
    (re.compile(r'\*'), ''),
]


def normalize_endpoint_path(raw_path: str) -> str | None:
    """
    标准化单个端点路径。

    处理流程:
    1. 移除 LLM 注释
    2. 移除通配符
    3. 验证 URL 格式
    4. 归一化

    Returns:
        标准化后的路径, 如果无法标准化则返回 None

    Examples:
        "/.git/ (source code extraction)" → "/.git/"
        "/vul/csrf/* (CSRF testing)" → "/vul/csrf/"
        "/pkxss/index.php (login form, potential XSS)" → "/pkxss/index.php"
        "/vul/dir/dir.php: potential directory traversal" → "/vul/dir/dir.php"
        "深度爬取发现 200 个 URL: [...]" → None (拒绝)
    """
    if not raw_path or not isinstance(raw_path, str):
        return None

    path = raw_path.strip()

    # Step 0: 快速拒绝明显非路径的字符串
    # 中文开头 → 非路径
    if re.search(r'^[\u4e00-\u9fff]', path):
        return None
    # 长度 > 500 → 很可能是列表/描述文本
    if len(path) > 500:
        return None

    # Step 1: 依次应用注释移除模式
    for pattern, replacement in _LLM_COMMENT_PATTERNS:
        path = pattern.sub(replacement, path).strip()

    # Step 2: 再次检查是否为空
    if not path or path in ('/', ''):
        return '/'

    # Step 3: 验证 URL 格式
    if path.startswith('http://') or path.startswith('https://'):
        try:
            parsed = urlparse(path)
            path = parsed.path or '/'
            if parsed.query:
                path = path + '?' + parsed.query
            if not path.startswith('/'):
                path = '/' + path
        except Exception:
            return None
    elif path.startswith('/'):
        # 绝对路径: 检查非法字符
        if re.search(r'[\s(){}\[\]【】]', path):
            return None
        # 如果 URL 编码的字符太多, 可能是垃圾
        if path.count('%') > 5:
            return None
    else:
        # 相对路径: 尝试加前缀
        if '/' in path and not re.search(r'[\s(){}\[\]【】]', path):
            path = '/' + path.lstrip('/')
        else:
            return None

    # Step 4: 路径长度检查
    if len(path) < 2 and path != '/':
        return None
    if len(path) > 300:
        return None

    return path


def normalize_endpoints(endpoints: list) -> list[dict]:
    """
    批量标准化端点列表。

    输入可以是 dict 列表、str 列表或混合。
    自动去重 (按标准化后的 path)。

    Returns:
        标准化且去重后的端点列表
    """
    normalized = []
    seen_paths = set()

    for ep in endpoints:
        if isinstance(ep, str):
            clean = normalize_endpoint_path(ep)
            if clean and clean not in seen_paths:
                seen_paths.add(clean)
                normalized.append({
                    "path": clean, "params": [],
                    "source": "normalized_from_string",
                })
        elif isinstance(ep, dict):
            raw_path = ep.get("path", "")
            clean = normalize_endpoint_path(raw_path)
            if clean and clean not in seen_paths:
                seen_paths.add(clean)
                entry = dict(ep)
                entry["path"] = clean
                normalized.append(entry)
        # 跳过其他类型

    return normalized


def is_valid_endpoint_path(path: str) -> bool:
    """快速检查路径是否有效 (不修改路径)"""
    return normalize_endpoint_path(path) is not None
