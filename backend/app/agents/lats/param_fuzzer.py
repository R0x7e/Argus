"""
参数 Fuzzing 引擎

三阶段参数发现:
  Stage 1: HTML/JS 静态分析 — 从页面源码提取参数名
  Stage 2: 智能 Fuzzing — 类型探测 + 错误触发 + 方法切换
  Stage 3: 内容指纹 — 去数字后对比 baseline vs probe

用于增强 discover_params 和侦察阶段的参数提取。
"""

import re
import logging
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def extract_params_from_html(html: str) -> list[dict]:
    """
    Stage 1: 从 HTML 源码提取参数名

    返回: [{"name": "username", "source": "input_tag", "type_hint": "text"}, ...]
    """
    params = []

    # <input name="xxx" type="yyy">
    for m in re.finditer(r'<input[^>]*name=["\']?(\w+)["\']?[^>]*type=["\']?(\w+)["\']?', html, re.I):
        params.append({"name": m.group(1), "source": "input_tag", "type_hint": m.group(2).lower()})

    # <textarea name="xxx">
    for m in re.finditer(r'<textarea[^>]*name=["\']?(\w+)["\']?', html, re.I):
        params.append({"name": m.group(1), "source": "textarea", "type_hint": "text"})

    # <select name="xxx">
    for m in re.finditer(r'<select[^>]*name=["\']?(\w+)["\']?', html, re.I):
        params.append({"name": m.group(1), "source": "select", "type_hint": "select"})

    # <button name="xxx">
    for m in re.finditer(r'<button[^>]*name=["\']?(\w+)["\']?', html, re.I):
        params.append({"name": m.group(1), "source": "button", "type_hint": "submit"})

    # <a href="?param=value">
    for m in re.finditer(r'href=["\']\?(\w+)=', html, re.I):
        params.append({"name": m.group(1), "source": "link_query", "type_hint": "unknown"})

    # JS/URL patterns: ?param=, &param=, req.query.param, $_GET['param']
    for m in re.finditer(r'[\?&](\w+)=', html, re.I):
        name = m.group(1)
        if not any(p["name"] == name for p in params):
            params.append({"name": name, "source": "url_pattern", "type_hint": "unknown"})

    # PHP patterns: $_GET['xxx'], $_POST['xxx'], $_REQUEST['xxx']
    for m in re.finditer(r'\$_(?:GET|POST|REQUEST)\[["\'](\w+)["\']\]', html, re.I):
        name = m.group(1)
        if not any(p["name"] == name for p in params):
            params.append({"name": name, "source": "php_var", "type_hint": "unknown"})

    return params


def extract_params_from_js(js_source: str) -> list[dict]:
    """从 JavaScript 源码提取参数名"""
    params = []
    patterns = [
        r'req\.query\.(\w+)', r'req\.params\.(\w+)', r'req\.body\.(\w+)',
        r'request\.query\[["\'](\w+)["\']', r'params\[["\'](\w+)["\']',
        r'\.getParameter\(["\'](\w+)["\']', r'\.getAttribute\(["\'](\w+)["\']',
        r'searchParams\.get\(["\'](\w+)["\']',
    ]
    for pat in patterns:
        for m in re.finditer(pat, js_source, re.I):
            name = m.group(1)
            if not any(p["name"] == name for p in params):
                params.append({"name": name, "source": "js_code", "type_hint": "unknown"})
    return params


def build_fuzz_params(param_name: str) -> list[dict]:
    """
    Stage 2: 为给定参数名生成智能 Fuzzing 参数列表

    返回: [{"value": ..., "purpose": "..."}, ...]
    """
    fuzz_cases = [
        # 类型探测
        {"value": "1", "purpose": "integer_normal"},
        {"value": "abc", "purpose": "string_normal"},
        {"value": "1e0", "purpose": "scientific_notation"},
        {"value": "1.0", "purpose": "float"},
        {"value": "-1", "purpose": "negative_integer"},
        {"value": "0", "purpose": "zero"},
        {"value": f"{param_name}[]=1", "purpose": "array_notation"},
        {"value": "true", "purpose": "boolean_true"},
        {"value": "null", "purpose": "null_value"},
        # 错误触发
        {"value": "'", "purpose": "single_quote"},
        {"value": '"', "purpose": "double_quote"},
        {"value": "\\", "purpose": "backslash"},
        {"value": "%00", "purpose": "null_byte"},
        {"value": "<script>", "purpose": "html_tag"},
        # 特殊值
        {"value": "../../../etc/passwd", "purpose": "path_traversal"},
        {"value": "http://127.0.0.1:80", "purpose": "ssrf_probe"},
        {"value": "{{7*7}}", "purpose": "ssti_probe"},
    ]
    return fuzz_cases


def analyze_fuzz_response(baseline: dict, responses: list[dict]) -> dict:
    """
    Stage 3: 分析 Fuzzing 响应差异

    返回: {
        "responsive_params": [...],  # 有响应的参数
        "anomalies": [...],           # 异常响应
        "inferred_type": "integer|string|unknown"
    }
    """
    bl_len = len(baseline.get("body", "") or "")
    bl_status = baseline.get("status_code", 0)
    bl_time = baseline.get("response_time_ms", 0)

    anomalies = []
    responsive = []

    for r in responses:
        value = r.get("value", "")
        purpose = r.get("purpose", "")
        r_status = r.get("status", 0)
        r_len = r.get("len", 0)
        r_time = r.get("time_ms", 0)

        if r_status != bl_status and r_status not in (404, 403):
            anomalies.append({"value": value, "purpose": purpose,
                              "signal": f"status {bl_status}→{r_status}"})
        elif abs(r_len - bl_len) > 80:
            anomalies.append({"value": value, "purpose": purpose,
                              "signal": f"len_diff={r_len - bl_len}"})
        elif r_time - bl_time > 2000:
            anomalies.append({"value": value, "purpose": purpose,
                              "signal": f"time +{r_time - bl_time}ms"})
        else:
            responsive.append({"value": value, "purpose": purpose})

    # 类型推断
    inferred_type = "unknown"
    for a in anomalies:
        if "single_quote" in a.get("purpose", "") and "status" in a.get("signal", ""):
            inferred_type = "string"
        elif "integer_normal" in a.get("purpose", "") and "len_diff" in a.get("signal", ""):
            inferred_type = "integer"

    return {
        "responsive_params": responsive,
        "anomalies": anomalies,
        "inferred_type": inferred_type,
        "total_tested": len(responses),
        "anomaly_count": len(anomalies),
    }


# ──── 便捷集成函数 ────

async def fuzz_endpoint_for_params(
    url: str,
    tool,  # http_request tool
    context,  # ExecutionContext
    html_body: str = "",
) -> dict:
    """
    对端点执行完整参数 Fuzzing 流程

    返回: {found_params: [...], html_params: [...], js_params: [...]}
    """
    result = {
        "found_params": [],
        "html_params": [],
        "js_params": [],
    }

    # Stage 1: HTML 静态分析
    if html_body:
        html_params = extract_params_from_html(html_body)
        result["html_params"] = [p["name"] for p in html_params[:20]]

    # Stage 2+3: 对提取到的参数执行 Fuzzing
    for pname in result["html_params"][:5]:  # 仅对前 5 个参数 fuzz
        fuzz_cases = build_fuzz_params(pname)
        baseline = await tool.execute({"url": url, "method": "GET"}, context)
        bl_len = len(baseline.get("body", "") or "")

        responses = []
        sep = "&" if "?" in url else "?"
        for case in fuzz_cases[:10]:  # 每参数最多 10 个 fuzz case
            test_url = f"{url}{sep}{pname}={case['value']}"
            r = await tool.execute({"url": test_url, "method": "GET"}, context)
            responses.append({
                "value": case["value"],
                "purpose": case["purpose"],
                "status": r.get("status_code", 0),
                "len": len(r.get("body", "") or ""),
                "time_ms": r.get("response_time_ms", 0),
            })

        baseline_dict = {"status_code": baseline.get("status_code", 0),
                         "body": baseline.get("body", ""),
                         "response_time_ms": baseline.get("response_time_ms", 0)}
        analysis = analyze_fuzz_response(baseline_dict, responses)

        if analysis["anomalies"] or len(analysis["responsive_params"]) > 0:
            result["found_params"].append({
                "name": pname,
                "inferred_type": analysis["inferred_type"],
                "anomalies": len(analysis["anomalies"]),
                "total_tested": analysis["total_tested"],
            })

    return result
