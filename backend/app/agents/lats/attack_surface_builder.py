"""
工具驱动的攻击面构造器 (v26)

替代 LLM-Orchestrator 生成攻击面的方式。
攻击面完全由侦察工具的实际发现构造，零 LLM 参与端点创建。

管线:
1. 从 recon_results 收集所有端点来源
2. 标准化所有路径 (EndpointNormalizer)
3. 去重 + 合并参数
4. P0 分类 + 评分
5. P1 能力探测 + 过滤
6. 输出 StructuredAttackSurface
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class StructuredAttackSurface:
    """工具驱动的攻击面 — 零 LLM 参与端点创建"""

    # 已验证的端点列表
    endpoints: list[dict] = field(default_factory=list)

    # 分类统计
    total_endpoints: int = 0
    vuln_pages: int = 0
    auth_pages: int = 0
    config_files: int = 0
    skipped_forbidden: int = 0
    skipped_not_found: int = 0

    # 发现的参数和表单
    parameters: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)

    # 原始侦察数据 (供 LLM Advisor 使用)
    recon_summary: dict = field(default_factory=dict)


def _extract_tech_indicators(recon_results: dict) -> list[str]:
    """从响应头提取技术栈线索 (零 LLM)"""
    indicators = []
    headers = recon_results.get("homepage_info", {}).get("headers", {})
    server = str(headers.get("Server", headers.get("server", "")))
    powered = str(headers.get("X-Powered-By", headers.get("x-powered-by", "")))
    set_cookie = str(headers.get("Set-Cookie", headers.get("set-cookie", "")))
    content_type = str(headers.get("Content-Type", headers.get("content-type", "")))

    s = server.lower()
    p = powered.lower()
    c = set_cookie.lower()

    if "apache" in s:
        indicators.append("Apache")
    if "nginx" in s:
        indicators.append("Nginx")
    if "iis" in s:
        indicators.append("IIS")
    if "php" in p or "php" in s:
        indicators.append("PHP")
    if "phpsessid" in c:
        indicators.append("PHP (session)")
    if "asp.net" in p or "asp.net" in s:
        indicators.append("ASP.NET")
    if "java" in p or "jsessionid" in c:
        indicators.append("Java")
    if "python" in p or "werkzeug" in s.lower() or "gunicorn" in s.lower():
        indicators.append("Python")
    if "node" in p.lower() or "express" in p.lower():
        indicators.append("Node.js")
    if "utf-8" in content_type.lower() or "charset" in content_type.lower():
        pass  # already covered

    if not indicators:
        indicators.append("Unknown")

    return indicators


async def build_attack_surface(
    recon_results: dict,
    target_url: str,
    task_id: str = "",
    max_endpoints: int = 60,
    max_probe: int = 50,
) -> StructuredAttackSurface:
    """
    纯工具驱动的攻击面构造 — 零 LLM 调用。

    Args:
        recon_results: _run_reconnaissance 的输出
        target_url: 目标 URL
        task_id: 任务 ID (用于日志)
        max_endpoints: 最终攻击面保留的最大端点数
        max_probe: 最多探测的端点数

    Returns:
        StructuredAttackSurface
    """
    from app.agents.lats.endpoint_normalizer import normalize_endpoints
    from app.agents.nodes.orchestrator import _classify_link, _score_link

    surface = StructuredAttackSurface()
    raw_endpoints = []

    # ── 来源 1: P0 分类链接 (最高质量, 评分最高) ──
    categorized = recon_results.get("homepage_info", {}).get("categorized_links", {})
    for cat, items in categorized.items():
        if cat == "static_asset":
            continue
        for item in items:
            raw_endpoints.append({
                "path": item["link"],
                "source": f"link_{cat}",
                "priority": item.get("score", 0.5),
                "params": [],
            })

    # ── 来源 2: 首页表单 ──
    # L1-fix: 表单无 action 时默认提交当前页 (DVWA/Pikachu 常见)
    for form in recon_results.get("forms", []):
        action = form.get("action", "")
        if not action:
            # 默认提交到目标 URL 当前页
            action = target_url if target_url else ""
            if not action:
                continue
        # 标准化: 若 action 是绝对 URL 且属于同站, 转为路径
        if action.startswith("http"):
            from urllib.parse import urlparse as _pu
            _ap = _pu(action)
            if target_url and _pu(target_url).netloc == _ap.netloc:
                action = _ap.path or "/"
        raw_endpoints.append({
            "path": action,
            "source": "form",
            "priority": 0.75,
            "params": form.get("params", []),
            "http_method": form.get("method", "GET"),
            "form_fields": form.get("form_fields", list(form.get("params", []))),
        })

    # ── 来源 3: 首页参数 URL ──
    for p in recon_results.get("parameters", [])[:30]:
        url = p.get("url", "")
        if url:
            raw_endpoints.append({
                "path": url,
                "source": "param_url",
                "priority": 0.6,
                "params": [p.get("name", "")],
            })

    # ── 来源 4: Playwright 发现的参数 ──
    # (已在 parameters 中, 其 url 在上一步覆盖)

    # ── 来源 5: deep_crawl (crawlergo) ──
    # (参数已被合并到 parameters, 如果有独立的 URL 端点也收集)
    for p in recon_results.get("parameters", []):
        url = p.get("url", "")
        source = p.get("source", "")
        if url and source in ("crawlergo", "deep_crawl"):
            # 避免重复
            if not any(ep.get("path") == url for ep in raw_endpoints):
                raw_endpoints.append({
                    "path": url,
                    "source": "deep_crawl",
                    "priority": 0.55,
                    "params": [p.get("name", "")],
                })

    # ── 来源 6: dir_scan 结果 (低优先级) ──
    for d in recon_results.get("directories", [])[:30]:
        path = d if isinstance(d, str) else d.get("path", "")
        if path:
            raw_endpoints.append({
                "path": path,
                "source": "dir_scan",
                "priority": 0.3,
                "params": [],
            })

    # ── 来源 7: 目标 URL 本身 ──
    from urllib.parse import urlparse
    parsed_target = urlparse(target_url)
    target_path = parsed_target.path or "/"
    raw_endpoints.append({
        "path": target_path,
        "source": "target_url",
        "priority": 0.8,
        "params": [],
    })
    # ── 来源 8 (P2): crawled_pages 中发现的链接 ──
    for page in recon_results.get("crawled_pages", [])[:15]:
        if isinstance(page, dict):
            url = page.get("url", "")
            if url and url not in [ep["path"] for ep in raw_endpoints]:
                raw_endpoints.append({
                    "path": url, "source": "crawled_page",
                    "priority": 0.5, "params": [],
                })

    # ── 来源 9 (P2): PCE/Playwright 提取的参数 URL ──
    for param_entry in recon_results.get("parameters", []):
        url = param_entry.get("url", "")
        name = param_entry.get("name", "")
        if url and name:
            # 合并到已有端点或新建
            existing = [ep for ep in raw_endpoints if ep["path"] == url]
            if existing:
                if name not in existing[0].setdefault("params", []):
                    existing[0]["params"].append(name)
            else:
                raw_endpoints.append({
                    "path": url, "source": "pce_param",
                    "priority": 0.55, "params": [name],
                })

    logger.info("AttackSurface builder: collected %d raw endpoints", len(raw_endpoints))

    # ── Step 1: 标准化路径 ──
    normalized = normalize_endpoints(raw_endpoints)
    logger.info("AttackSurface builder: %d after normalization", len(normalized))

    # ── Step 2: 按 path 去重, 合并 params 和 sources ──
    merged: dict[str, dict] = {}
    for ep in normalized:
        path = ep["path"]
        if path not in merged:
            merged[path] = {
                "path": path,
                "params": list(set(ep.get("params", []))),
                "sources": [ep.get("source", "")],
                "priority": ep.get("priority", 0.3),
                "http_method": ep.get("http_method", "GET"),
                "form_fields": list(ep.get("form_fields", [])),
            }
        else:
            existing = merged[path]
            existing["params"] = list(set(existing["params"] + ep.get("params", [])))
            if ep.get("source") not in existing["sources"]:
                existing["sources"].append(ep.get("source", ""))
            existing["priority"] = max(existing["priority"], ep.get("priority", 0))
            # 保留 form 来源的 http_method 与完整表单字段
            if ep.get("source") == "form":
                if ep.get("http_method"):
                    existing["http_method"] = ep.get("http_method", "GET")
                ff = ep.get("form_fields", [])
                for _f in ff:
                    if _f not in existing.get("form_fields", []):
                        existing.setdefault("form_fields", []).append(_f)

    # ── P3 Step 2.5: 从 URL 文件名推断参数 ──
    # v2/L1-P1d: hint 与真实表单字段冲突仲裁 — 真实表单字段优先。
    # 旧实现把 rce_ping 的 hint ["ipaddress","cmd","ping"] 全注入,
    # 与真实表单 ipaddress 混入不存在的 cmd/ping, 污染 Level0 探测。
    # 改为: hint 仅对无表单字段(source != "form" 且 form_fields 为空)的端点触发,
    # 且打上 param_source="url_hint" 标签, 由探针层降级使用。
    _URL_PARAM_HINTS = {
        "sqli_id": ["id"], "sqli_str": ["name", "id"], "sqli_search": ["name", "keyword"],
        "rce_ping": ["ipaddress", "cmd", "ping"], "rce_eval": ["txt", "cmd"],
        "xss_reflected_get": ["message"], "xss_stored": ["message"],
        "xss_dom": ["text", "id"], "fi_local": ["filename"],
        "fi_remote": ["filename", "url"], "ssrf_curl": ["url"],
        "ssrf_fgc": ["file", "url"], "bf_form": ["username", "password"],
        "bf_client": ["username", "password"], "bf_server": ["username", "password"],
        "csrf_login": ["username", "password"], "pkxss": ["username", "password"],
        "urlredirect": ["url"], "unsafeupload": ["file"],
        "unsafedownload": ["filename"], "overpermission": ["username", "password"],
    }
    for path, ep in merged.items():
        # 真实表单字段优先 — 有表单字段的端点跳过 hint 注入
        existing_form_fields = ep.get("form_fields", []) or []
        has_form_source = "form" in (ep.get("sources", []) or [])
        if existing_form_fields or has_form_source:
            continue  # 真实表单已提供参数, 不再注入 hint
        path_lower = path.lower()
        for hint_pattern, param_names in _URL_PARAM_HINTS.items():
            if hint_pattern in path_lower:
                for p in param_names:
                    if p not in ep["params"]:
                        ep["params"].append(p)
                break

    # ── Step 3: P0 分类 + 评分 ──
    for path, ep in merged.items():
        cat = _classify_link(path)
        ep["category"] = cat
        ep["score"] = max(
            ep.get("priority", 0),
            _score_link(path, cat)
        )

    # Step 3.5: 防御性回退 — 确保所有端点都有 category
    for path, ep in merged.items():
        if "category" not in ep:
            cat = _classify_link(path)
            ep["category"] = cat
            ep["score"] = max(ep.get("score", 0), _score_link(path, cat))
            logger.warning("防御性回退分类: %s → %s", path, cat)
    # ── Step 4: 按 score 排序 ──
    sorted_eps = sorted(merged.values(), key=lambda x: x.get("score", 0), reverse=True)

    # ── Step 5: P1 能力探测 + 过滤 ──
    from app.agents.lats.endpoint_capability import (
        get_endpoint_capability, get_compatible_vuln_types,
    )

    paths_to_probe = [ep["path"] for ep in sorted_eps[:max_probe]]
    if paths_to_probe:
        tasks = [get_endpoint_capability(p, target_url) for p in paths_to_probe]
        caps = await asyncio.gather(*tasks, return_exceptions=True)

        validated = []
        for path, cap_result in zip(paths_to_probe, caps):
            if isinstance(cap_result, Exception):
                # 探测失败: 使用同步版本回退
                try:
                    from app.agents.lats.endpoint_capability import get_endpoint_capability_sync
                    cap_result = get_endpoint_capability_sync(path, target_url)
                except Exception:
                    continue

            cap = cap_result

            # 查找对应的 merged entry
            ep = merged.get(path)
            if not ep:
                continue

            # 过滤不可访问
            if cap.accessibility in ("forbidden", "not_found", "timeout"):
                if cap.accessibility == "forbidden":
                    surface.skipped_forbidden += 1
                else:
                    surface.skipped_not_found += 1
                continue

            # 填充能力信息
            ep["accessibility"] = cap.accessibility
            ep["is_dynamic"] = cap.is_dynamic_page
            ep["has_forms"] = cap.has_forms or ep.get("has_forms", False)
            ep["compatible_vuln_types"] = get_compatible_vuln_types(cap)
            ep["capability"] = cap

            # 分类统计
            cat = ep.get("category", "")
            if cat == "vuln_page":
                surface.vuln_pages += 1
            elif cat == "auth_page":
                surface.auth_pages += 1
            elif cat == "config_leak":
                surface.config_files += 1

            validated.append(ep)

        # 对未探测到的端点 (超过 max_probe 的), 保留但标记为未验证
        for ep in sorted_eps[max_probe:]:
            ep["accessibility"] = "unknown"
            ep["is_dynamic"] = False
            ep["compatible_vuln_types"] = []
            validated.append(ep)

    else:
        validated = sorted_eps

    # ── Step 6: 最终排序 + 截断 ──
    validated.sort(key=lambda x: x.get("score", 0), reverse=True)
    surface.endpoints = validated[:max_endpoints]
    surface.total_endpoints = len(validated)
    surface.parameters = recon_results.get("parameters", [])[:50]
    surface.forms = recon_results.get("forms", [])[:20]
    surface.recon_summary = {
        "tech_indicators": _extract_tech_indicators(recon_results),
        "status_code": recon_results.get("homepage_info", {}).get("status_code"),
        "headers": recon_results.get("homepage_info", {}).get("headers", {}),
        "smart_snippets": recon_results.get("homepage_info", {}).get("smart_snippets", []),
        "total_links": recon_results.get("homepage_info", {}).get("total_links", 0),
    }


    # 防御性断言: vuln_pages 为 0 但 categorized_links 有数据时警告
    vuln_in_categorized = len(categorized.get("vuln_page", []))
    if surface.vuln_pages == 0 and vuln_in_categorized > 0:
        logger.error(
            "BUG: categorized_links has %d vuln_page items but surface.vuln_pages=0. "
            "Step 3 可能未设置 ep['category']", vuln_in_categorized
        )
    logger.info(
        "AttackSurface built: %d validated, %d vuln, %d auth, %d config, "
        "skipped: %d forbidden, %d not_found",
        surface.total_endpoints, surface.vuln_pages, surface.auth_pages,
        surface.config_files, surface.skipped_forbidden, surface.skipped_not_found,
    )

    return surface
