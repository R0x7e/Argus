"""
Katana HTTP API Wrapper (v2 — 审计修正版)

通过 RESTful 接口调用 Katana 爬虫 binary，
返回发现的 URL、表单、JS 端点和参数。
"""

import json
import os
import subprocess
from urllib.parse import parse_qs, urlparse

from flask import Flask, jsonify, request

app = Flask(__name__)

CHROMIUM_PATH = os.environ.get("CHROMIUM_PATH", "/usr/bin/chromium")
LISTEN_ADDR = os.environ.get("LISTEN_ADDR", "0.0.0.0:7778")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


def _normalize_url(raw: str, base_url: str) -> str:
    """标准化 URL: 相对路径 → 绝对路径"""
    if not raw:
        return raw
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    base = base_url.rstrip("/")
    return f"{base}{raw}" if raw.startswith("/") else f"{base}/{raw}"


@app.route("/crawl", methods=["POST"])
def crawl():
    """
    执行 Katana 爬取。

    请求体:
    {
        "url": "http://target:8765",
        "depth": 2,
        "headless": true,
        "max_count": 200,
        "timeout": 90
    }

    响应:
    {
        "urls": [...],
        "forms": [{"action":..., "method":..., "inputs":[...]}],
        "js_endpoints": [...],
        "params": [...],
        "total_urls": N, "total_forms": M, "total_js_endpoints": K
    }
    """
    data = request.get_json()
    target_url = data.get("url", "")
    depth = data.get("depth", 2)
    headless = data.get("headless", True)
    max_count = data.get("max_count", 200)
    timeout = data.get("timeout", 90)

    if not target_url:
        return jsonify({"error": "url required"}), 400

    parsed = urlparse(target_url)
    scope_host = parsed.netloc

    cmd = [
        "katana",
        "-u", target_url,
        "-d", str(depth),
        "-mdc", str(max_count),
        "-jc",
        "-silent",
        "-c", "10",
        "-rl", "20",
        "-timeout", "10",
        "-sf", scope_host,
        "-H", "User-Agent: Mozilla/5.0 (compatible; Argus-Scanner/1.0)",
    ]

    if headless:
        cmd.extend(["-headless", "-no-sandbox"])

    try:
        app.logger.info("Katana: url=%s depth=%d headless=%s", target_url, depth, headless)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if result.stderr:
            stderr_preview = result.stderr[:300]
            if "error" in stderr_preview.lower() or "fatal" in stderr_preview.lower():
                app.logger.error("Katana stderr: %s", stderr_preview)

        urls = set()
        forms = []
        js_endpoints = set()
        static_files = set()
        params_set = set()

        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            req = entry.get("request", {})
            ep = req.get("endpoint", "")
            source = entry.get("source", "")

            if not ep:
                continue

            # 标准化 URL
            ep = _normalize_url(ep, target_url)
            if not ep:
                continue

            # 解析 URL 组件 (审计修正: 每次循环都解析)
            try:
                parsed_ep = urlparse(ep)
                path = parsed_ep.path or ep
                query = parsed_ep.query or ""
            except Exception:
                path = ep
                query = ""

            # 提取 query params
            if query:
                try:
                    for pname in parse_qs(query).keys():
                        params_set.add(pname)
                except Exception:
                    pass

            # 分类
            if source == "javascript":
                js_endpoints.add(ep)
            elif source == "form":
                # 审计修正: Katana JSONL 中表单数据在 req.form, 不是 req.inputs
                form_data = req.get("form", {})
                if isinstance(form_data, dict):
                    inputs = list(form_data.keys())
                else:
                    inputs = []
                forms.append({
                    "action": path,
                    "method": req.get("method", "GET"),
                    "inputs": inputs,
                })
            elif path and any(
                path.lower().endswith(ext) for ext in
                ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif',
                 '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot')
            ):
                static_files.add(path)
            else:
                urls.add(ep)

        all_urls = list(urls)
        all_js = list(js_endpoints)
        all_params = list(params_set)

        app.logger.info(
            "Katana done: %d urls, %d forms, %d js, %d params, %d static",
            len(all_urls), len(forms), len(all_js), len(all_params), len(static_files),
        )

        return jsonify({
            "urls": all_urls,
            "forms": forms,
            "js_endpoints": all_js,
            "params": all_params,
            "total_urls": len(all_urls),
            "total_forms": len(forms),
            "total_js_endpoints": len(all_js),
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": f"Katana timed out after {timeout}s"}), 504
    except FileNotFoundError:
        return jsonify({"error": "katana binary not found"}), 500
    except Exception as e:
        app.logger.error("Katana error: %s", str(e))
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7778)
