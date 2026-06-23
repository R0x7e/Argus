"""
crawlergo HTTP API wrapper

提供 RESTful 接口调用 crawlergo 深度爬虫 binary，
返回发现的 URL、表单、参数列表。
"""

import json
import os
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

CHROMIUM_PATH = os.environ.get("CHROMIUM_PATH", "/usr/bin/chromium")
LISTEN_ADDR = os.environ.get("LISTEN_ADDR", "0.0.0.0:7777")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/crawl", methods=["POST"])
def crawl():
    data = request.get_json()
    url = data.get("url", "")
    max_crawl_count = data.get("max_crawl_count", 500)

    if not url:
        return jsonify({"error": "url required"}), 400

    cmd = [
        "crawlergo",
        "-c", CHROMIUM_PATH,
        "-t", "5",
        "--max-crawled-count", str(max_crawl_count),
        "--output-mode", "json",
        "--no-headless=false",
        url,
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=180
        )

        stdout = result.stdout.strip()
        if stdout:
            json_start = stdout.find("{")
            if json_start != -1:
                output = json.loads(stdout[json_start:])
            else:
                output = {}
        else:
            output = {}

        req_list = output.get("req_list", [])
        urls = []
        forms = []
        parameters = []

        for req in req_list:
            req_url = req.get("url", "")
            method = req.get("method", "GET")
            req_data = req.get("data", "")

            urls.append({"url": req_url, "method": method})

            if method == "POST" and req_data:
                forms.append({
                    "action": req_url,
                    "method": "POST",
                    "params": [p.split("=")[0] for p in req_data.split("&") if "=" in p],
                })

            if "?" in req_url:
                query = req_url.split("?", 1)[1]
                for pair in query.split("&"):
                    if "=" in pair:
                        param_name = pair.split("=")[0]
                        parameters.append({"name": param_name, "url": req_url})

        return jsonify({
            "urls": urls[:200],
            "forms": forms[:50],
            "parameters": parameters[:100],
            "subdomains": output.get("sub_domain_list", []),
            "total_urls": len(urls),
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": "crawl timeout (180s)"}), 504
    except json.JSONDecodeError:
        return jsonify({"error": "failed to parse crawlergo output", "stderr": result.stderr[:500]}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    host, port = LISTEN_ADDR.rsplit(":", 1)
    app.run(host=host, port=int(port))
