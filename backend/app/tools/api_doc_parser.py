"""
API 文档解析器

解析 OpenAPI 2.0 (Swagger) 和 OpenAPI 3.0+ 规范，
提取端点路径、HTTP 方法和参数，用于攻击面发现。
"""

import json
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def parse_openapi_spec(spec_text: str) -> list[dict]:
    """
    解析 OpenAPI/Swagger 规范文本，返回端点列表。

    Returns:
        [{"path": "/api/users/{id}", "method": "GET", "params": [...], "description": "..."}, ...]
    """
    spec = _load_spec(spec_text)
    if not spec or not isinstance(spec, dict):
        return []

    if spec.get("swagger", "").startswith("2"):
        return _parse_swagger_2(spec)
    elif spec.get("openapi", "").startswith("3"):
        return _parse_openapi_3(spec)
    elif "paths" in spec:
        return _parse_swagger_2(spec)
    return []


def _load_spec(text: str) -> dict | None:
    text = text.strip()
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        import yaml
        return yaml.safe_load(text)
    except ImportError:
        pass
    except Exception:
        pass
    return None


_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}


def _parse_swagger_2(spec: dict) -> list[dict]:
    endpoints = []
    base_path = spec.get("basePath", "")
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        full_path = f"{base_path}{path}".replace("//", "/") or path

        for method, operation in methods.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            params = []
            for p in operation.get("parameters", []):
                if isinstance(p, dict) and p.get("name"):
                    params.append({
                        "name": p["name"],
                        "in": p.get("in", ""),
                        "required": p.get("required", False),
                    })

            endpoints.append({
                "path": full_path,
                "method": method.upper(),
                "params": params,
                "description": (operation.get("summary") or operation.get("description") or "")[:200],
            })

    return endpoints


def _parse_openapi_3(spec: dict) -> list[dict]:
    endpoints = []

    base_path = ""
    servers = spec.get("servers", [])
    if servers and isinstance(servers[0], dict):
        server_url = servers[0].get("url", "")
        if server_url.startswith("/"):
            base_path = server_url
        elif server_url.startswith("http"):
            base_path = urlparse(server_url).path

    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        full_path = f"{base_path}{path}".replace("//", "/") or path

        path_params = methods.get("parameters", [])

        for method, operation in methods.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            params = []
            all_params = (path_params or []) + (operation.get("parameters") or [])
            for p in all_params:
                if isinstance(p, dict) and p.get("name"):
                    params.append({
                        "name": p["name"],
                        "in": p.get("in", ""),
                        "required": p.get("required", False),
                    })

            request_body = operation.get("requestBody", {})
            if isinstance(request_body, dict):
                content = request_body.get("content", {})
                for _media_type, schema_info in content.items():
                    if not isinstance(schema_info, dict):
                        continue
                    schema = schema_info.get("schema", {})
                    if schema.get("type") == "object":
                        required_fields = set(schema.get("required", []))
                        for prop_name in schema.get("properties", {}).keys():
                            params.append({
                                "name": prop_name,
                                "in": "body",
                                "required": prop_name in required_fields,
                            })
                    break

            endpoints.append({
                "path": full_path,
                "method": method.upper(),
                "params": params,
                "description": (operation.get("summary") or operation.get("description") or "")[:200],
            })

    return endpoints
