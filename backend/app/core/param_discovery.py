"""
多源参数发现管线 (v3)

融合6+数据源发现目标端点的参数，按置信度排序输出。

优先级:
1. 表单提取 (confidence=1.0)
2. URL查询参数 (confidence=0.95)
3. JS端点提取 (confidence=0.7)
4. LLM语义推断 (confidence=0.6, 仅在无表单时触发)
5. URL文件名启发式 (confidence=0.3, 降级)
6. 通用回退 (confidence=0.1, 最后手段)

设计原则:
- 多源融合提供退化容错
- 高置信度源自动屏蔽低置信度源的同名参数
- LLM推理仅在前3源均无结果时触发(节省Token)

解决根本问题: _infer_params_from_url 单源不可靠
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ParamCandidate:
    """参数候选项"""
    name: str
    vuln_types: list[str] = field(default_factory=list)
    confidence: float = 0.0
    source: str = ""
    source_detail: str = ""
    endpoint: str = ""
    method: str = "GET"


class ParamDiscoveryPipeline:
    """多源参数发现管线"""

    def __init__(self, llm_client=None):
        self._llm = llm_client

    async def discover(
        self,
        url: str,
        page_contents: list[dict] | None = None,
        shared_knowledge=None,
    ) -> list[ParamCandidate]:
        """
        融合所有来源，返回去重排序后的参数候选列表。
        """
        candidates: list[ParamCandidate] = []

        # 来源1: 表单提取 (最高置信度)
        if page_contents:
            candidates.extend(self._from_page_contents(page_contents))

        # 来源2: URL查询参数
        candidates.extend(self._from_url_query(url))

        # 来源3: JS端点提取
        if page_contents:
            candidates.extend(self._from_js_endpoints(page_contents))

        # 来源4: LLM语义推断 (仅前3源均无结果时触发)
        if not candidates and self._llm:
            try:
                llm_params = await self._from_llm_inference(url, page_contents)
                candidates.extend(llm_params)
            except Exception as e:
                logger.warning("LLM参数推断失败: %s", e)

        # 来源5: URL文件名启发式 (降级为低置信度)
        heuristic_params = self._from_url_heuristic(url)
        existing_names = {c.name for c in candidates if c.confidence >= 0.5}
        for hp in heuristic_params:
            if hp.name not in existing_names:
                hp.confidence = 0.3
                candidates.append(hp)

        # 来源6: 通用参数回退 (仅在没有其他来源时)
        if not candidates:
            candidates.extend(self._generic_fallback(url))

        return self._deduplicate_and_sort(candidates)

    def _from_page_contents(
        self, page_contents: list[dict]
    ) -> list[ParamCandidate]:
        """从页面内容提取参数 (confidence=1.0)"""
        candidates = []
        for pc in page_contents:
            endpoint = pc.get("url", "")
            for form in pc.get("forms", []):
                method = form.get("method", "GET")
                form_type = form.get("form_type", "normal")
                for pname in form.get("params", []):
                    candidates.append(ParamCandidate(
                        name=pname,
                        vuln_types=[],
                        confidence=1.0,
                        source="form_extraction",
                        source_detail=f"form_type={form_type}",
                        endpoint=endpoint,
                        method=method,
                    ))
            for pname in pc.get("input_params", []):
                if not any(c.name == pname and c.endpoint == endpoint
                          for c in candidates):
                    candidates.append(ParamCandidate(
                        name=pname,
                        vuln_types=[],
                        confidence=0.9,
                        source="form_extraction",
                        source_detail="input_param",
                        endpoint=endpoint,
                    ))
        return candidates

    def _from_url_query(self, url: str) -> list[ParamCandidate]:
        """从URL查询字符串提取参数 (confidence=0.95)"""
        from urllib.parse import parse_qs, urlparse as _urlparse
        candidates = []
        try:
            parsed = _urlparse(url)
            for pname, values in parse_qs(parsed.query).items():
                candidates.append(ParamCandidate(
                    name=pname,
                    vuln_types=[],
                    confidence=0.95,
                    source="url_query",
                    source_detail=f"value={values[0][:50] if values else ''}",
                    endpoint=url,
                ))
        except Exception:
            pass
        return candidates

    def _from_js_endpoints(
        self, page_contents: list[dict]
    ) -> list[ParamCandidate]:
        """从JS端点提取参数 (confidence=0.7)"""
        import re
        candidates = []
        for pc in page_contents:
            for ep in pc.get("js_endpoints", []):
                if "?" in ep:
                    from urllib.parse import parse_qs, urlparse as _urlparse
                    try:
                        parsed = _urlparse(ep)
                        for pname in parse_qs(parsed.query).keys():
                            candidates.append(ParamCandidate(
                                name=pname,
                                vuln_types=[],
                                confidence=0.7,
                                source="js_extraction",
                                source_detail=f"endpoint={ep[:50]}",
                                endpoint=pc.get("url", ""),
                            ))
                    except Exception:
                        pass
        return candidates

    async def _from_llm_inference(
        self, url: str, page_contents: list[dict] | None
    ) -> list[ParamCandidate]:
        """LLM语义推理参数 (confidence=0.6, 节省Token)"""
        import json

        ctx_text = ""
        if page_contents:
            for pc in page_contents:
                ctx_text += f"URL: {pc.get('url','')}\n"
                ctx_text += f"Title: {pc.get('title','')}\n"
                ctx_text += f"Body: {pc.get('body_preview','')[:1000]}\n"

        prompt = (
            f"分析以下网页，推断该页面接受哪些HTTP请求参数(parameter names)。\n\n"
            f"URL: {url}\n"
            f"{ctx_text}\n\n"
            f"返回JSON数组，每个元素包含param_name和reasoning字段。"
            f"只返回确定存在的参数，不要猜测。如果页面没有明显的表单或API，返回空数组。\n"
            f'示例: [{{"param_name": "ipaddress", "reasoning": "页面提示Enter IP address，表单input name=ipaddress"}}]'
        )

        try:
            response = await self._llm.call(
                agent="param_inference",
                messages=[{"role": "user", "content": prompt}],
            )
            params = json.loads(response) if isinstance(response, str) else response
            if not isinstance(params, list):
                return []

            return [
                ParamCandidate(
                    name=p.get("param_name", ""),
                    vuln_types=[],
                    confidence=0.6,
                    source="llm_inference",
                    source_detail=p.get("reasoning", "")[:100],
                    endpoint=url,
                )
                for p in params
                if p.get("param_name")
            ]
        except Exception:
            return []

    def _from_url_heuristic(self, url: str) -> list[ParamCandidate]:
        """扩展版URL文件名启发式"""
        import re as _re

        path = url.split("?")[0]
        filename = path.rsplit("/", 1)[-1] if "/" in path else path
        words = _re.split(r'[_.\-]', filename.lower())
        words = [w for w in words if w and len(w) > 1 and w != "php"]

        # 扩展映射
        param_hints = {
            "id": ["idor", "sql_injection", "xss"],
            "user": ["idor", "auth_bypass"],
            "search": ["xss", "sql_injection"],
            "query": ["sql_injection", "xss"],
            "name": ["xss", "sql_injection"],
            "file": ["lfi", "path_traversal"],
            "page": ["lfi", "path_traversal"],
            "url": ["ssrf", "open_redirect"],
            "cmd": ["rce"],
            "exec": ["rce"],
            "ping": ["rce", "ssrf"],
            "login": ["auth_bypass", "sql_injection"],
            "upload": ["file_upload", "rce"],
            "download": ["path_traversal"],
            "admin": ["auth_bypass"],
            "token": ["auth_bypass"],
            "redirect": ["open_redirect"],
        }

        candidates = []
        for word in words:
            if word in param_hints:
                candidates.append(ParamCandidate(
                    name=word,
                    vuln_types=param_hints[word],
                    confidence=0.3,
                    source="url_heuristic",
                    source_detail=f"keyword={word}",
                    endpoint=url,
                ))

        return candidates

    def _generic_fallback(self, url: str) -> list[ParamCandidate]:
        """通用参数回退 (极低置信度)"""
        return [
            ParamCandidate(name=n, vuln_types=vt, confidence=0.1,
                          source="generic_fallback", endpoint=url)
            for n, vt in [
                ("id", ["idor", "sql_injection"]),
                ("q", ["xss", "sql_injection"]),
                ("page", ["lfi"]),
                ("url", ["ssrf"]),
                ("file", ["lfi"]),
            ]
        ]

    def _deduplicate_and_sort(
        self, candidates: list[ParamCandidate]
    ) -> list[ParamCandidate]:
        """去重: 同名参数保留最高置信度的来源, 按confidence排序"""
        best: dict[str, ParamCandidate] = {}
        for c in candidates:
            if c.name not in best or c.confidence > best[c.name].confidence:
                best[c.name] = c
        return sorted(best.values(), key=lambda x: x.confidence, reverse=True)
