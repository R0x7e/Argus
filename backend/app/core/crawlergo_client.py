"""
crawlergo HTTP API 客户端

封装对 crawlergo sidecar 容器的 HTTP 调用。
"""

import logging

import httpx

logger = logging.getLogger(__name__)


class CrawlergoClient:
    def __init__(self, base_url: str):
        self._base_url = base_url.rstrip("/")

    async def crawl(
        self,
        target_url: str,
        max_depth: int = 3,
        max_count: int = 500,
        timeout: int = 120,
    ) -> dict:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout + 10)) as client:
            resp = await client.post(
                f"{self._base_url}/crawl",
                json={
                    "url": target_url,
                    "max_depth": max_depth,
                    "max_crawl_count": max_count,
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{self._base_url}/health")
                return resp.status_code == 200
        except Exception:
            return False
