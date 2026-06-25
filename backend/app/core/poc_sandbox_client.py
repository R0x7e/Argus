"""
PoC 沙箱 HTTP API 客户端

封装对 poc-sandbox sidecar 容器的 HTTP 调用。
"""

import logging

import httpx

logger = logging.getLogger(__name__)


class PocSandboxClient:
    def __init__(self, base_url: str):
        self._base_url = base_url.rstrip("/")
        from app.config import get_settings
        self._sidecar_secret = get_settings().SIDECAR_SECRET

    async def execute(
        self,
        code: str,
        target_host: str,
        timeout: int = 30,
        allowed_hosts: list[str] | None = None,
    ) -> dict:
        headers = {}
        if self._sidecar_secret:
            headers["X-Sidecar-Secret"] = self._sidecar_secret
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout + 10)) as client:
            resp = await client.post(
                f"{self._base_url}/execute",
                json={
                    "code": code,
                    "target_host": target_host,
                    "timeout": timeout,
                    "allowed_hosts": allowed_hosts or [target_host],
                },
                headers=headers,
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
