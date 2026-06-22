"""
Playwright 浏览器管理器

管理 Chromium 浏览器实例生命周期，提供页面创建和代理配置。
所有浏览器流量可选经 mitmproxy 代理以捕获隐藏 API 调用。
"""

import logging

from playwright.async_api import Browser, BrowserContext, Playwright, async_playwright

logger = logging.getLogger(__name__)

_playwright: Playwright | None = None
_browser: Browser | None = None
_proxy_url: str | None = None


async def init_playwright(proxy_url: str | None = None) -> Browser:
    global _playwright, _browser, _proxy_url
    _proxy_url = proxy_url
    _playwright = await async_playwright().start()

    launch_args = {
        "headless": True,
        "args": ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
    }
    if proxy_url:
        launch_args["proxy"] = {"server": proxy_url}

    _browser = await _playwright.chromium.launch(**launch_args)
    logger.info("Playwright 浏览器已启动 (proxy=%s)", proxy_url or "none")
    return _browser


async def close_playwright() -> None:
    global _playwright, _browser
    if _browser:
        await _browser.close()
        _browser = None
    if _playwright:
        await _playwright.stop()
        _playwright = None
    logger.info("Playwright 已关闭")


def get_browser() -> Browser:
    if _browser is None:
        raise RuntimeError("Playwright 未初始化，请先调用 init_playwright()")
    return _browser


async def create_context(proxy_url: str | None = None) -> BrowserContext:
    browser = get_browser()
    ctx_args = {"ignore_https_errors": True}
    if proxy_url:
        ctx_args["proxy"] = {"server": proxy_url}
    return await browser.new_context(**ctx_args)
