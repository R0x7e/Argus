"""
PoC 沙箱 Worker — 隔离执行 Python PoC 代码

安全层：
- RestrictedPython AST 验证
- Import 白名单
- 执行超时
- Docker 层: read_only, tmpfs, resource limits, non-root
"""

import io
import time
import asyncio
import builtins
from contextlib import redirect_stdout, redirect_stderr

from fastapi import FastAPI
from pydantic import BaseModel
from RestrictedPython import compile_restricted, safe_globals
from RestrictedPython.Eval import default_guarded_getiter
from RestrictedPython.Guards import guarded_unpack_sequence, safer_getattr
from RestrictedPython.PrintCollector import PrintCollector

app = FastAPI(title="Argus PoC Sandbox")

ALLOWED_IMPORTS = {
    "requests", "urllib3", "base64", "json", "hashlib",
    "re", "time", "socket", "struct", "urllib", "http",
    "collections", "itertools", "string", "binascii", "zlib",
}


class ExecuteRequest(BaseModel):
    code: str
    target_host: str
    timeout: int = 30
    allowed_hosts: list[str] = []


class ExecuteResponse(BaseModel):
    success: bool
    output: str = ""
    error: str = ""
    execution_time_ms: int = 0
    exit_code: int = 0


def _safe_import(name, *args, **kwargs):
    top_level = name.split(".")[0]
    if top_level not in ALLOWED_IMPORTS:
        raise ImportError(
            f"Import '{name}' is not allowed. Allowed: {sorted(ALLOWED_IMPORTS)}"
        )
    return builtins.__import__(name, *args, **kwargs)


def _run_code(byte_code, restricted_globals, stdout_buf, stderr_buf):
    with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
        exec(byte_code, restricted_globals)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/execute", response_model=ExecuteResponse)
async def execute(req: ExecuteRequest):
    start = time.monotonic()

    if len(req.code) > 10000:
        return ExecuteResponse(
            success=False,
            error="Code exceeds 10000 character limit",
            exit_code=1,
        )

    try:
        result = compile_restricted(req.code, filename="<poc>", mode="exec")
        if hasattr(result, "errors"):
            if result.errors:
                return ExecuteResponse(
                    success=False,
                    error=f"Compilation errors: {'; '.join(result.errors)}",
                    exit_code=1,
                )
            byte_code = result.code
        else:
            byte_code = result
    except SyntaxError as e:
        return ExecuteResponse(
            success=False, error=f"Syntax error: {e}", exit_code=1
        )
    except Exception as e:
        return ExecuteResponse(
            success=False, error=f"Compilation error: {e}", exit_code=1
        )

    restricted_globals = safe_globals.copy()
    restricted_globals["__builtins__"] = dict(safe_globals["__builtins__"])
    restricted_globals["__builtins__"]["__import__"] = _safe_import
    restricted_globals["_getiter_"] = default_guarded_getiter
    restricted_globals["_unpack_sequence_"] = guarded_unpack_sequence
    restricted_globals["_getattr_"] = safer_getattr
    restricted_globals["_print_"] = PrintCollector
    restricted_globals["_getitem_"] = lambda obj, key: obj[key]
    restricted_globals["_write_"] = lambda obj: obj
    restricted_globals["_inplacevar_"] = lambda op, x, y: op(x, y)
    restricted_globals["TARGET_HOST"] = req.target_host
    restricted_globals["ALLOWED_HOSTS"] = req.allowed_hosts or [req.target_host]

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    try:
        loop = asyncio.get_event_loop()
        await asyncio.wait_for(
            loop.run_in_executor(
                None, _run_code, byte_code, restricted_globals,
                stdout_capture, stderr_capture
            ),
            timeout=req.timeout,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        printed = restricted_globals.get("_print")
        printed_output = printed() if callable(printed) else ""
        combined_output = (stdout_capture.getvalue() + printed_output)[:10000]
        return ExecuteResponse(
            success=True,
            output=combined_output,
            error=stderr_capture.getvalue()[:2000],
            execution_time_ms=elapsed_ms,
            exit_code=0,
        )
    except asyncio.TimeoutError:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        printed = restricted_globals.get("_print")
        printed_output = printed() if callable(printed) else ""
        combined_output = (stdout_capture.getvalue() + printed_output)[:5000]
        return ExecuteResponse(
            success=False,
            output=combined_output,
            error=f"Execution timeout ({req.timeout}s)",
            execution_time_ms=elapsed_ms,
            exit_code=124,
        )
    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return ExecuteResponse(
            success=False,
            error=str(e)[:2000],
            execution_time_ms=elapsed_ms,
            exit_code=1,
        )
