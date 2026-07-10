"""Tier2 LLM client — single entry point for the external LLM (v0.4).

Endpoint/model/key are read from environment (kept out of the repo via .gitignore'd
.env). The judge uses deepseek-v4-pro via the kspmas gateway, which places JSON
directly in `content` (reasoning in `reasoning_content`) — no enable_thinking
workaround needed.

Stability (Part 5): temperature defaults to 0.0. The provider does not document a
seed param, so determinism is "temperature=0 + same prompt", and Part 5 verifies
that empirically over 5 runs. Parse is lenient: we extract the first balanced {...}
JSON object (handles reasoning-model JSON split across lines / trailing prose).
"""
from __future__ import annotations

import json
import os
import re
import time

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


DEFAULT_BASE = "https://kspmas.ksyun.com/v1/chat/completions"
DEFAULT_MODEL = "deepseek-v4-pro"
DEFAULT_TIMEOUT = 120.0


def _cfg():
    return {
        "base": os.environ.get("TIER2_LLM_BASE", DEFAULT_BASE),
        "key": os.environ.get("TIER2_LLM_API_KEY", ""),
        "model": os.environ.get("TIER2_LLM_MODEL", DEFAULT_MODEL),
        "timeout": float(os.environ.get("TIER2_LLM_TIMEOUT", str(DEFAULT_TIMEOUT))),
    }


def _extract_json(text: str) -> dict | None:
    """Extract the first balanced JSON object from `text`. Returns None on failure.

    Handles: JSON in `content` with newlines; trailing prose after the JSON; a
    code-fence wrapper (```json ... ```); and reasoning-model output where the
    JSON is split across many lines. We scan for the first '{' and track brace
    depth (respecting string literals) to find the matching '}'.
    """
    if not text:
        return None
    # strip code fences if present
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if fenced:
        text = fenced.group(1)
    depth = 0
    in_str = False
    esc = False
    start = -1
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                cand = text[start : i + 1]
                try:
                    return json.loads(cand)
                except json.JSONDecodeError:
                    # keep scanning for a later balanced object
                    start = -1
                    continue
    return None


def chat(messages: list[dict], *, temperature: float = 0.0,
         max_tokens: int = 1200) -> tuple[str, float, dict]:
    """Call the LLM. Returns (content, latency_ms, meta).

    meta carries raw info for debugging/fallback decisions (parse_ok, usage).
    Raises on HTTP/transport error so the caller can apply the honest fallback.
    """
    if not _HAS_HTTPX:
        raise RuntimeError("httpx is required for the Tier2 LLM client")
    cfg = _cfg()
    if not cfg["key"]:
        raise RuntimeError("TIER2_LLM_API_KEY not set (see .env, gitignored)")
    t0 = time.perf_counter()
    client = httpx.Client(timeout=cfg["timeout"])
    try:
        r = client.post(
            cfg["base"],
            headers={
                "Authorization": f"Bearer {cfg['key']}",
                "Content-Type": "application/json",
            },
            json={
                "model": cfg["model"],
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            },
        )
        r.raise_for_status()
        data = r.json()
    finally:
        client.close()
    content = data["choices"][0]["message"].get("content", "") or ""
    latency = (time.perf_counter() - t0) * 1000.0
    meta = {
        "model": cfg["model"],
        "finish_reason": data["choices"][0].get("finish_reason"),
        "usage": data.get("usage"),
        "content_len": len(content),
        "parse_ok": _extract_json(content) is not None,
    }
    return content, latency, meta
