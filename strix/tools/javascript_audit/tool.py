"""Persistent per-scan JavaScript asset audit ledger.

The ledger tracks discovered assets and their audit disposition. It does not
fetch or execute assets; workers perform analysis and record evidence here.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from agents import RunContextWrapper, function_tool

logger = logging.getLogger(__name__)
_LOCK = asyncio.Lock()
_VALID_STATUSES = {"discovered", "analyzed", "failed", "skipped"}


def _ledger_path() -> Path | None:
    try:
        from strix.report.state import get_global_report_state

        state = get_global_report_state()
        if state is None:
            return None
        return state.get_run_dir() / "javascript_audit.json"
    except (ImportError, AttributeError, OSError):
        logger.exception("Unable to resolve JavaScript audit ledger path")
        return None


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": 1, "assets": {}}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"JavaScript audit ledger is unreadable: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("assets"), dict):
        raise RuntimeError("JavaScript audit ledger has an invalid structure")
    return raw


def _save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".json.tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\\n", encoding="utf-8")
    temp.replace(path)


@function_tool(timeout=30)
async def record_javascript_asset(
    ctx: RunContextWrapper,
    asset_url: str,
    status: Literal["discovered", "analyzed", "failed", "skipped"] = "discovered",
    notes: str = "",
    reason: str = "",
    content_sha256: str = "",
) -> str:
    """Record one in-scope JavaScript asset in the persistent scan audit ledger.

    Call once when an asset is discovered (status=discovered), then update it
    after individually inspecting it. Use analyzed only after file-level
    analysis; failed/skipped require a concrete reason. Record the source URL
    even when identical content is deduplicated by hash. This tool tracks work;
    it does not fetch files, validate scope, or prove a vulnerability.
    """
    parsed = urlsplit(asset_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return json.dumps({"success": False, "error": "asset_url must be an absolute HTTP(S) URL"})
    if parsed.username or parsed.password:
        return json.dumps({"success": False, "error": "Credentials are not allowed in asset_url"})
    if status not in _VALID_STATUSES:
        return json.dumps({"success": False, "error": "Unsupported status"})
    if status in {"failed", "skipped"} and not reason.strip():
        return json.dumps({"success": False, "error": "failed/skipped status requires a reason"})
    if content_sha256 and (len(content_sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in content_sha256)):
        return json.dumps({"success": False, "error": "content_sha256 must be a 64-character hex digest"})

    path = _ledger_path()
    if path is None:
        return json.dumps({"success": False, "error": "Scan report state is unavailable; asset was not recorded"})
    key = asset_url.strip()
    async with _LOCK:
        try:
            data = _load(path)
            assets = data["assets"]
            previous = assets.get(key, {})
            entry = {
                "url": key,
                "status": status,
                "notes": notes.strip()[:12000],
                "reason": reason.strip()[:4000],
                "content_sha256": content_sha256.lower() or previous.get("content_sha256", ""),
            }
            assets[key] = entry
            data["updated_count"] = len(assets)
            _save(path, data)
        except (OSError, RuntimeError, TypeError) as exc:
            logger.exception("Failed to persist JavaScript audit asset")
            return json.dumps({"success": False, "error": f"Could not persist asset: {exc}"})
    return json.dumps({"success": True, "asset": entry, "tracked_assets": len(assets)}, ensure_ascii=False)


def javascript_audit_status(run_dir: Path) -> dict[str, Any]:
    """Return audit coverage for finish_scan; absent ledger means not initialized."""
    path = run_dir / "javascript_audit.json"
    if not path.exists():
        return {"initialized": False, "total": 0, "pending": [], "terminal": []}
    data = _load(path)
    assets = data["assets"]
    pending = [
        url for url, item in assets.items()
        if not isinstance(item, dict) or item.get("status") not in {"analyzed", "failed", "skipped"}
        or (item.get("status") in {"failed", "skipped"} and not str(item.get("reason", "")).strip())
    ]
    terminal = [
        {"url": url, "status": item.get("status"), "reason": item.get("reason", "")}
        for url, item in assets.items()
        if isinstance(item, dict) and item.get("status") in {"failed", "skipped"}
    ]
    return {"initialized": True, "total": len(assets), "pending": pending, "terminal": terminal}
