"""Persistent per-scan JavaScript asset audit ledger.

The ledger tracks discovered assets and their audit disposition. It does not
fetch or execute assets; workers perform analysis and record evidence here.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
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
        return {"version": 1, "assets": {}, "inventory_complete": False}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"JavaScript audit ledger is unreadable: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("assets"), dict):
        raise RuntimeError("JavaScript audit ledger has an invalid structure")
    return raw


def _save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp:
            temp.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
            temp.flush()
            os.fsync(temp.fileno())
            temp_path = Path(temp.name)
        temp_path.replace(path)
    except Exception:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Could not remove temporary JavaScript audit file %s", temp_path)
        raise


def _record_asset(
    data: dict[str, Any],
    key: str,
    status: str,
    notes: str,
    reason: str,
    content_sha256: str,
) -> dict[str, Any]:
    """Update one asset without downgrading an unchanged, already-audited file."""
    assets = data["assets"]
    previous = assets.get(key)
    is_new_asset = not isinstance(previous, dict)
    if is_new_asset:
        previous = {}

    previous_sha = str(previous.get("content_sha256", ""))
    next_sha = content_sha256.lower() or previous_sha
    effective_status = status
    if (
        status == "discovered"
        and previous.get("status") == "analyzed"
        and (not content_sha256 or next_sha == previous_sha)
    ):
        effective_status = "analyzed"

    entry = {
        "url": key,
        "status": effective_status,
        "notes": (notes.strip() or previous.get("notes", ""))[:12000],
        "reason": (
            reason.strip()
            or (previous.get("reason", "") if effective_status in {"failed", "skipped"} else "")
        )[:4000],
        "content_sha256": next_sha,
        "sources": (
            previous.get("sources", [])
            if isinstance(previous.get("sources", []), list)
            else []
        ),
    }
    assets[key] = entry
    # Inventory completion concerns discovery, not audit disposition. Only a
    # genuinely new URL reopens discovery; retrying a known asset does not.
    if is_new_asset:
        data["inventory_complete"] = False
    data["updated_count"] = len(assets)
    return entry


@function_tool(timeout=30)
async def record_javascript_asset(
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
        return json.dumps(
            {"success": False, "error": "asset_url must be an absolute HTTP(S) URL"}
        )
    if parsed.username or parsed.password:
        return json.dumps({"success": False, "error": "Credentials are not allowed in asset_url"})
    if status not in _VALID_STATUSES:
        return json.dumps({"success": False, "error": "Unsupported status"})
    if status in {"failed", "skipped"} and not reason.strip():
        return json.dumps({"success": False, "error": "failed/skipped status requires a reason"})
    if content_sha256 and (
        len(content_sha256) != 64
        or any(c not in "0123456789abcdefABCDEF" for c in content_sha256)
    ):
        return json.dumps(
            {"success": False, "error": "content_sha256 must be a 64-character hex digest"}
        )

    path = _ledger_path()
    if path is None:
        return json.dumps(
            {"success": False, "error": "Scan report state is unavailable; asset was not recorded"}
        )
    key = asset_url.strip()
    async with _LOCK:
        try:
            data = _load(path)
            entry = _record_asset(
                data, key, status, notes, reason, content_sha256
            )
            assets = data["assets"]
            _save(path, data)
        except (OSError, RuntimeError, TypeError) as exc:
            logger.exception("Failed to persist JavaScript audit asset")
            return json.dumps({"success": False, "error": f"Could not persist asset: {exc}"})
    return json.dumps(
        {"success": True, "asset": entry, "tracked_assets": len(assets)},
        ensure_ascii=False,
    )


def _merge_discovered_assets(
    data: dict[str, Any],
    asset_urls: list[str],
    source: str,
) -> int:
    """Merge validated source URLs while preserving per-URL provenance."""
    assets = data["assets"]
    unique_urls = list(dict.fromkeys(asset_urls))
    added = 0
    for url in unique_urls:
        previous = assets.get(url)
        if not isinstance(previous, dict):
            assets[url] = {
                "url": url,
                "status": "discovered",
                "notes": "",
                "reason": "",
                "content_sha256": "",
                "sources": [source],
            }
            added += 1
            continue
        raw_sources = previous.get("sources", [])
        sources = list(raw_sources) if isinstance(raw_sources, list) else []
        if source not in sources:
            sources.append(source)
        previous["sources"] = sources
    if added:
        data["inventory_complete"] = False
    data["updated_count"] = len(assets)
    return len(unique_urls)


@function_tool(timeout=60)
async def record_javascript_assets(
    asset_urls: list[str],
    source: str = "crawler",
) -> str:
    """Bulk-import JavaScript URLs from crawler output or recursive reference discovery.

    Pass only absolute HTTP(S) URLs already confirmed in the authorized scope.
    Use this after parsing Katana/headless crawler output and again after
    discovering HTML script references, imports, workers, or dynamic chunks.
    There is no scan-wide asset cap; split calls only when practical for tool payload size.
    Each URL is recorded separately; identical content URLs are not collapsed.
    """
    if not asset_urls:
        return json.dumps({"success": True, "recorded": 0, "tracked_assets": 0})
    source = source.strip()[:200] or "unspecified"
    normalized: list[str] = []
    invalid: list[str] = []
    for value in asset_urls:
        if not isinstance(value, str):
            invalid.append(str(value)[:300])
            continue
        url = value.strip()
        parsed = urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
        ):
            invalid.append(url[:300])
            continue
        normalized.append(url)
    if invalid:
        return json.dumps({
            "success": False,
            "error": (
                "Batch rejected; every entry must be an absolute HTTP(S) URL "
                "without embedded credentials"
            ),
            "invalid_count": len(invalid),
            "invalid_preview": invalid[:10],
        })
    path = _ledger_path()
    if path is None:
        return json.dumps({
            "success": False,
            "error": "Scan report state is unavailable; inventory was not recorded",
        })
    unique_urls = list(dict.fromkeys(normalized))
    async with _LOCK:
        try:
            data = _load(path)
            _merge_discovered_assets(data, unique_urls, source)
            assets = data["assets"]
            _save(path, data)
        except (OSError, RuntimeError, TypeError) as exc:
            logger.exception("Failed to bulk-import JavaScript assets")
            return json.dumps({
                "success": False,
                "error": f"Could not persist JavaScript inventory: {exc}",
            })
    return json.dumps({
        "success": True,
        "recorded": len(unique_urls),
        "duplicates_in_batch": len(normalized) - len(unique_urls),
        "tracked_assets": len(assets),
        "inventory_complete": False,
    }, ensure_ascii=False)


@function_tool(timeout=30)
async def complete_javascript_inventory(ctx: RunContextWrapper) -> str:
    """Mark recursive JavaScript discovery complete after the crawl/import queue is exhausted.

    Call only after crawler results, HTML script references, static imports,
    and discovered dynamic chunks have been reconciled. This does not mark
    any asset analyzed; each ledger entry must separately reach a terminal status.
    """
    context = ctx.context if isinstance(ctx.context, dict) else {}
    if context.get("parent_id") is not None:
        return json.dumps({
            "success": False,
            "error": "Only the root agent may close JavaScript inventory",
        })
    path = _ledger_path()
    if path is None:
        return json.dumps({"success": False, "error": "Scan report state is unavailable"})
    async with _LOCK:
        try:
            data = _load(path)
            data["inventory_complete"] = True
            _save(path, data)
        except (OSError, RuntimeError, TypeError) as exc:
            logger.exception("Failed to complete JavaScript inventory")
            return json.dumps(
                {"success": False, "error": f"Could not persist inventory completion: {exc}"}
            )
    return json.dumps({
        "success": True,
        "inventory_complete": True,
        "tracked_assets": len(data["assets"]),
    })


@function_tool(timeout=30)
async def get_javascript_audit_status() -> str:
    """Read the current per-scan JavaScript inventory and audit coverage summary."""
    path = _ledger_path()
    if path is None:
        return json.dumps({
            "success": False,
            "error": "Scan report state is unavailable",
        })
    try:
        status = javascript_audit_status(path.parent)
    except (OSError, RuntimeError, TypeError) as exc:
        logger.exception("Unable to read JavaScript audit status")
        return json.dumps({
            "success": False,
            "error": f"JavaScript audit ledger could not be read: {exc}",
        })
    return json.dumps({"success": True, **status}, ensure_ascii=False)


def javascript_audit_status(run_dir: Path) -> dict[str, Any]:
    """Return audit coverage for finish_scan; absent ledger means not initialized."""
    path = run_dir / "javascript_audit.json"
    if not path.exists():
        return {
            "initialized": False,
            "inventory_complete": False,
            "total": 0,
            "pending": [],
            "terminal": [],
        }
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
    return {
        "initialized": True,
        "inventory_complete": bool(data.get("inventory_complete")),
        "total": len(assets),
        "pending": pending,
        "terminal": terminal,
    }
