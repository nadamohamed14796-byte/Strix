from __future__ import annotations

from types import SimpleNamespace

from strix.tools.javascript_audit.tool import (
    _merge_discovered_assets,
    _record_asset,
    _save,
    javascript_audit_status,
)


def test_missing_javascript_ledger_does_not_block_non_js_scans(tmp_path):
    status = javascript_audit_status(tmp_path)

    assert status["initialized"] is False
    assert status["inventory_complete"] is False
    assert status["pending"] == []


def test_discovered_assets_remain_pending_until_individually_audited(tmp_path):
    _save(
        tmp_path / "javascript_audit.json",
        {
            "version": 1,
            "inventory_complete": True,
            "assets": {
                "https://example.test/app.js": {
                    "url": "https://example.test/app.js",
                    "status": "discovered",
                    "reason": "",
                }
            },
        },
    )

    status = javascript_audit_status(tmp_path)

    assert status["inventory_complete"] is True
    assert status["pending"] == ["https://example.test/app.js"]


def test_failed_and_skipped_assets_are_terminal_but_reported_as_gaps(tmp_path):
    _save(
        tmp_path / "javascript_audit.json",
        {
            "version": 1,
            "inventory_complete": True,
            "assets": {
                "https://example.test/failed.js": {
                    "url": "https://example.test/failed.js",
                    "status": "failed",
                    "reason": "Fetch timed out after retries",
                },
                "https://example.test/skipped.js": {
                    "url": "https://example.test/skipped.js",
                    "status": "skipped",
                    "reason": "Redirect left authorized scope",
                },
            },
        },
    )

    status = javascript_audit_status(tmp_path)

    assert status["pending"] == []
    assert {entry["status"] for entry in status["terminal"]} == {"failed", "skipped"}


def test_bulk_import_has_no_scan_wide_asset_ceiling():
    data = {"version": 1, "inventory_complete": True, "assets": {}}
    urls = [f"https://example.test/{index}.js" for index in range(5001)]

    recorded = _merge_discovered_assets(data, urls, "crawler")

    assert recorded == 5001
    assert len(data["assets"]) == 5001
    assert data["inventory_complete"] is False


def test_finish_scan_blocks_initialized_inventory_with_pending_assets(tmp_path, monkeypatch):
    import strix.report.state as report_state
    from strix.tools.finish.tool import _do_finish

    _save(
        tmp_path / "javascript_audit.json",
        {
            "version": 1,
            "inventory_complete": False,
            "assets": {
                "https://example.test/app.js": {
                    "url": "https://example.test/app.js",
                    "status": "discovered",
                    "reason": "",
                }
            },
        },
    )
    persisted = {}
    state = SimpleNamespace(
        get_run_dir=lambda: tmp_path,
        vulnerability_reports=[],
        update_scan_final_fields=lambda **kwargs: persisted.update(kwargs),
    )
    monkeypatch.setattr(report_state, "get_global_report_state", lambda: state)

    result = _do_finish(
        parent_id=None,
        executive_summary="Summary",
        methodology="Methodology",
        technical_analysis="Analysis",
        recommendations="Recommendations",
        agent_graph={},
    )

    assert result["success"] is False
    assert result["scan_completed"] is False
    assert result["javascript_audit"]["pending_count"] == 1
    assert persisted == {}


def test_finish_scan_allows_no_js_ledger_and_closed_inventory(tmp_path, monkeypatch):
    import strix.report.state as report_state
    from strix.tools.finish.tool import _do_finish

    persisted = {}
    state = SimpleNamespace(
        get_run_dir=lambda: tmp_path,
        vulnerability_reports=[],
        update_scan_final_fields=lambda **kwargs: persisted.update(kwargs),
    )
    monkeypatch.setattr(report_state, "get_global_report_state", lambda: state)
    monkeypatch.setattr("strix.tools.finish.tool._coverage_summary", lambda _graph: {})

    result_without_ledger = _do_finish(
        parent_id=None,
        executive_summary="Summary",
        methodology="Methodology",
        technical_analysis="Analysis",
        recommendations="Recommendations",
        agent_graph={},
    )
    assert result_without_ledger["scan_completed"] is True

    _save(
        tmp_path / "javascript_audit.json",
        {
            "version": 1,
            "inventory_complete": True,
            "assets": {
                "https://example.test/unavailable.js": {
                    "url": "https://example.test/unavailable.js",
                    "status": "failed",
                    "reason": "Fetch failed after retries",
                }
            },
        },
    )
    result_with_terminal_gap = _do_finish(
        parent_id=None,
        executive_summary="Summary",
        methodology="Methodology",
        technical_analysis="Analysis",
        recommendations="Recommendations",
        agent_graph={},
    )

    assert result_with_terminal_gap["scan_completed"] is True
    assert result_with_terminal_gap["javascript_assets_audited"] == 1
    assert result_with_terminal_gap["javascript_audit_gaps"][0]["status"] == "failed"

def test_repeated_discovery_does_not_downgrade_analyzed_unchanged_asset():
    data = {
        "version": 1,
        "inventory_complete": True,
        "assets": {
            "https://example.test/app.js": {
                "url": "https://example.test/app.js",
                "status": "analyzed",
                "notes": "Reviewed all functions and sinks",
                "reason": "",
                "content_sha256": "a" * 64,
                "sources": ["crawler"],
            }
        },
    }

    entry = _record_asset(
        data,
        "https://example.test/app.js",
        "discovered",
        "",
        "",
        "",
    )

    assert entry["status"] == "analyzed"
    assert entry["notes"] == "Reviewed all functions and sinks"
    assert data["inventory_complete"] is True


def test_changed_javascript_content_reopens_asset_for_analysis():
    data = {
        "version": 1,
        "inventory_complete": True,
        "assets": {
            "https://example.test/app.js": {
                "url": "https://example.test/app.js",
                "status": "analyzed",
                "notes": "Reviewed previous version",
                "reason": "",
                "content_sha256": "a" * 64,
                "sources": ["crawler"],
            }
        },
    }

    entry = _record_asset(
        data,
        "https://example.test/app.js",
        "discovered",
        "",
        "",
        "b" * 64,
    )

    assert entry["status"] == "discovered"
    assert entry["content_sha256"] == "b" * 64
    assert entry["notes"] == ""
    assert data["inventory_complete"] is True


def test_new_single_asset_reopens_discovery_inventory():
    data = {"version": 1, "inventory_complete": True, "assets": {}}

    _record_asset(
        data,
        "https://example.test/new.js",
        "discovered",
        "",
        "",
        "",
    )

    assert data["inventory_complete"] is False

