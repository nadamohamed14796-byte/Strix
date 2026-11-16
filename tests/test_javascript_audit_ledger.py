from __future__ import annotations

from strix.tools.javascript_audit.tool import (
    _load,
    _merge_discovered_assets,
    _save,
    javascript_audit_status,
)


def test_missing_ledger_is_not_treated_as_completed(tmp_path):
    status = javascript_audit_status(tmp_path)

    assert status["initialized"] is False
    assert status["inventory_complete"] is False
    assert status["pending"] == []


def test_open_inventory_blocks_completion(tmp_path):
    _save(
        tmp_path / "javascript_audit.json",
        {
            "version": 1,
            "inventory_complete": False,
            "assets": {
                "https://example.test/app.js": {
                    "url": "https://example.test/app.js",
                    "status": "analyzed",
                    "reason": "",
                }
            },
        },
    )

    status = javascript_audit_status(tmp_path)

    assert status["inventory_complete"] is False
    assert status["pending"] == []


def test_discovered_asset_remains_pending_until_individually_audited(tmp_path):
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


def test_failed_asset_is_terminal_but_reported_as_a_coverage_gap(tmp_path):
    _save(
        tmp_path / "javascript_audit.json",
        {
            "version": 1,
            "inventory_complete": True,
            "assets": {
                "https://example.test/bundle.js": {
                    "url": "https://example.test/bundle.js",
                    "status": "failed",
                    "reason": "Fetch timed out after retries",
                }
            },
        },
    )

    status = javascript_audit_status(tmp_path)

    assert status["pending"] == []
    assert status["terminal"] == [
        {
            "url": "https://example.test/bundle.js",
            "status": "failed",
            "reason": "Fetch timed out after retries",
        }
    ]


def test_failed_asset_without_reason_is_not_terminal(tmp_path):
    _save(
        tmp_path / "javascript_audit.json",
        {
            "version": 1,
            "inventory_complete": True,
            "assets": {
                "https://example.test/bundle.js": {
                    "url": "https://example.test/bundle.js",
                    "status": "failed",
                    "reason": "",
                }
            },
        },
    )

    status = javascript_audit_status(tmp_path)

    assert status["pending"] == ["https://example.test/bundle.js"]


def test_ledger_round_trips_as_json(tmp_path):
    path = tmp_path / "javascript_audit.json"
    expected = {"version": 1, "inventory_complete": True, "assets": {}}

    _save(path, expected)

    assert _load(path) == expected



def test_finish_scan_refuses_to_finish_before_inventory_is_closed(tmp_path, monkeypatch):
    from types import SimpleNamespace

    import strix.report.state as report_state
    from strix.tools.finish.tool import _do_finish

    state = SimpleNamespace(
        get_run_dir=lambda: tmp_path,
        vulnerability_reports=[],
        update_scan_final_fields=lambda **_kwargs: None,
    )
    monkeypatch.setattr(report_state, "get_global_report_state", lambda: state)

    result = _do_finish(
        parent_id=None,
        executive_summary="Summary",
        methodology="Methodology",
        technical_analysis="Analysis",
        recommendations="Recommendations",
    )

    assert result["success"] is False
    assert result["scan_completed"] is False
    assert result["javascript_audit"]["inventory_complete"] is False


def test_finish_scan_accepts_closed_inventory_and_terminal_asset_gaps(tmp_path, monkeypatch):
    from types import SimpleNamespace

    import strix.report.state as report_state
    from strix.tools.finish.tool import _do_finish

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
    )

    assert result["success"] is True
    assert result["javascript_assets_audited"] == 1
    assert result["javascript_audit_gaps"][0]["status"] == "failed"
    assert persisted["executive_summary"] == "Summary"



def test_bulk_import_preserves_every_url_and_source_provenance():
    data = {
        "version": 1,
        "inventory_complete": True,
        "assets": {
            "https://example.test/app.js": {
                "url": "https://example.test/app.js",
                "status": "analyzed",
                "notes": "Reviewed routes and auth checks",
                "content_sha256": "a" * 64,
                "sources": ["html-script"],
            }
        },
    }

    recorded = _merge_discovered_assets(
        data,
        [
            "https://example.test/app.js",
            "https://example.test/chunk.js",
            "https://example.test/chunk.js",
        ],
        "katana-jsonl",
    )

    assert recorded == 2
    assert data["inventory_complete"] is False
    assert data["assets"]["https://example.test/app.js"]["status"] == "analyzed"
    assert data["assets"]["https://example.test/app.js"]["notes"] == (
        "Reviewed routes and auth checks"
    )
    assert data["assets"]["https://example.test/app.js"]["sources"] == [
        "html-script",
        "katana-jsonl",
    ]
    assert "https://example.test/chunk.js" in data["assets"]


def test_bulk_import_reopens_inventory_after_previous_completion():
    data = {
        "version": 1,
        "inventory_complete": True,
        "assets": {},
    }

    _merge_discovered_assets(
        data,
        ["https://example.test/new-import.js"],
        "html-import-recursion",
    )

    assert data["inventory_complete"] is False
    assert data["assets"]["https://example.test/new-import.js"]["status"] == "discovered"
