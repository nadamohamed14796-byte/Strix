from __future__ import annotations

from strix.tools.javascript_audit.tool import _load, _save, javascript_audit_status


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
