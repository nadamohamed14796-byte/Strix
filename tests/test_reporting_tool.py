from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from strix.tools.reporting.tool import _calculate_cvss, _reporting_phase_error


def test_cvss_without_demonstrated_impact_is_informational() -> None:
    score, severity, vector = _calculate_cvss(
        {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "N",
            "integrity": "N",
            "availability": "N",
        }
    )

    assert score == 0.0
    assert severity == "info"
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"


def test_cvss_calculation_does_not_fabricate_high_severity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenCVSS:
        def __init__(self, vector: str) -> None:
            raise RuntimeError(vector)

    monkeypatch.setattr("cvss.CVSS3", BrokenCVSS)

    with pytest.raises(ValueError, match="Failed to calculate CVSS"):
        _calculate_cvss(
            {
                "attack_vector": "N",
                "attack_complexity": "L",
                "privileges_required": "N",
                "user_interaction": "N",
                "scope": "U",
                "confidentiality": "L",
                "integrity": "N",
                "availability": "N",
            }
        )


def test_reporting_is_blocked_until_scan_wide_testing_phase() -> None:
    coordinator = SimpleNamespace(scan_phase="recon")
    context = SimpleNamespace(context={"coordinator": coordinator})

    blocked = _reporting_phase_error(context)  # type: ignore[arg-type]
    assert blocked is not None
    assert json.loads(blocked)["success"] is False

    coordinator.scan_phase = "testing"
    assert _reporting_phase_error(context) is None  # type: ignore[arg-type]
