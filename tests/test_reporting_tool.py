from __future__ import annotations

import pytest

import strix.report.state as report_state
from strix.tools.reporting.tool import _calculate_cvss, _do_create


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

async def test_vulnerability_report_fails_when_report_state_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(report_state, "get_global_report_state", lambda: None)

    result = await _do_create(
        title="Unauthorized profile access",
        description="A lower-privileged user can access a restricted profile.",
        impact="Restricted profile data is disclosed to an unauthorized user.",
        target="https://example.test",
        technical_analysis="The API omits the ownership check for the selected record.",
        poc_description="Authenticate as a standard user and request another user's profile.",
        poc_script_code="print('reproduction evidence captured')",
        remediation_steps="Enforce object-level authorization before returning the profile.",
        evidence="The response contains the other user's restricted profile fields.",
        assumptions="The attacker has a valid standard-user account.",
        counterevidence=(
            "The same request was denied when the object belonged to a protected tenant."
        ),
        confidence="high",
        severity_change_conditions="A confirmed tenant-boundary bypass would raise severity.",
        fix_effort="medium",
        cvss_breakdown={
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "L",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "N",
            "availability": "N",
        },
        endpoint=None,
        method=None,
        cve=None,
        cwe=None,
        code_locations=None,
        impact_type="person",
        impact_proven=True,
        chain_complete=True,
        credential_type="none",
        credential_access_proven=False,
    )

    assert result["success"] is False
    assert result["persisted"] is False
    assert "report state unavailable" in result["error"].lower()
    assert "report_id" not in result
