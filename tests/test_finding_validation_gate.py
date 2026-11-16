"""Tests for the mandatory finding reportability gate."""

from strix.tools.reporting.tool import _finding_validation_gate


def test_recon_only_candidate_is_informational() -> None:
    status, _reason = _finding_validation_gate(
        impact_type="recon",
        impact_proven=True,
        chain_complete=True,
        credential_type="none",
        credential_access_proven=False,
    )
    assert status == "INFORMATIONAL"


def test_unproven_impact_is_not_reportable() -> None:
    status, _reason = _finding_validation_gate(
        impact_type="person",
        impact_proven=False,
        chain_complete=True,
        credential_type="none",
        credential_access_proven=False,
    )
    assert status == "INFORMATIONAL"


def test_incomplete_exploit_chain_is_preserved_for_follow_up() -> None:
    status, _reason = _finding_validation_gate(
        impact_type="platform",
        impact_proven=True,
        chain_complete=False,
        credential_type="none",
        credential_access_proven=False,
    )
    assert status == "NEEDS_CHAIN"


def test_private_credential_requires_proven_granted_access() -> None:
    status, _reason = _finding_validation_gate(
        impact_type="credential",
        impact_proven=True,
        chain_complete=True,
        credential_type="private",
        credential_access_proven=False,
    )
    assert status == "NEEDS_VALIDATION"


def test_public_client_configuration_is_not_a_credential_finding() -> None:
    status, _reason = _finding_validation_gate(
        impact_type="credential",
        impact_proven=True,
        chain_complete=True,
        credential_type="public_client",
        credential_access_proven=False,
    )
    assert status == "INFORMATIONAL"


def test_small_but_proven_person_impact_remains_reportable() -> None:
    status, reason = _finding_validation_gate(
        impact_type="person",
        impact_proven=True,
        chain_complete=True,
        credential_type="none",
        credential_access_proven=False,
    )
    assert status is None
    assert reason is None


def test_small_but_proven_platform_impact_remains_reportable() -> None:
    status, reason = _finding_validation_gate(
        impact_type="platform",
        impact_proven=True,
        chain_complete=True,
        credential_type="none",
        credential_access_proven=False,
    )
    assert status is None
    assert reason is None
