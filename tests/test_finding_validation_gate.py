"""Tests for the mandatory finding reportability gate."""

from strix.tools.notes import tools as notes_tools
from strix.tools.reporting.tool import (
    _finding_validation_gate,
    _preserve_validation_candidate,
    _redact_candidate_secrets,
)


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



def test_blocked_candidate_surfaces_note_persistence_failure(monkeypatch) -> None:
    monkeypatch.setattr(notes_tools, "_notes_path", None)
    monkeypatch.setattr(notes_tools, "_notes_storage", {})

    result = _preserve_validation_candidate(
        "Unverified API credential",
        {"source": "app.js:42"},
        "NEEDS_VALIDATION",
        "Credential access has not been demonstrated.",
    )

    assert result["success"] is False
    assert "persistence failed" in result["error"].lower()
    assert len(notes_tools._notes_storage) == 1


def test_blocked_candidate_redacts_secrets_before_note_storage() -> None:
    raw_api_key = "private-api-key-value-123456"
    raw_bearer = "eyJhbGciOiJIUzI1NiJ9.secret.payload"
    raw_github_token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

    sanitized = _redact_candidate_secrets(
        {
            "api_key": raw_api_key,
            "credential_type": "private",
            "credential_access_proven": False,
            "evidence": (
                f"Authorization: Bearer {raw_bearer}; "
                f"also found {raw_github_token}"
            ),
            "nested": [{"client_secret": raw_api_key}],
        }
    )
    serialized = str(sanitized)

    assert raw_api_key not in serialized
    assert raw_bearer not in serialized
    assert raw_github_token not in serialized
    assert "[REDACTED sha256:" in serialized
    assert sanitized["credential_type"] == "private"
    assert sanitized["credential_access_proven"] is False


def test_blocked_candidate_notes_survive_hydration(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(notes_tools, "_notes_path", None)
    monkeypatch.setattr(notes_tools, "_notes_storage", {})

    created = notes_tools._create_note_impl(
        title="[NEEDS_VALIDATION] Candidate",
        content="Candidate evidence retained for follow-up.",
        category="findings",
        tags=["finding-validation", "needs_validation"],
    )
    assert created["success"] is False

    notes_tools._notes_path = tmp_path / "notes.json"
    assert notes_tools._persist() is True
    notes_tools._notes_storage.clear()
    notes_tools.hydrate_notes_from_disk(tmp_path)

    restored = notes_tools._list_notes_impl(category="findings", include_content=True)
    assert restored["success"] is True
    assert len(restored["notes"]) == 1
    assert restored["notes"][0]["title"] == "[NEEDS_VALIDATION] Candidate"
    assert "retained for follow-up" in restored["notes"][0]["content"]
