from strix.tools.agents_graph.tools import _render_completion_report


def test_completion_report_preserves_unresolved_work_for_parent() -> None:
    report = _render_completion_report(
        agent_name="XSS Validator",
        agent_id="abc12345",
        task="Validate reflected input on the search endpoint",
        success=True,
        result_summary="Confirmed reflection but did not establish script execution.",
        findings=["Input is reflected in an HTML attribute."],
        open_items=["Obtain an authenticated account to test the state-changing sink."],
        recommendations=["Assign a follow-up validator with an authenticated session."],
    )

    assert "Open items (unresolved, need follow-up):" in report
    assert "Obtain an authenticated account" in report
    assert "Assign a follow-up validator" in report


def test_completion_report_explicitly_marks_no_open_items() -> None:
    report = _render_completion_report(
        agent_name="Recon",
        agent_id="def67890",
        task="Map the public application surface",
        success=True,
        result_summary="Completed bounded mapping.",
        findings=[],
        open_items=[],
        recommendations=[],
    )

    assert "Open items (unresolved, need follow-up):" in report
    assert "- (none)" in report
