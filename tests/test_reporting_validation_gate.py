"""Regression tests for the mandatory evidence-backed ten-question gate."""

from strix.tools.reporting.tool import _VALIDATION_QUESTIONS, _validate_ten_questions


def _all_yes() -> dict[str, dict[str, object]]:
    return {
        question: {"passed": True, "evidence": f"Evidence for {question}"}
        for question in _VALIDATION_QUESTIONS
    }


def test_ten_question_gate_rejects_missing_answers() -> None:
    status, reason = _validate_ten_questions(None)
    assert status == "NEEDS_VALIDATION"
    assert "not supplied" in (reason or "")


def test_ten_question_gate_rejects_failed_answer() -> None:
    answers = _all_yes()
    answers["impact_observed"] = {"passed": False, "evidence": "No impact observed"}

    status, reason = _validate_ten_questions(answers)

    assert status == "NEEDS_VALIDATION"
    assert "impact_observed" in (reason or "")


def test_ten_question_gate_rejects_yes_without_evidence() -> None:
    answers = _all_yes()
    answers["poc_reproducible"] = {"passed": True, "evidence": ""}

    status, reason = _validate_ten_questions(answers)

    assert status == "NEEDS_VALIDATION"
    assert "poc_reproducible" in (reason or "")


def test_ten_question_gate_accepts_ten_evidence_backed_yes_answers() -> None:
    status, reason = _validate_ten_questions(_all_yes())

    assert status is None
    assert reason is None


def test_ten_question_gate_rejects_extra_answers_when_required_answer_missing() -> None:
    answers = _all_yes()
    del answers["poc_reproducible"]
    answers["scanner_says_critical"] = {"passed": True, "evidence": "Scanner output"}

    status, reason = _validate_ten_questions(answers)

    assert status == "NEEDS_VALIDATION"
    assert "poc_reproducible" in (reason or "")
