"""Regression tests for the mandatory ten-question finding gate."""

from strix.tools.reporting.tool import _VALIDATION_QUESTIONS, _validate_ten_questions


def _all_yes() -> dict[str, bool]:
    return {question: True for question in _VALIDATION_QUESTIONS}


def test_ten_question_gate_rejects_missing_answers() -> None:
    status, reason = _validate_ten_questions(None)
    assert status == "NEEDS_VALIDATION"
    assert "not supplied" in (reason or "")


def test_ten_question_gate_rejects_any_failed_or_non_boolean_answer() -> None:
    answers = _all_yes()
    answers["impact_observed"] = False
    answers["counterevidence_reviewed"] = "yes"  # type: ignore[assignment]

    status, reason = _validate_ten_questions(answers)

    assert status == "NEEDS_VALIDATION"
    assert "impact_observed" in (reason or "")
    assert "counterevidence_reviewed" in (reason or "")


def test_ten_question_gate_accepts_only_ten_explicit_boolean_yes_answers() -> None:
    status, reason = _validate_ten_questions(_all_yes())

    assert status is None
    assert reason is None


def test_ten_question_gate_rejects_extra_answers_when_required_answer_missing() -> None:
    answers = _all_yes()
    del answers["poc_reproducible"]
    answers["scanner_says_critical"] = True

    status, reason = _validate_ten_questions(answers)

    assert status == "NEEDS_VALIDATION"
    assert "poc_reproducible" in (reason or "")
