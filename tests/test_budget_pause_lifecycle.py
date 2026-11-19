from __future__ import annotations

from types import SimpleNamespace
import asyncio

import pytest

from strix.core.agents import AgentCoordinator
from strix.core.hooks import BudgetPausedError, ReportUsageHooks



def test_pause_policy_blocks_the_next_model_call_at_the_budget_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator = AgentCoordinator()
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=5.0, budget_policy="pause")

    class _ReportState:
        @staticmethod
        def get_total_llm_cost() -> float:
            return 5.25

    def _get_report_state() -> _ReportState:
        return _ReportState()

    monkeypatch.setattr("strix.core.hooks.get_global_report_state", _get_report_state)

    with pytest.raises(BudgetPausedError) as raised:
        hooks._pause_if_limited(SimpleNamespace(context={"coordinator": coordinator}))

    assert raised.value.resume_epoch == coordinator.resume_epoch
    assert raised.value.operator_pause is False


def test_operator_pause_is_checked_before_any_new_model_call() -> None:
    coordinator = AgentCoordinator()
    hooks = ReportUsageHooks(model="test-model", budget_policy="pause")
    coordinator._operator_paused = True
    coordinator._budget_paused = True

    with pytest.raises(BudgetPausedError) as raised:
        hooks._pause_if_operator_paused(SimpleNamespace(context={"coordinator": coordinator}))

    assert raised.value.operator_pause is True
    assert raised.value.resume_epoch == coordinator.resume_epoch


@pytest.mark.asyncio
async def test_resume_epoch_prevents_lost_budget_resume() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)
    await coordinator.park_for_budget("root")
    parked_epoch = coordinator.resume_epoch

    waiter = asyncio.create_task(
        coordinator.wait_for_budget_resume("root", parked_epoch=parked_epoch)
    )
    # Resume before the waiter is scheduled: the epoch must make the wake durable.
    await coordinator.resume_budget()
    await asyncio.wait_for(waiter, timeout=1)

    assert coordinator.statuses["root"] == "running"
    assert coordinator.budget_paused is False
    assert coordinator.resume_epoch == parked_epoch + 1


@pytest.mark.asyncio
async def test_operator_pause_is_distinct_and_cleared_on_resume() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", parent_id=None)

    assert coordinator.budget_policy == "stop"
    await coordinator.pause_budget()
    assert coordinator.operator_paused is True
    assert coordinator.budget_paused is True

    await coordinator.resume_budget()
    assert coordinator.operator_paused is False
    assert coordinator.budget_paused is False


@pytest.mark.asyncio
async def test_operator_pause_survives_coordinator_snapshot_restore() -> None:
    original = AgentCoordinator()
    await original.register("root", "root", parent_id=None)
    await original.pause_budget()

    snapshot = await original.snapshot()
    restored = AgentCoordinator()
    await restored.restore(snapshot)

    assert restored.operator_paused is True
    assert restored.budget_paused is True


@pytest.mark.asyncio
async def test_resume_budget_can_replace_the_limit() -> None:
    coordinator = AgentCoordinator()
    limits = [10.0]
    coordinator.set_budget_limit_setter(lambda value: limits.__setitem__(0, value))
    await coordinator.pause_budget()

    await coordinator.resume_budget(max_budget_usd=25.0)

    assert limits == [25.0]
