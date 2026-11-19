from __future__ import annotations

import asyncio

import pytest

from strix.core.agents import AgentCoordinator


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
async def test_resume_budget_can_replace_the_limit() -> None:
    coordinator = AgentCoordinator()
    limits = [10.0]
    coordinator.set_budget_limit_setter(lambda value: limits.__setitem__(0, value))
    await coordinator.pause_budget()

    await coordinator.resume_budget(max_budget_usd=25.0)

    assert limits == [25.0]
