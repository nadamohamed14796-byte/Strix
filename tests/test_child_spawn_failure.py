"""Regression tests for child-agent startup failures."""

from __future__ import annotations

from typing import Any, cast

import pytest

from strix.core import execution
from strix.core.agents import AgentCoordinator


@pytest.mark.asyncio
async def test_failed_child_startup_is_terminal_and_notifies_parent(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root Agent", parent_id=None)

    async def fail_start(**_kwargs: Any) -> None:
        raise RuntimeError("session bootstrap failed")

    monkeypatch.setattr(execution, "_start_child_runner", fail_start)

    with pytest.raises(RuntimeError, match="session bootstrap failed"):
        await execution.spawn_child_agent(
            coordinator=coordinator,
            factory=lambda **_kwargs: object(),
            agents_db_path=tmp_path,
            sessions_to_close=cast("Any", []),
            run_config=cast("Any", None),
            max_turns=1,
            interactive=False,
            parent_ctx={"agent_id": "root"},
            name="XSS Specialist",
            task="Validate XSS",
            skills=[],
            parent_history=[],
        )

    parent_of, statuses, names, _ = await coordinator.graph_snapshot()
    child_ids = [agent_id for agent_id, parent_id in parent_of.items() if parent_id == "root"]

    assert len(child_ids) == 1
    child_id = child_ids[0]
    assert names[child_id] == "XSS Specialist"
    assert statuses[child_id] == "failed"
    assert not await coordinator.active_agents_except("root")
    assert len(coordinator.runtimes["root"].mailbox) == 1
    assert coordinator.runtimes["root"].mailbox[0]["type"] == "failed"


@pytest.mark.asyncio
async def test_child_spawn_starts_a_detached_runner(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root Agent", parent_id=None)
    fake_session = object()
    captured: dict[str, Any] = {}

    monkeypatch.setattr(execution, "open_agent_session", lambda *_args: fake_session)

    async def fake_run_agent_loop(**kwargs: Any) -> None:
        captured.update(kwargs)
        await coordinator.set_status(kwargs["agent_id"], "completed")

    monkeypatch.setattr(execution, "run_agent_loop", fake_run_agent_loop)

    result = await execution.spawn_child_agent(
        coordinator=coordinator,
        factory=lambda **kwargs: captured.setdefault("factory", kwargs) or object(),
        agents_db_path=tmp_path,
        sessions_to_close=cast("Any", []),
        run_config=cast("Any", None),
        max_turns=3,
        interactive=False,
        parent_ctx={"agent_id": "root", "spawn_child_agent": object()},
        name="XSS Specialist",
        task="Validate reflected and stored XSS",
        skills=[],
        parent_history=[{"role": "user", "content": "Target is in scope"}],
    )

    assert result["success"] is True
    child_id = result["agent_id"]
    child_runtime = coordinator.runtimes[child_id]
    assert child_runtime.session is fake_session
    assert child_runtime.task is not None
    await child_runtime.task

    assert captured["agent_id"] == child_id
    assert captured["context"]["parent_id"] == "root"
    assert captured["context"]["task"] == "Validate reflected and stored XSS"
    assert captured["context"]["spawn_child_agent"] is not None
    assert captured["factory"] == {"name": "XSS Specialist", "skills": []}
    assert coordinator.statuses[child_id] == "completed"
    assert coordinator.runtimes["root"].mailbox[0]["type"] == "completed"
