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
            sessions_to_close=cast(Any, []),
            run_config=cast(Any, None),
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
