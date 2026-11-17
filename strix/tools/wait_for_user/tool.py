"""Hand control back to the user and wait for their next message."""

from __future__ import annotations

import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.core.agents import coordinator_from_context


def _ctx(ctx: RunContextWrapper) -> dict[str, Any]:
    return ctx.context if isinstance(ctx.context, dict) else {}


@function_tool
async def wait_for_user(ctx: RunContextWrapper) -> str:
    """Yield to the user after writing the reply as plain text.

    Use only when no useful work remains until the user responds. Use
    wait_for_agents for child-agent results and finish_scan/agent_finish
    to terminate the engagement.
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    if coordinator is None or me is None:
        return json.dumps({"success": False, "error": "Agent coordinator or agent_id missing in context"})
    if not bool(inner.get("interactive", False)):
        return json.dumps({"success": False, "error": "No user is attached to an autonomous run. Keep working, and call finish_scan (root) or agent_finish (subagent) when the task is done."})
    async with coordinator._lock:
        stopped = coordinator.statuses.get(me) == "stopped"
    if stopped:
        return json.dumps({"success": True, "wait_outcome": "stopped"})
    pending, _ = await coordinator.consume_pending(me)
    if pending > 0:
        await coordinator.mark_running(me)
        return json.dumps({"success": True, "wait_outcome": "message_arrived", "pending_messages": pending})
    await coordinator.park_waiting(me, wait_kind="user")
    return json.dumps({"success": True, "wait_outcome": "waiting", "note": "Parked until the user responds."})
