"""SDK-native state for Strix's addressable agent graph."""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

from strix.core.sessions import session_write_lock


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from agents.items import TResponseInputItem
    from agents.memory import Session


logger = logging.getLogger(__name__)

Status = Literal["running", "waiting", "completed", "stopped", "crashed", "failed", "budget_paused"]
ScanPhase = Literal["recon", "testing"]

# Why an agent parked. The user can message any agent, so this - not the agent's
# position in the tree - decides whether waiting is bounded: only an agent waiting
# on other agents is re-checked on a timer.
WaitKind = Literal["user", "agents", "stalled"]


@dataclass(slots=True)
class AgentRuntime:
    session: Session | None = None
    task: asyncio.Task[Any] | None = None
    stream: Any | None = None
    interrupt_on_message: bool = False
    wake: asyncio.Event = field(default_factory=asyncio.Event)
    mailbox: list[dict[str, Any]] = field(default_factory=list)
    user_wake_required: bool = False


class AgentCoordinator:
    """Single owner for graph state, SDK runtimes, messages, and resume snapshots."""

    def __init__(self) -> None:
        self.statuses: dict[str, Status] = {}
        self.scan_phase: ScanPhase = "recon"
        self.target_ledger: dict[str, dict[str, Any]] = {}
        self._target_ledger_initialized = False
        self.parent_of: dict[str, str | None] = {}
        self.names: dict[str, str] = {}
        self.metadata: dict[str, dict[str, Any]] = {}
        self.pending_counts: dict[str, int] = {}
        self.errors: dict[str, str] = {}
        self.recovery_counts: dict[str, int] = {}
        self.idle_resume_counts: dict[str, int] = {}
        self.wait_kinds: dict[str, WaitKind] = {}
        self.runtimes: dict[str, AgentRuntime] = {}
        self._parent_notified: set[str] = set()
        self._lock = asyncio.Lock()
        self._snapshot_path: Path | None = None
        self.is_shutting_down = False
        self._budget_stopped = False
        self._reserve_stopped = False
        self._budget_paused = False
        self._extend_budget: Callable[[], None] | None = None
        self._target_append_handler: (
            Callable[[list[dict[str, Any]]], Awaitable[dict[str, Any]]] | None
        ) = None
        self._target_append_ready = asyncio.Event()

    def set_target_append_handler(
        self,
        handler: Callable[[list[dict[str, Any]]], Awaitable[dict[str, Any]]],
    ) -> None:
        """Register the active-run handler that updates scope and root instructions."""
        self._target_append_handler = handler
        self._target_append_ready.set()

    async def append_targets(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Append user-authorized targets to the currently running Recon queue."""
        if self._target_append_handler is None:
            try:
                await asyncio.wait_for(self._target_append_ready.wait(), timeout=30)
            except TimeoutError:
                raise RuntimeError("Live target addition is not ready for this scan") from None
        handler = self._target_append_handler
        if handler is None:
            raise RuntimeError("Live target addition is unavailable for this scan")
        return await handler(entries)

    async def append_target_entries(
        self,
        entries: list[dict[str, Any]],
        *,
        persist: Callable[[], None] | None = None,
    ) -> list[str]:
        """Atomically append ledger entries while Recon is still open.

        The persistence callback runs under the coordinator lock before the ledger
        changes, so the root cannot cross the Recon barrier between persisting the
        new scope and making the new targets visible to the barrier.
        """
        normalized: dict[str, dict[str, Any]] = {}
        for entry in entries:
            target_id = entry.get("target_id")
            if not isinstance(target_id, str) or not target_id:
                raise ValueError("Every target ledger entry must have a stable target_id")
            if target_id in normalized:
                raise ValueError(f"Duplicate target_id in appended scope: {target_id}")
            normalized[target_id] = {
                **entry,
                "status": "queued",
                "assigned_to": None,
                "attempts": 0,
                "recon_summary": "",
            }

        async with self._lock:
            if not self._target_ledger_initialized:
                raise RuntimeError("Target ledger is not initialized")
            if self.scan_phase != "recon":
                raise ValueError("New targets can only be appended while the scan is in Recon")
            additions: dict[str, dict[str, Any]] = {}
            for target_id, entry in normalized.items():
                current = self.target_ledger.get(target_id)
                if current is None:
                    additions[target_id] = entry
                    continue
                for key in ("type", "value", "workspace_path"):
                    if current.get(key, "") != entry.get(key, ""):
                        raise ValueError(
                            f"Target identity changed for {target_id}; refusing scope drift"
                        )
            if not additions:
                return []
            if persist is not None:
                persist()
            self.target_ledger.update(additions)

        await self._maybe_snapshot()
        return sorted(additions)

    def set_snapshot_path(self, path: Path) -> None:
        self._snapshot_path = path

    def mark_shutting_down(self) -> None:
        self.is_shutting_down = True

    async def initialize_target_ledger(self, entries: list[dict[str, Any]]) -> None:
        """Initialize or verify the canonical, persisted set of authorized targets."""
        normalized: dict[str, dict[str, Any]] = {}
        for entry in entries:
            target_id = entry.get("target_id")
            if not isinstance(target_id, str) or not target_id:
                raise ValueError("Every target ledger entry must have a stable target_id")
            if target_id in normalized:
                raise ValueError(f"Duplicate target_id in canonical ledger: {target_id}")
            normalized[target_id] = {
                **entry,
                "status": "queued",
                "assigned_to": None,
                "attempts": 0,
                "recon_summary": "",
            }

        async with self._lock:
            if self._target_ledger_initialized:
                existing_ids = set(self.target_ledger)
                incoming_ids = set(normalized)
                if not existing_ids.issubset(incoming_ids):
                    raise ValueError(
                        "The authorized target set changed; refusing to remove prior scope"
                    )
                for target_id in existing_ids:
                    entry = normalized[target_id]
                    current = self.target_ledger[target_id]
                    for key in ("type", "value", "workspace_path"):
                        if current.get(key, "") != entry.get(key, ""):
                            raise ValueError(
                                f"Target identity changed for {target_id}; refusing scope drift"
                            )
                additions = incoming_ids - existing_ids
                if additions and self.scan_phase != "recon":
                    raise ValueError(
                        "New targets can only be appended before the scan enters Testing"
                    )
                # Preserve every existing status, owner, attempt count, and summary.
                # Only genuinely new authorized targets enter the Recon queue.
                for target_id in additions:
                    self.target_ledger[target_id] = normalized[target_id]
            else:
                self.target_ledger = normalized
                self._target_ledger_initialized = True
        await self._maybe_snapshot()

    async def record_target_outcomes(
        self,
        agent_id: str,
        outcomes: list[dict[str, str]],
    ) -> None:
        """Commit one Recon outcome for every target assigned to a worker."""
        async with self._lock:
            metadata = self.metadata.get(agent_id, {})
            if metadata.get("phase", "recon") != "recon":
                raise ValueError("Target Recon outcomes can only be recorded by Recon workers")
            assigned = set(metadata.get("target_ids", []))
            if not assigned:
                raise ValueError("Recon worker has no assigned target IDs")
            received: dict[str, tuple[str, str]] = {}
            for outcome in outcomes:
                target_id = outcome.get("target_id", "").strip()
                status = outcome.get("status", "").strip()
                summary = outcome.get("summary", "").strip()
                if target_id in received:
                    raise ValueError(f"Duplicate Recon outcome for target {target_id}")
                if status not in {"complete", "blocked"} or not summary:
                    raise ValueError(
                        f"Invalid Recon outcome for target {target_id or '(missing ID)'}"
                    )
                received[target_id] = (status, summary)
            if set(received) != assigned:
                missing = sorted(assigned - set(received))
                unexpected = sorted(set(received) - assigned)
                raise ValueError(
                    f"Recon outcomes must cover exactly assigned targets; missing={missing}, "
                    f"unexpected={unexpected}"
                )
            for target_id, (status, summary) in received.items():
                entry = self.target_ledger[target_id]
                if entry.get("assigned_to") != agent_id:
                    raise ValueError(f"Recon worker does not own target {target_id}")
                entry["status"] = "recon_complete" if status == "complete" else "blocked"
                entry["recon_summary"] = summary
        await self._maybe_snapshot()

    async def phase_for(self, agent_id: str) -> ScanPhase:
        async with self._lock:
            phase = self.metadata.get(agent_id, {}).get("phase", self.scan_phase)
            return phase if phase in {"recon", "testing"} else self.scan_phase

    async def advance_scan_phase(
        self,
        agent_id: str,
        *,
        confirmed_all_targets_reconciled: bool,
        reconciliation_summary: str,
    ) -> dict[str, Any]:
        """Open Testing only after root reconciliation and completed Recon workers."""
        async with self._lock:
            if agent_id not in self.statuses or self.parent_of.get(agent_id) is not None:
                raise ValueError("Only a registered root agent may advance the scan-wide phase")
            if self.scan_phase != "recon":
                raise ValueError(f"Cannot advance from scan phase {self.scan_phase!r}")
            if not confirmed_all_targets_reconciled or not reconciliation_summary.strip():
                raise ValueError("Root must confirm target reconciliation and provide a summary")
            unfinished = [
                aid
                for aid, metadata in self.metadata.items()
                if aid != agent_id
                and metadata.get("phase", "recon") == "recon"
                and self.statuses.get(aid) in {"running", "waiting", "budget_paused"}
            ]
            unreconciled = [
                target_id
                for target_id, entry in self.target_ledger.items()
                if entry.get("status") not in {"recon_complete", "blocked"}
            ]
            if unreconciled:
                raise ValueError(
                    f"Target ledger still has unreconciled targets: {sorted(unreconciled)}"
                )
            if unfinished:
                details = ", ".join(
                    f"{aid}={self.statuses.get(aid, 'unknown')}" for aid in unfinished
                )
                raise ValueError(f"Recon workers are still active: {details}")
            self.scan_phase = "testing"
            self.metadata.setdefault(agent_id, {})["phase"] = "testing"
        await self._maybe_snapshot()
        return {
            "success": True,
            "scan_phase": "testing",
            "reconciliation_summary": reconciliation_summary.strip(),
        }

    @property
    def budget_stopped(self) -> bool:
        return self._budget_stopped

    async def trigger_budget_stop(self) -> None:
        """Signal a scan-wide budget stop and wake every parked agent so it exits."""
        async with self._lock:
            self._budget_stopped = True
            for runtime in self.runtimes.values():
                runtime.wake.set()

    @property
    def reserve_stopped(self) -> bool:
        return self._reserve_stopped

    @property
    def budget_paused(self) -> bool:
        return self._budget_paused

    def set_budget_extender(self, extend: Callable[[], None]) -> None:
        self._extend_budget = extend

    async def pause_for_budget(self, agent_id: str) -> None:
        async with self._lock:
            self._budget_paused = True
        await self.set_status(agent_id, "budget_paused")

    async def resume_from_budget_pause(self, *, exclude: str | None = None) -> None:
        async with self._lock:
            if not self._budget_paused:
                return
            self._budget_paused = False
            paused = [aid for aid, status in self.statuses.items() if status == "budget_paused"]
        if self._extend_budget is not None:
            self._extend_budget()
        for aid in paused:
            await self.set_status(aid, "waiting")
            if aid != exclude:
                await self.send(
                    aid,
                    {
                        "from": "system",
                        "type": "budget_extended",
                        "content": (
                            "[Budget] The user extended the scan budget \u2014 continue your "
                            "current task."
                        ),
                    },
                )

    async def reset_budget_stops(
        self,
        *,
        budget_stopped: bool,
        reserve_stopped: bool,
        budget_paused: bool = False,
    ) -> None:
        async with self._lock:
            self._budget_stopped = budget_stopped
            self._reserve_stopped = reserve_stopped
            if not budget_paused:
                self._budget_paused = False
                for aid, status in self.statuses.items():
                    if status == "budget_paused":
                        self.statuses[aid] = "waiting"
        await self._maybe_snapshot()

    async def claim_reserve_notification(self) -> str | None:
        async with self._lock:
            if self._reserve_stopped:
                return None
            self._reserve_stopped = True
            for runtime in self.runtimes.values():
                runtime.wake.set()
            return next((aid for aid, parent in self.parent_of.items() if parent is None), None)

    async def register(  # noqa: PLR0912 - validation keeps ownership and phase checks atomic.
        self,
        agent_id: str,
        name: str,
        parent_id: str | None,
        *,
        task: str | None = None,
        skills: list[str] | None = None,
        phase: ScanPhase | None = None,
        target_ids: list[str] | None = None,
    ) -> None:
        async with self._lock:
            parent_phase = (
                self.metadata.get(parent_id, {}).get("phase", self.scan_phase)
                if parent_id is not None
                else self.scan_phase
            )
            assigned_phase = phase or parent_phase
            if assigned_phase != self.scan_phase or assigned_phase != parent_phase:
                raise ValueError(
                    f"Cannot register {assigned_phase!r} agent while scan/parent phase is "
                    f"{self.scan_phase!r}/{parent_phase!r}"
                )
            normalized_target_ids = list(dict.fromkeys(target_ids or []))
            if len(normalized_target_ids) != len(target_ids or []):
                raise ValueError("A child task cannot contain duplicate target IDs")
            if parent_id is not None and self.target_ledger:
                if assigned_phase == "recon" and (
                    parent_id not in self.parent_of or self.parent_of[parent_id] is not None
                ):
                    raise ValueError("Recon batches are root-owned; Recon workers cannot delegate")
                if not normalized_target_ids:
                    raise ValueError(
                        "Child tasks must declare target_ids when the scan has a target ledger"
                    )
                unknown = sorted(set(normalized_target_ids) - set(self.target_ledger))
                if unknown:
                    raise ValueError(f"Child task references unknown target IDs: {unknown}")
                if assigned_phase == "testing":
                    blocked = [
                        target_id
                        for target_id in normalized_target_ids
                        if self.target_ledger[target_id].get("status") != "recon_complete"
                    ]
                    if blocked:
                        raise ValueError(
                            "Testing cannot be assigned to targets without completed Recon: "
                            f"{blocked}"
                        )
                if assigned_phase == "recon":
                    for target_id in normalized_target_ids:
                        entry = self.target_ledger[target_id]
                        if entry.get("status") in {"recon_complete", "blocked"}:
                            raise ValueError(
                                f"Target {target_id} already has a terminal Recon outcome"
                            )
                        owner = entry.get("assigned_to")
                        if owner and self.statuses.get(owner) in {
                            "running",
                            "waiting",
                            "budget_paused",
                        }:
                            raise ValueError(
                                f"Target {target_id} is already assigned to active worker {owner}"
                            )
            self.statuses[agent_id] = "running"
            self.parent_of[agent_id] = parent_id
            self.names[agent_id] = name
            self.pending_counts.setdefault(agent_id, 0)
            self.metadata[agent_id] = {
                "task": task or "",
                "skills": list(skills or []),
                "phase": assigned_phase,
                "target_ids": normalized_target_ids,
            }
            if parent_id is not None and self.target_ledger and assigned_phase == "recon":
                for target_id in normalized_target_ids:
                    entry = self.target_ledger[target_id]
                    entry["status"] = "recon_in_progress"
                    entry["assigned_to"] = agent_id
                    entry["attempts"] = int(entry.get("attempts", 0)) + 1
            self.runtimes.setdefault(agent_id, AgentRuntime())
        logger.info("agent.register %s (%s) parent=%s", agent_id, name, parent_id or "-")
        await self._maybe_snapshot()

    async def attach_runtime(
        self,
        agent_id: str,
        *,
        session: Session | None = None,
        task: asyncio.Task[Any] | None = None,
        interrupt_on_message: bool | None = None,
    ) -> None:
        async with self._lock:
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            if session is not None:
                runtime.session = session
            if task is not None:
                runtime.task = task
            if interrupt_on_message is not None:
                runtime.interrupt_on_message = interrupt_on_message

    async def resume_silent_user_wait(self, agent_id: str) -> bool:
        """Undo a user wait only if the agent is still parked on the user."""
        async with self._lock:
            if self.statuses.get(agent_id) != "waiting" or self.wait_kinds.get(agent_id) != "user":
                return False
            self.statuses[agent_id] = "running"
            self.errors.pop(agent_id, None)
            self.wait_kinds.pop(agent_id, None)
            self.runtimes.setdefault(agent_id, AgentRuntime()).user_wake_required = False
            self._parent_notified.discard(agent_id)
        await self._maybe_snapshot()
        return True

    async def mark_running(self, agent_id: str) -> None:
        async with self._lock:
            if agent_id in self.statuses:
                self.statuses[agent_id] = "running"
                self.errors.pop(agent_id, None)
                self.wait_kinds.pop(agent_id, None)
                self.runtimes.setdefault(agent_id, AgentRuntime()).user_wake_required = False
                self._parent_notified.discard(agent_id)
        await self._maybe_snapshot()

    async def park_waiting(self, agent_id: str, *, wait_kind: WaitKind) -> None:
        """Park an agent, recording what it is waiting on so the driver can time it."""
        async with self._lock:
            if agent_id in self.statuses:
                self.wait_kinds[agent_id] = wait_kind
        await self.set_status(agent_id, "waiting")

    async def wait_kind_of(self, agent_id: str) -> WaitKind | None:
        async with self._lock:
            return self.wait_kinds.get(agent_id)

    async def record_recovery(self, agent_id: str) -> int:
        """Count a turn that ended without a lifecycle tool call; return the new total.

        Persisted so a resumed agent cannot earn a fresh nudge budget on every
        auto-resume and loop forever.
        """
        async with self._lock:
            count = self.recovery_counts.get(agent_id, 0) + 1
            self.recovery_counts[agent_id] = count
        await self._maybe_snapshot()
        return count

    async def reset_recovery(self, agent_id: str) -> None:
        """Clear the nudge budget after real progress (new message or a lifecycle tool)."""
        async with self._lock:
            if self.recovery_counts.pop(agent_id, None) is None:
                return
        await self._maybe_snapshot()

    async def record_idle_resume(self, agent_id: str) -> int:
        """Count an auto-resume that no message triggered; return the new total.

        An agent that parks again after every auto-resume would otherwise burn a
        model turn per timeout for the rest of the scan.
        """
        async with self._lock:
            count = self.idle_resume_counts.get(agent_id, 0) + 1
            self.idle_resume_counts[agent_id] = count
        await self._maybe_snapshot()
        return count

    async def reset_idle_resumes(self, agent_id: str) -> None:
        async with self._lock:
            if self.idle_resume_counts.pop(agent_id, None) is None:
                return
        await self._maybe_snapshot()

    async def set_status(
        self, agent_id: str, status: Status | str, *, error: str | None = None
    ) -> None:
        async with self._lock:
            if agent_id not in self.statuses:
                return
            self.statuses[agent_id] = status  # type: ignore[assignment]
            if error is not None:
                self.errors[agent_id] = error
            elif status == "running":
                self.errors.pop(agent_id, None)
            if status == "running":
                # Running again means a fresh stint that owes its parent its own notice.
                self._parent_notified.discard(agent_id)
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            runtime.user_wake_required = status in {"failed", "crashed"}
            runtime.wake.set()
        logger.info("agent.status %s=%s", agent_id, status)
        await self._maybe_snapshot()

    async def claim_parent_notice(self, agent_id: str) -> bool:
        """Reserve the one notice a child owes its parent when it stops running.

        A completion report and a terminal notice carry the same information, so
        whichever comes first claims the slot and the other is skipped.
        """
        async with self._lock:
            if agent_id in self._parent_notified:
                return False
            self._parent_notified.add(agent_id)
            return True

    async def send(
        self, target_agent_id: str, message: dict[str, Any], *, interrupt: bool = True
    ) -> bool:
        """Queue a user/peer message in the target's mailbox and wake it."""
        from_user = message.get("from") == "user"
        if from_user and self._budget_paused:
            await self.resume_from_budget_pause(exclude=target_agent_id)
        async with self._lock:
            if target_agent_id not in self.statuses:
                logger.debug("agent.send dropped unknown target=%s", target_agent_id)
                return False
            runtime = self.runtimes.setdefault(target_agent_id, AgentRuntime())
            runtime.mailbox.append(dict(message))
            self.pending_counts[target_agent_id] = self.pending_counts.get(target_agent_id, 0) + 1
            if from_user:
                runtime.user_wake_required = False
            runtime.wake.set()
            stream = runtime.stream
            interrupt_on_message = runtime.interrupt_on_message
        if stream is not None and interrupt and interrupt_on_message:
            stream.cancel(mode="immediate")
        await self._maybe_snapshot()
        return True

    async def wait_for_message(self, agent_id: str, *, timeout: float | None = None) -> bool:
        """Wait until a message is ready for ``agent_id``; False on ``timeout``."""
        while True:
            async with self._lock:
                runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
                reserve_exit = self._reserve_stopped and self.parent_of.get(agent_id) is not None
                pending_ready = (
                    self.pending_counts.get(agent_id, 0) > 0 and not runtime.user_wake_required
                )
                if self._budget_stopped or reserve_exit or pending_ready:
                    return True
                wake = runtime.wake
                wake.clear()
            if timeout is None:
                await wake.wait()
            else:
                try:
                    await asyncio.wait_for(wake.wait(), timeout)
                except TimeoutError:
                    return False

    async def consume_pending(
        self,
        agent_id: str,
        *,
        include_items: bool = False,
    ) -> tuple[int, list[Any]]:
        """Drain the agent's mailbox into its own SDK session."""
        async with self._lock:
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            queued = list(runtime.mailbox)
            runtime.mailbox.clear()
            count = max(self.pending_counts.get(agent_id, 0), len(queued))
            self.pending_counts[agent_id] = 0
            session = runtime.session
        if count <= 0:
            return 0, []
        items = [self._message_to_session_item(m) for m in queued]
        if items:
            if session is None:
                logger.warning(
                    "agent %s has no SDK session attached; %d queued messages were not persisted",
                    agent_id,
                    len(items),
                )
            else:
                try:
                    async with session_write_lock(session):
                        await session.add_items(items)
                except Exception:
                    logger.exception(
                        "failed to append %d queued messages to the session of %s",
                        len(items),
                        agent_id,
                    )
        await self._maybe_snapshot()
        if not include_items:
            return count, []
        return count, items

    async def request_stop(self, agent_id: str) -> None:
        async with self._lock:
            if agent_id not in self.statuses:
                return
            self.statuses[agent_id] = "stopped"
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            runtime.wake.set()
            stream = runtime.stream
        if stream is not None:
            stream.cancel(mode="after_turn")
        await self._maybe_snapshot()

    async def cancel_descendants(self, agent_id: str) -> None:
        tasks = []
        async with self._lock:
            for aid in reversed(self._subtree_order_locked(agent_id)):
                task = self.runtimes.get(aid, AgentRuntime()).task
                if task is not None and not task.done():
                    tasks.append(task)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def cancel_descendants_graceful(self, agent_id: str) -> list[str]:
        """Stop a subtree leaves-first and report which agents were stopped."""
        async with self._lock:
            order = self._subtree_order_locked(agent_id)
        stopped = list(reversed(order))
        for aid in stopped:
            await self.request_stop(aid)
        await self._maybe_snapshot()
        return stopped

    async def attach_stream(
        self,
        agent_id: str,
        stream: Any,
    ) -> None:
        async with self._lock:
            self.runtimes.setdefault(agent_id, AgentRuntime()).stream = stream

    async def detach_stream(
        self,
        agent_id: str,
        stream: Any,
    ) -> None:
        async with self._lock:
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            if runtime.stream is stream:
                runtime.stream = None

    async def active_agents_except(self, agent_id: str) -> list[dict[str, Any]]:
        async with self._lock:
            return [
                {
                    "agent_id": aid,
                    "name": self.names.get(aid, aid),
                    "status": status,
                    "parent_id": self.parent_of.get(aid),
                }
                for aid, status in self.statuses.items()
                if aid != agent_id and status in {"running", "waiting"}
            ]

    async def graph_snapshot(
        self,
    ) -> tuple[dict[str, str | None], dict[str, Status], dict[str, str], dict[str, str]]:
        async with self._lock:
            return (
                dict(self.parent_of),
                dict(self.statuses),
                dict(self.names),
                dict(self.errors),
            )

    def _message_to_session_item(self, message: dict[str, Any]) -> TResponseInputItem:
        sender = str(message.get("from", "unknown"))
        content = str(message.get("content", ""))
        if sender == "user":
            return cast("TResponseInputItem", {"role": "user", "content": content})
        sender_name = self.names.get(sender, sender)
        msg_type = message.get("type", "information")
        priority = message.get("priority", "normal")
        return cast(
            "TResponseInputItem",
            {
                "role": "user",
                "content": (
                    f"[Message from {sender_name} ({sender}) | type={msg_type} "
                    f"| priority={priority}]\n{content}"
                ),
            },
        )

    def _subtree_order_locked(self, agent_id: str) -> list[str]:
        queue = [agent_id]
        order: list[str] = []
        while queue:
            aid = queue.pop()
            order.append(aid)
            queue.extend(child for child, parent in self.parent_of.items() if parent == aid)
        return order

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return {
                "statuses": dict(self.statuses),
                "scan_phase": self.scan_phase,
                "target_ledger": {tid: dict(entry) for tid, entry in self.target_ledger.items()},
                "target_ledger_initialized": self._target_ledger_initialized,
                "parent_of": dict(self.parent_of),
                "names": dict(self.names),
                "metadata": {aid: dict(md) for aid, md in self.metadata.items()},
                "pending_counts": dict(self.pending_counts),
                "recovery_counts": dict(self.recovery_counts),
                "idle_resume_counts": dict(self.idle_resume_counts),
                "wait_kinds": dict(self.wait_kinds),
                "mailboxes": {
                    aid: [dict(m) for m in runtime.mailbox]
                    for aid, runtime in self.runtimes.items()
                    if runtime.mailbox
                },
                "errors": dict(self.errors),
                "budget_stopped": self._budget_stopped,
                "reserve_stopped": self._reserve_stopped,
                "budget_paused": self._budget_paused,
            }

    async def restore(self, snap: dict[str, Any]) -> None:
        async with self._lock:
            self.statuses = dict(snap.get("statuses", {}))
            self.scan_phase = "testing" if snap.get("scan_phase") == "testing" else "recon"
            raw_ledger = snap.get("target_ledger", {})
            self.target_ledger = (
                {
                    tid: dict(entry)
                    for tid, entry in raw_ledger.items()
                    if isinstance(tid, str) and isinstance(entry, dict)
                }
                if isinstance(raw_ledger, dict)
                else {}
            )
            self._target_ledger_initialized = bool(
                snap.get("target_ledger_initialized", "target_ledger" in snap)
            )
            self.parent_of = dict(snap.get("parent_of", {}))
            self.names = dict(snap.get("names", {}))
            self.metadata = {aid: dict(md) for aid, md in snap.get("metadata", {}).items()}
            for aid in self.statuses:
                if self.metadata.get(aid, {}).get("phase") not in {"recon", "testing"}:
                    parent = self.parent_of.get(aid)
                    parent_metadata = self.metadata.get(parent, {}) if parent is not None else {}
                    inherited = parent_metadata.get("phase", self.scan_phase)
                    self.metadata.setdefault(aid, {})["phase"] = inherited
            self.pending_counts = dict(snap.get("pending_counts", {}))
            self.errors = dict(snap.get("errors", {}))
            self.recovery_counts = dict(snap.get("recovery_counts", {}))
            self.idle_resume_counts = dict(snap.get("idle_resume_counts", {}))
            self.wait_kinds = dict(snap.get("wait_kinds", {}))
            mailboxes = snap.get("mailboxes", {})
            if isinstance(mailboxes, dict):
                for aid, msgs in mailboxes.items():
                    if isinstance(msgs, list):
                        runtime = self.runtimes.setdefault(aid, AgentRuntime())
                        runtime.mailbox = [dict(m) for m in msgs if isinstance(m, dict)]
            self._budget_stopped = bool(snap.get("budget_stopped", False))
            self._reserve_stopped = bool(snap.get("reserve_stopped", False))
            self._budget_paused = bool(snap.get("budget_paused", False))
            for aid in self.statuses:
                self.runtimes.setdefault(aid, AgentRuntime())

    async def _maybe_snapshot(self) -> None:
        path = self._snapshot_path
        if path is None:
            return
        try:
            data = await self.snapshot()
            payload = json.dumps(data, ensure_ascii=False, default=str)
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(path.parent),
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp:
                tmp.write(payload)
                tmp_path = Path(tmp.name)
            tmp_path.replace(path)
        except Exception:
            logger.exception("coordinator snapshot to %s failed", path)


def coordinator_from_context(ctx: dict[str, Any]) -> AgentCoordinator | None:
    coordinator = ctx.get("coordinator")
    return coordinator if isinstance(coordinator, AgentCoordinator) else None
