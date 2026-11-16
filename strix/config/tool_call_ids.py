"""Keep tool-call ids unique within a conversation.

Some providers return per-turn tool-call ids (``exec_command:0``,
``exec_command:1``, ...) whose counter restarts on every turn. Once the same
id appears twice in one conversation, the request payload has two assistant
tool calls sharing an id and strict providers reject the whole turn, which
permanently kills the agent because the malformed history is replayed on
every retry. Rewriting duplicates to fresh unique ids keeps the history
valid for any provider.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any
from uuid import uuid4

from openai.types.responses import ResponseFunctionToolCall


def new_call_id() -> str:
    return f"call_{uuid4().hex}"


def collect_call_ids(items: list[Any]) -> set[str]:
    used: set[str] = set()
    for item in items:
        if isinstance(item, dict):
            call_id = item.get("call_id")
            if isinstance(call_id, str):
                used.add(call_id)
        elif isinstance(item, ResponseFunctionToolCall):
            used.add(item.call_id)
    return used


def _item_field(item: Any, field: str) -> Any:
    if isinstance(item, dict):
        return item.get(field)
    return getattr(item, field, None)


def _replace_call_id(item: Any, call_id: str) -> Any:
    if isinstance(item, dict):
        return {**item, "call_id": call_id}
    model_copy = getattr(item, "model_copy", None)
    if callable(model_copy):
        return model_copy(update={"call_id": call_id})
    return item


def dedupe_history_call_ids(items: list[Any]) -> tuple[list[Any], bool]:
    """Repair duplicate and orphan tool items in a conversation history.

    Session items can be dictionaries or typed OpenAI response objects. Both
    representations must participate in pairing: otherwise a typed assistant
    call followed by a dictionary tool result is misclassified as an orphan,
    and Chat Completions rejects the resulting role=tool message.
    """
    used: set[str] = set()
    pending: dict[str, deque[str]] = defaultdict(deque)
    rebuilt: list[Any] = []
    changed = False

    for original_item in items:
        kind = _item_field(original_item, "type")
        call_id = _item_field(original_item, "call_id")
        if not isinstance(call_id, str) or kind not in {
            "function_call",
            "function_call_output",
        }:
            rebuilt.append(original_item)
            continue

        item = original_item
        if kind == "function_call":
            effective = call_id
            if call_id in used:
                effective = new_call_id()
                item = _replace_call_id(item, effective)
                changed = True
            used.add(effective)
            pending[call_id].append(effective)
        else:
            queue = pending.get(call_id)
            if not queue:
                # A cancelled/partially persisted turn can leave a tool result
                # without its assistant call. Chat Completions serializes this
                # as a role=tool message, which strict providers reject.
                changed = True
                continue
            effective = queue.popleft()
            if effective != call_id:
                item = _replace_call_id(item, effective)
                changed = True
        rebuilt.append(item)

    return rebuilt, changed


def dedupe_input(model_input: str | list[Any]) -> str | list[Any]:
    if isinstance(model_input, str):
        return model_input
    rebuilt, changed = dedupe_history_call_ids(model_input)
    return rebuilt if changed else model_input


class TurnCallIdRewriter:
    """Rewrite a single turn's tool-call ids that collide with the history.

    A turn's items surface several times (streamed item events, then the
    completed response), so the same original id must always map to the same
    replacement within the turn.
    """

    def __init__(self, model_input: str | list[Any]) -> None:
        self._used = set() if isinstance(model_input, str) else collect_call_ids(model_input)
        self._remap: dict[str, str] = {}
        self._settled: set[str] = set()

    def rewrite_item(self, item: Any) -> Any:
        if not isinstance(item, ResponseFunctionToolCall):
            return item
        original = item.call_id
        if original in self._settled:
            return item
        replacement = self._remap.get(original)
        if replacement is None:
            if original not in self._used:
                self._used.add(original)
                self._settled.add(original)
                return item
            replacement = new_call_id()
            self._remap[original] = replacement
            self._used.add(replacement)
            self._settled.add(replacement)
        return item.model_copy(update={"call_id": replacement})

    def rewrite_items(self, items: list[Any]) -> list[Any]:
        return [self.rewrite_item(item) for item in items]
