"""The Message Batches API: half price for requests that do not need an answer now.

Only Anthropic's own API offers it -- not Amazon Bedrock, Google Vertex, Microsoft
Foundry, OpenRouter or a local Ollama. A cell whose model is on any other route
runs exactly as it would without batching, and the preflight check says so. The
harness condition never batches: a supervised run is a conversation, and each
turn depends on the last.

Three things make batching safe for a study on a budget:

* **The request is the one the harness would send.** A batched baseline cell
  must be comparable with an unbatched one, so `harness_body` builds the body
  the way the harness's Anthropic provider does -- the same system text with the
  same schema instruction, the same parameters from your config -- and a test
  holds the two equal.
* **A submitted batch is never paid for twice.** Its id and the cells in it are
  written to ``batches.json`` the moment it is accepted. A crash, a closed
  terminal or a plain re-run collects the results; it does not resubmit.
* **The budget counts what is in flight.** Cells waiting in a batch are spent as
  far as the budget guard is concerned, at their projected batch price.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

#: Routes whose provider offers the Message Batches API.
BATCH_PROVIDERS = frozenset({"anthropic"})


def supports_batch(route: str) -> bool:
    return route.split(":", 1)[0] in BATCH_PROVIDERS


def custom_id(cell_id: str, index: int) -> str:
    """A batch-legal id (``[a-zA-Z0-9_-]{1,64}``) for one request of one cell."""
    digest = hashlib.sha256(cell_id.encode("utf-8")).hexdigest()[:24]
    return f"c{digest}-{index}"


@dataclass
class BatchItem:
    custom_id: str
    params: dict[str, Any]


@dataclass
class BatchOutcome:
    custom_id: str
    kind: str                        # succeeded | errored | canceled | expired
    message: dict[str, Any] | None = None
    error: str = ""


class BatchClient(Protocol):
    def submit(self, items: list[BatchItem]) -> str: ...

    def status(self, batch_id: str) -> str: ...

    def results(self, batch_id: str) -> Iterator[BatchOutcome]: ...


class AnthropicBatchClient:
    """The official SDK's batches resource, with the credentials the harness would use."""

    def __init__(self, workdir: Path | None = None) -> None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise RuntimeError("batching needs the Anthropic SDK: "
                               "pip install -e \".[batch]\"") from exc
        api_key, base_url = _anthropic_credentials(workdir)
        kwargs: dict[str, Any] = {}
        if api_key:
            kwargs["api_key"] = api_key
        if base_url:
            kwargs["base_url"] = base_url
        self._client = anthropic.Anthropic(**kwargs)

    def submit(self, items: list[BatchItem]) -> str:
        batch = self._client.messages.batches.create(
            requests=[{"custom_id": i.custom_id, "params": i.params}  # type: ignore[typeddict-item]
                      for i in items]
        )
        return str(batch.id)

    def status(self, batch_id: str) -> str:
        return str(self._client.messages.batches.retrieve(batch_id).processing_status)

    def results(self, batch_id: str) -> Iterator[BatchOutcome]:
        for entry in self._client.messages.batches.results(batch_id):
            result = entry.result
            if result.type == "succeeded":
                yield BatchOutcome(entry.custom_id, "succeeded",
                                   message=result.message.model_dump(mode="json"))
            elif result.type == "errored":
                error = getattr(result, "error", None)
                yield BatchOutcome(entry.custom_id, "errored", error=str(error)[:300])
            else:
                yield BatchOutcome(entry.custom_id, str(result.type))


def _anthropic_credentials(workdir: Path | None) -> tuple[str, str]:
    """The key and endpoint the harness's `anthropic` provider is configured with."""
    from supervisor_harness.config import load_config

    cfg = load_config(workdir or Path.cwd()).providers.get("anthropic")
    if cfg is None:
        return "", ""
    return cfg.resolved_key(), cfg.base_url


def harness_body(*, route: str, system: str, user: str, json_schema: dict[str, Any] | None,
                 max_tokens: int, extra: dict[str, Any], workdir: Path | None = None,
                 cache_system: bool = False) -> dict[str, Any]:
    """The Messages API body the harness's Anthropic provider would send for this request.

    Built from the same pieces in the same order: route parameters from your
    config lifted the way the router lifts them, the schema instruction appended
    to the system text, no sampling parameter unless one is set. The only
    permitted difference is ``cache_system``, which marks the system text as a
    cache breakpoint -- a cost saving that changes nothing the model reads.
    """
    from supervisor_harness.config import load_config
    from supervisor_harness.providers.base import DEFAULT_MAX_TOKENS, schema_instruction

    config = load_config(workdir or Path.cwd())
    config.routing = {"default": route}
    binding = config.binding_for("analysis")
    params = dict(binding.params)
    temperature = params.pop("temperature", None)
    max_tokens = int(params.pop("max_tokens", max_tokens))
    params.pop("timeout", None)
    merged_extra = {**params, **extra}

    text = system
    if json_schema:
        text = f"{text}\n\n{schema_instruction(json_schema)}".strip()
    body: dict[str, Any] = {
        "model": binding.model,
        "max_tokens": max_tokens or DEFAULT_MAX_TOKENS,
        "messages": [{"role": "user", "content": user if user.strip() else "Proceed."}],
    }
    if temperature is not None:
        body["temperature"] = float(temperature)
    if text:
        body["system"] = (
            [{"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}]
            if cache_system else text
        )
    body.update(merged_extra)
    return body


def message_text(message: dict[str, Any]) -> str:
    return "".join(b.get("text", "") for b in message.get("content") or []
                   if b.get("type") == "text")


@dataclass
class Reply:
    """One batched request's answer, read the way a live call's is read."""

    text: str = ""
    finish: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    refusal: str | None = None       # the category ("" if none given); None if not refused
    error: str = ""                  # set when the request itself did not succeed


def read_outcome(outcome: BatchOutcome) -> Reply:
    if outcome.kind != "succeeded" or outcome.message is None:
        return Reply(error=f"{outcome.kind}: {outcome.error}".strip(": "))
    message = outcome.message
    usage = message.get("usage") or {}
    reply = Reply(
        text=message_text(message),
        finish=str(message.get("stop_reason") or ""),
        input_tokens=int(usage.get("input_tokens") or 0),
        output_tokens=int(usage.get("output_tokens") or 0),
        cache_read_tokens=int(usage.get("cache_read_input_tokens") or 0),
        cache_write_tokens=int(usage.get("cache_creation_input_tokens") or 0),
    )
    if reply.finish == "refusal":
        details = message.get("stop_details") or {}
        reply.refusal = str(details.get("category") or "")
    return reply


# -- the record of what is in flight ------------------------------------------------


@dataclass
class PendingBatch:
    batch_id: str
    submitted: str
    items: dict[str, dict[str, Any]] = field(default_factory=dict)   # custom_id -> {cell, index}
    cells: dict[str, dict[str, Any]] = field(default_factory=dict)   # cell -> {projected, n}
    collected: bool = False


class BatchStore:
    """``batches.json`` beside the ledger: every batch submitted, and whether it was collected."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.batches: dict[str, PendingBatch] = {}
        if path.is_file():
            for batch_id, raw in json.loads(path.read_text(encoding="utf-8")).items():
                self.batches[batch_id] = PendingBatch(batch_id=batch_id, **raw)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {b.batch_id: {"submitted": b.submitted, "items": b.items, "cells": b.cells,
                             "collected": b.collected} for b in self.batches.values()}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def record(self, batch_id: str, items: dict[str, dict[str, Any]],
               cells: dict[str, dict[str, Any]]) -> None:
        self.batches[batch_id] = PendingBatch(
            batch_id, datetime.now(UTC).isoformat(timespec="seconds"), items, cells)
        self.save()

    def pending(self) -> list[PendingBatch]:
        return [b for b in self.batches.values() if not b.collected]

    def pending_cells(self) -> dict[str, float]:
        """Cell id -> projected cost, for every cell waiting in an uncollected batch."""
        return {cell: float(info.get("projected", 0.0))
                for b in self.pending() for cell, info in b.cells.items()}

    def mark_collected(self, batch_id: str) -> None:
        self.batches[batch_id].collected = True
        self.save()
