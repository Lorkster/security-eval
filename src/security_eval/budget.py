"""What a run costs, what a matrix will cost, and refusing what cannot be afforded.

Prices live in ``configs/prices.json`` rather than in code, with the date they
were copied and where from. A price table in code goes stale silently; one in a
dated file at least says how old it is.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_PRICES = Path(__file__).resolve().parents[2] / "configs" / "prices.json"


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
            self.cache_read_tokens + other.cache_read_tokens,
            self.cache_write_tokens + other.cache_write_tokens,
        )


@dataclass(frozen=True)
class Price:
    input: float                 # $ per 1M tokens
    output: float
    cache_read: float | None = None
    cache_write: float | None = None


class PriceTable:
    def __init__(self, data: dict[str, Any]) -> None:
        self.as_of = str(data.get("as_of", "unknown"))
        self.source = str(data.get("source", ""))
        self.batch_discount = float(data.get("batch_discount", 0.0))
        self.cache_write_multiplier = float(data.get("cache_write_multiplier", 1.25))
        self.models = {
            name: Price(**{k: float(v) for k, v in p.items() if k in Price.__dataclass_fields__})
            for name, p in data.get("models", {}).items()
        }

    @classmethod
    def load(cls, path: Path | str = DEFAULT_PRICES) -> PriceTable:
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def price(self, route: str) -> Price:
        """The price for a route like ``anthropic:claude-sonnet-5-5`` or a bare model id.

        Local providers cost nothing per token. Anything else unknown is an
        error, not a zero: a model missing from the table would otherwise be
        free in every projection, which is exactly the wrong failure.
        """
        provider, _, model = route.partition(":") if ":" in route else ("", "", route)
        if provider in ("ollama", "fake"):
            return Price(0.0, 0.0, 0.0, 0.0)
        # A route's model id may carry a vendor prefix, e.g. OpenRouter's
        # `anthropic/claude-sonnet-5-5`.
        for key in (model, model.rsplit("/", 1)[-1]):
            if key in self.models:
                return self.models[key]
        raise KeyError(f"no price for {route!r} in the price table (as of {self.as_of})")

    def cost(self, route: str, usage: Usage, *, batch: bool = False) -> float:
        p = self.price(route)
        cache_read = p.cache_read if p.cache_read is not None else p.input * 0.1
        cache_write = (p.cache_write if p.cache_write is not None
                       else p.input * self.cache_write_multiplier)
        dollars = (
            usage.input_tokens * p.input
            + usage.output_tokens * p.output
            + usage.cache_read_tokens * cache_read
            + usage.cache_write_tokens * cache_write
        ) / 1_000_000
        return dollars * (1 - self.batch_discount) if batch else dollars


class BudgetExceeded(RuntimeError):
    pass


class BudgetGuard:
    """Refuse to start work the remaining budget cannot cover.

    Checked *before* a cell starts, against its projected cost, because a run
    that has started has already been paid for. The projection is only as good
    as the per-run token figures behind it: assumptions until the pilot, then
    measurements.
    """

    def __init__(self, cap_usd: float, spent_usd: float = 0.0) -> None:
        if cap_usd <= 0:
            raise ValueError("a budget cap must be positive")
        self.cap = cap_usd
        self.spent = spent_usd

    @property
    def remaining(self) -> float:
        return self.cap - self.spent

    def check(self, projected_usd: float, what: str = "this run") -> None:
        if self.spent + projected_usd > self.cap:
            raise BudgetExceeded(
                f"{what} is projected at ${projected_usd:.2f}; ${self.remaining:.2f} "
                f"of ${self.cap:.2f} remains"
            )

    def record(self, actual_usd: float) -> None:
        self.spent += actual_usd
