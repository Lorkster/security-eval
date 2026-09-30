from __future__ import annotations

from pathlib import Path

import pytest

from security_eval.budget import PriceTable
from security_eval.manifest import Target, load_target

ROOT = Path(__file__).resolve().parents[1]
TOY = ROOT / "benchmarks" / "toy-webapp" / "manifest.json"


@pytest.fixture
def toy() -> Target:
    return load_target(TOY)


@pytest.fixture
def prices() -> PriceTable:
    return PriceTable.load(ROOT / "configs" / "prices.json")
