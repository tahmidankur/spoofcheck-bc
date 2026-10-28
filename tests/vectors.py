import json
from pathlib import Path
from typing import Any

import pytest

VECTOR_DIR = Path(__file__).parent / "vectors"


def vector_cases(filename: str) -> list[Any]:
    cases = json.loads((VECTOR_DIR / filename).read_text())["cases"]
    return [pytest.param(case, id=case["name"]) for case in cases]
