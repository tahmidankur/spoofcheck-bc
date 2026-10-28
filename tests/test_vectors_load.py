import json
from pathlib import Path

import pytest

VECTOR_DIR = Path(__file__).parent / "vectors"


@pytest.mark.parametrize("path", sorted(VECTOR_DIR.glob("*.json")), ids=lambda p: p.name)
def test_every_vector_has_a_name_and_an_expect_block(path: Path) -> None:
    cases = json.loads(path.read_text())["cases"]
    assert cases
    for case in cases:
        assert case["name"]
        assert isinstance(case["expect"], dict)
