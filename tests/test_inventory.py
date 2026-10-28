from pathlib import Path

from spoofcheck.inventory import COLUMNS, INVENTORY_PATH, read_inventory

HEADER = ",".join(COLUMNS)


def write_csv(tmp_path: Path, *rows: str) -> Path:
    path = tmp_path / "inventory.csv"
    path.write_text("\n".join([HEADER, *rows]) + "\n")
    return path


def test_committed_inventory_has_no_problems() -> None:
    bodies, problems = read_inventory(INVENTORY_PATH)
    assert problems == []
    assert len(bodies) >= 20


def test_valid_row_is_loaded(tmp_path: Path) -> None:
    path = write_csv(
        tmp_path, "Village of Riverbend,municipality,Thompson-Nicola,Riverbend.example,,no,"
    )
    bodies, problems = read_inventory(path)
    assert problems == []
    assert bodies[0].domain == "riverbend.example"
    assert not bodies[0].verified


def test_unknown_sector_and_bad_hostname_are_reported(tmp_path: Path) -> None:
    path = write_csv(tmp_path, "Riverbend Library,library,Thompson-Nicola,not a domain,,no,")
    bodies, problems = read_inventory(path)
    assert bodies == []
    assert len(problems) == 2


def test_duplicate_domain_is_reported(tmp_path: Path) -> None:
    row = "Village of Riverbend,municipality,Thompson-Nicola,riverbend.example,,no,"
    _, problems = read_inventory(write_csv(tmp_path, row, row))
    assert problems == ["line 3: riverbend.example already listed on line 2"]


def test_verified_row_without_source_is_reported(tmp_path: Path) -> None:
    row = "Village of Riverbend,municipality,Thompson-Nicola,riverbend.example,,yes,"
    _, problems = read_inventory(write_csv(tmp_path, row))
    assert problems == ["line 2: verified rows need an https source_url"]
