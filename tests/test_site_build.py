from pathlib import Path

from spoofcheck.site.build import build_site, sector_bars, trend_svg


def snapshot(week: int, enforced: int, total: int = 20) -> dict[str, object]:
    return {
        "week": f"2026-W{week:02d}",
        "total": total,
        "levels": {"3": enforced, "2": total - enforced, "1": 0, "0": 0},
    }


def test_small_segments_carry_no_count_label() -> None:
    snap = {"sectors": {"municipality": {"3": 1, "2": 19, "1": 0, "0": 0}}}
    (bar,) = sector_bars(snap)
    assert [s.labelled for s in bar.segments] == [False, True]
    assert bar.label == "Municipalities"


def test_trend_needs_two_weeks() -> None:
    assert trend_svg([snapshot(44, 4)]) is None


def test_trend_labels_first_and_last_week_and_end_value() -> None:
    svg = trend_svg([snapshot(43, 4), snapshot(44, 5)])
    assert svg is not None
    assert "W43" in svg and "W44" in svg and ">25%</text>" in svg


def test_build_writes_every_page_and_the_checker_assets(tmp_path: Path) -> None:
    out = tmp_path / "site"
    build_site(out)
    for page in ("index.html", "method/index.html", "fix/index.html", "about/index.html"):
        html = (out / page).read_text()
        assert "Not affiliated with the Government of British Columbia" in html
    for asset in ("site.css", "check.js", "page.js", "findings.json", "orgs.json"):
        assert (out / "assets" / asset).exists()
    assert not (out / "assets" / "check.test.js").exists()
