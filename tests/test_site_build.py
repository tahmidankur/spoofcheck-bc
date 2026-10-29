from pathlib import Path

from spoofcheck.site.build import build_site, sector_bars, trend_chart


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
    assert trend_chart([snapshot(44, 4)]) is None


def test_trend_labels_first_and_last_week_and_end_value() -> None:
    chart = trend_chart([snapshot(43, 4), snapshot(44, 5)])
    assert chart is not None
    assert (chart.first_week, chart.last_week, chart.end_label) == ("W43", "W44", "25%")
    assert [label for _, label in chart.gridlines] == ["20%", "25%", "30%"]


def test_build_writes_every_page_and_the_checker_assets(tmp_path: Path) -> None:
    out = tmp_path / "site"
    build_site(out)
    for page in ("index.html", "method/index.html", "fix/index.html", "about/index.html"):
        html = (out / page).read_text()
        assert "Not affiliated with the Government of British Columbia" in html
    for asset in ("site.css", "check.js", "page.js", "findings.json", "orgs.json"):
        assert (out / "assets" / asset).exists()
    assert not (out / "assets" / "check.test.js").exists()
