"""Screenshot and accessibility check for the built site.

Build and serve the site first:
    uv run spoofcheck build-site --out site/
    python -m http.server -d site 8000
Then run:
    uv run python scripts/check_site.py

Screenshots go to screenshots/ (git-ignored). Problems are printed; no output
after "checked" means none were found.
"""

from pathlib import Path

from axe_playwright_python.sync_playwright import Axe
from playwright.sync_api import Page, sync_playwright

BASE = "http://localhost:8000"
PAGES = ["/?domain=canada.ca", "/method/", "/fix/", "/about/", "/404.html"]
SIZES = [(390, 844), (1280, 900)]
OUT = Path("screenshots")


def open_page(page: Page, path: str) -> None:
    page.goto(BASE + path)
    if "domain=" in path:
        page.wait_for_selector(".postmark", timeout=15_000)


def file_name(path: str, width: int, scheme: str) -> str:
    name = path.strip("/").split("?")[0].replace("/", "-").removesuffix(".html") or "home"
    return f"{name}-{width}-{scheme}.png"


def main() -> None:
    OUT.mkdir(exist_ok=True)
    axe = Axe()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for scheme in ("light", "dark"):
            for width, height in SIZES:
                page = browser.new_page(
                    viewport={"width": width, "height": height},
                    color_scheme=scheme,
                    reduced_motion="reduce",
                )
                for path in PAGES:
                    open_page(page, path)
                    page.screenshot(path=OUT / file_name(path, width, scheme), full_page=True)
                    if width == 1280 and scheme == "light":
                        violations = axe.run(page).response["violations"]
                        for v in violations:
                            if v["impact"] in ("serious", "critical"):
                                print(f"axe {path}: {v['id']} ({v['impact']})")
                page.close()

        # No sideways scrolling on small phones
        for width in (360, 390):
            page = browser.new_page(viewport={"width": width, "height": 800})
            for path in PAGES:
                open_page(page, path)
                scroll_width = page.evaluate("document.documentElement.scrollWidth")
                if scroll_width != width:
                    print(f"{path} scrolls sideways at {width}px ({scroll_width}px wide)")
            page.close()
        browser.close()
    print(f"checked {len(PAGES)} pages, screenshots in {OUT}/")


if __name__ == "__main__":
    main()
