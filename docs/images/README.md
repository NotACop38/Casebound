# Demo images

This directory holds the README's visual assets.

## report.png

`docs/images/report.png` is the README hero: a screenshot of the generated,
self-contained HTML report (`out/report.html`), framed from the masthead through
the rejected-claims audit so the whole verification story (the verified narrative
with per-claim citations, beside the dropped-and-logged claims) reads in one view.
See PRD Section 14 and Phase 7.

It is committed and kept in sync with the report layout. The report is
self-contained, so the screenshot renders with no network.

To regenerate it after the report layout changes:

```bash
# 1. Produce the report.
make demo                      # writes out/report.html

# 2a. Reproduce the committed framing (top through the rejected-claims audit)
#     with a headless browser via Playwright:
python - <<'PY'
from pathlib import Path
from playwright.sync_api import sync_playwright

report = Path("out/report.html").resolve()
with sync_playwright() as p:
    page = p.chromium.launch().new_page(
        viewport={"width": 1200, "height": 1600}, device_scale_factor=2
    )
    page.goto(report.as_uri())
    page.wait_for_load_state("networkidle")
    cut = page.evaluate(
        "() => { const h = [...document.querySelectorAll('section > h2')]"
        ".find(e => e.textContent.trim().startsWith('Deterministic timeline'));"
        " return Math.round(h.closest('section').getBoundingClientRect().top"
        " + window.scrollY) - 18; }"
    )
    page.set_viewport_size({"width": 1200, "height": cut})
    page.screenshot(path="docs/images/report.png")
PY

# 2b. Or a quick fixed-window capture with any headless renderer:
chromium --headless --screenshot=docs/images/report.png \
  --window-size=1200,2000 --hide-scrollbars out/report.html
```

Playwright is a screenshot-only developer tool, not a project dependency. Install
it into your environment (`pip install playwright && playwright install chromium`)
only when you need to regenerate this image.
