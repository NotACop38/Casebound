# Images

## report.png

The README's hero: the HTML report `casebound demo` writes for the bundled
synthetic scenario, framed from the masthead through the rejected-claims audit, so
the whole verification story reads in one image: the guarantee, the verified
narrative grouped by episode with every sentence linked to its evidence, one claim
accepted only after revision, and the rejected and dropped drafts.

The report is self-contained, so it renders with no network. To regenerate the
image after the report layout changes (Playwright and Pillow are screenshot-only
tools, not project dependencies):

```bash
casebound demo -o out
pip install playwright pillow && playwright install chromium

python - <<'PY'
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

report = Path("out/report.html").resolve()
with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1200, "height": 1600}, device_scale_factor=1.5)
    page.goto(report.as_uri())
    # Cut just above the ATT&CK matrix, which follows the rejected-claims audit.
    cut = page.evaluate(
        "() => Math.round(document.getElementById('attack').getBoundingClientRect().top"
        " + window.scrollY) - 18"
    )
    page.set_viewport_size({"width": 1200, "height": cut})
    page.screenshot(path="docs/images/report.png")
    browser.close()

# A 256-color palette keeps the flat UI and text sharp at about a third of the size.
image = Image.open("docs/images/report.png").convert("RGB")
image.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(
    "docs/images/report.png", optimize=True
)
PY
```
