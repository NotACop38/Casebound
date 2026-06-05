# Demo images

This directory holds the README's visual assets.

## report.png (TODO)

`docs/images/report.png` is the screenshot of the generated HTML report
(`out/report.html`), used as the README hero (PRD Section 14, Phase 7).

It is not committed yet: this Phase 1 environment has no headless browser, so the
PNG cannot be rendered here. The report itself is fully generated and verified by
`make demo` and the report tests; only the screenshot is pending.

To regenerate it once a headless renderer is available:

```bash
# 1. Produce the report.
make demo            # writes out/report.html

# 2. Screenshot it to this path (any one of these).
#    a) headless Chromium:
chromium --headless --screenshot=docs/images/report.png \
  --window-size=1100,2000 --hide-scrollbars out/report.html
#    b) wkhtmltoimage:
wkhtmltoimage --width 1100 out/report.html docs/images/report.png
```

Keep the image in sync with the report layout. The report is self-contained, so a
local screenshot needs no network.
