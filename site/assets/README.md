# Fixed README assets

Locally owned, non-generated assets referenced by the README candidate. Each
file is bound by the SHA-256 recorded in `site/generated/README.slots.json`.

| File | Purpose | Format |
| --- | --- | --- |
| `cirewind-banner-dark.png` | Banner above the README heading on GitHub's dark theme; wordmark only, no other text; meaning carried by shape and color with alt text naming every element | 1800 by 600 pixels, 256-color palette PNG, no metadata |

Replacing a file requires regenerating the README candidate so the recorded
digest moves with it, and repeating the accessibility and cold-reader review of
the exact bytes before release.
