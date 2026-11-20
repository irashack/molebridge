# Screenshots

`capture.js` retakes the images in `docs/assets` that come from the panel or
a source SVG:

- `switchyard.png`: four exits (Mullvad, PIA, NordVPN, and Surfshark through
  gluetun), Mullvad open;
- `switchyard-gluetun.png`: Mullvad, Mullvad through gluetun (open) and
  Surfshark through gluetun;
- `switchyard-configured.png`: one NordVPN exit pinned by `SERVER`;
- `brand/social-preview.png`, rendered from `brand/social-preview.svg`.

Run it from the repository, with the Go toolchain and Playwright's Chromium
installed (`require('playwright')` must resolve):

```sh
node tools/screenshots/capture.js                  # all four
node tools/screenshots/capture.js switchyard       # one scene, or social-preview
```

It builds `molebridge` into a temporary directory, then runs
`TestWriteScreenshotState` (`internal/panel/screenshots_test.go`) with
`MOLEBRIDGE_SCREENSHOT_STATE` set, which writes each scene's state: the
catalogues, a status record a minute old (the test fixtures' schema 2
records) and the panel's request, plus a `scene.json` with the panel's
environment. For each scene it starts `molebridge panel` on loopback with
only that environment and `MOLEBRIDGE_PANEL_ISOLATION_CHECK=off`, opens the
page in Chromium at 1280×860 with a device scale factor of 2, and writes a
2560×1720 PNG. The social preview is the SVG on a 1280×640 page at the same
scale, 2560×1280.

Chromium on Linux picks fonts through fontconfig, and a fontconfig without
the usual alias files resolves `sans-serif` to a serif face. The script
gives Chromium a `fonts.conf` that includes yours (`FONTCONFIG_FILE`, else
`/etc/fonts/fonts.conf`) and prefers Noto Sans, DejaVu Sans or Liberation
Sans for the panel's system font stack. The committed images were taken with
DejaVu Sans.

Every value in the seeded state is fictitious: servers named in each
provider's public pattern, documentation addresses (`198.51.100.0/24` and
`192.0.2.0/24` for servers, `203.0.113.0/24` for exit addresses) and
all-zero keys. Those servers answer nothing, so the latencies on the page
are made up too: the script answers `/api/latency` with the panel's own
answer, its numbers replaced by the scene's table (roughly 1 ms per 70 km
from the exit's city).

Look at every image before you commit it. The panel's look changes with the
code, so retake all three screenshots when it does.
