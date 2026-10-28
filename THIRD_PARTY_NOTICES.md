# Third-party notices

Front-end libraries are vendored under `static/` (no CDN is used at runtime).
Each directory contains the upstream license text.

| Library | Version | License | Location |
|---|---|---|---|
| Bootstrap | 5.3.0 | MIT | `static/vendor/bootstrap/` |
| Bootstrap Icons | 1.11.3 | MIT | `static/vendor/bootstrap-icons/` |
| jsQR | 1.4.0 | Apache-2.0 | `static/vendor/jsqr/` |
| qrcodejs | 1.0.0 | MIT | `static/qrcode.min.js` (license: `static/vendor/qrcodejs/LICENSE`) |

All files were taken unmodified from the corresponding npm packages (only
`sourceMappingURL` comments were removed from the Bootstrap files).

Python dependencies are listed in `requirements.txt` and carry their own licenses.
