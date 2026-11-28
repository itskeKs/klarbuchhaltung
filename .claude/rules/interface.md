---
description: Flask templates and user interface
paths:
  - "templates/**"
  - "static/**"
  - "site/**"
  - "worker.js"
  - "desktop.py"
---

Use the current Jinja shell, shared components and CSS tokens. Honor German copy and
the displayed number, currency and date formats. Preserve keyboard access and the correct
empty, busy, success and failure states. Verify a visible change with synthetic data at
desktop width and 360 px and update the design contract with the change.

The public site has separate assets and its own redirect worker. Treat it separately from
the tenant UI. Hosted views must hide local-only actions and maintain hosted CSRF behavior.

See [DESIGN.md](../../DESIGN.md) and [acceptance](../../docs/acceptance/README.md).
