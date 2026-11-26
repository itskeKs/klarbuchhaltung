# Executable behavior

Pytest is the executable specification for Klarbuchhaltung. Place a new behavior test
beside the closest existing case in [tests](../tests). Use an observable result for a
user scenario and focused assertions for edge cases. The current suite uses plain pytest
fixtures, request tests and local integration tests.

- Exercise booking and report rules through the existing `conn`, `cfg` and `make_invoice`
  fixtures in [conftest.py](../conftest.py). Calculate expected amounts independently.
- Exercise web validation or navigation through its Flask request path. Reuse the hosted
  fixtures to cover the gateway, CSRF, a stub bank provider and two independent tenant roots.
- Keep test profiles and bank payloads synthetic, and stub external requests. Test imports
  and upgrades with disposable paths and historical data shapes.
- Establish the failing behavior before the implementation, run the focused test after the
  fix and run the full verification before merge.

The [core journeys](../docs/acceptance/journeys.md) link each walkthrough to its nearest
automated coverage. Add an observable pytest scenario for a confirmed acceptance finding
before fixing it. A route or domain test provides regression evidence. A browser user check
also covers navigation, wording and layout.

```sh
.venv/bin/python -m pytest tests/test_hosted.py
.venv/bin/python -m pytest tests/test_reports.py -k vat
make test
```
