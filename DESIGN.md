# Hosted banking interface

**Banking** uses the shared app shell, form controls and status messages. Show the
registered return address during setup. Each connection displays its bank, account,
consent expiry and the last completed import. A queued sync tells the user when to
reload. An expired consent directs them to connect again.

**Zahlungen** uses the existing signed amounts, German number formatting and open
payment filter. Keep the bank controls and payment amounts reachable at 360 px.
When a booked amount is confirmed and its reference is unclear, use the payment
description “Kontoauszug prüfen”.
See the [bank import walkthrough](docs/acceptance/journeys.md).
