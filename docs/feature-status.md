# Feature status

This catalog describes the current code paths. Hosted entries identified here have local
automated coverage using fixture state. See the [acceptance journeys](acceptance/journeys.md)
for checks against a running product.

| Area | Current behavior | Main evidence |
| --- | --- | --- |
| Setup and profiles | Hosted first-run setup is per tenant. Standalone installations can create and switch local profiles. | [Hosted](../tests/test_hosted.py), [setup](../tests/test_setup.py), [profiles](../tests/test_profile.py) |
| Invoices and customers | Create domestic, EU and third-country invoices, produce PDFs and record payment. Existing invoices can be imported from CSV. | [Invoices](../tests/test_invoices.py), [customers](../tests/test_customers.py), [route tests](../tests/test_web_routes.py) |
| Transactions and expenses | Use manual or imported payments, attach documents, categorize receipts and reconcile invoices. Closed periods restrict booking changes. | [Transactions](../tests/test_transactions.py), [documents](../tests/test_documents.py), [hosted accounting](../tests/test_hosted.py) |
| Reports | Provide EÜR, VAT summaries and ZM, with tests for period boundaries, income treatments and VAT types. The output supports manual filing. | [Reports](../tests/test_reports.py), [VAT types](../tests/test_vat_kinds.py) |
| Hosted gateway | Authenticate users, isolate ledgers and deny local-only endpoints. | [Hosted](../tests/test_hosted.py) |
| Hosted bank integration | Configure tenant credentials, complete consent, import bank history and sync again without duplicating seen transactions. Provider setup requires an eligible application and registered callback. | [Hosted](../tests/test_hosted.py), [operator guide](../hosted/README.md) |
| Other entry points | Standalone Web, desktop, CLI, MCP and local integrations. The gateway permits only its explicit hosted web surface. | [README](../README.md), [CLI](../tests/test_cli.py), [MCP](../tests/test_mcp.py) |
| Public site | Static landing page and redirect worker, independent of the hosted ledger. | [Public site](../site), [worker](../worker.js) |

Update this page when a change affects availability, support or its test evidence.
