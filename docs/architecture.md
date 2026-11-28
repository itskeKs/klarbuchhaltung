# Architecture

Klarbuchhaltung keeps bookkeeping data in independent SQLite ledgers. The Flask web app,
desktop shell, CLI and tool interfaces share the same domain logic. Hosted adds a gateway
and Enable Banking integration around two private instances of the Flask app.

## Layers and entry points

| Layer | Code | Responsibility |
| --- | --- | --- |
| Domain and storage | [core.py](../core.py) | Profile and attachment paths, schema upgrades, bookkeeping, reports and invoice PDFs. |
| Web | [app.py](../app.py), [templates](../templates), [static](../static) | Flask routes, Jinja views, form handling and browser presentation. |
| Local surfaces | [desktop.py](../desktop.py), [bookkeeping.py](../bookkeeping.py), [assistant.py](../assistant.py), [mcp_server.py](../mcp_server.py), [wirex.py](../wirex.py) | pywebview shell, CLI, assistant tools, stdio MCP and local Wirex integration. |
| Hosted boundary | [gateway](../hosted/gateway.py), [tenant](../hosted/tenant.py), [Compose](../compose.hosted.yml) | HTTPS edge routing, login, tenant proxy authentication, endpoint permissions and per-tenant runtime. |
| Hosted provider | [bank service](../hosted/bank_service.py), [Enable Banking client](../hosted/enable_banking.py) | Consent, bank queries, scheduling and conversion into local transactions. |
| Public site | [site](../site), [worker.js](../worker.js) | Static marketing pages and public redirects. |

Change the storage or domain logic before changing the entry points that depend on it.
Keep bookkeeping and report definitions in the domain layer. Browser styling and hosted
request trust belong to the respective outer layers.

## Hosted request and data boundaries

The external HTTPS proxy reaches only the gateway. The gateway assigns a signed-in user
to one tenant and proxies to that tenant on its private network. Each tenant has its own
gateway token, data volume and bank credentials. The tenant checks the internal token,
login context, endpoint allowlist and CSRF before a state-changing request. Bank callbacks
complete consent only in the matching signed-in context. Keep local-only features disabled
and use the existing tenant-aware attachment response.

The bank service queues consent imports, manual refreshes and daily sync. It preserves
provider references for deduplication and keeps transactions ready for the user's booking
decision. An imported payment can count directly as income or be assigned to an invoice.
The selected treatment contributes once, in accordance with the configured timing and
VAT basis. Preserve closed periods and keep a failed import from producing partial or
unconverted ledger entries.

## Storage and compatibility

A source run defaults to the checkout for data unless `BB_HOME` is set. Installed apps use an
OS application-data directory. Local profiles have separate configuration and data subtrees.
Hosted fixes the tenant root and disables profile switching. Configuration, SQLite files,
bank statements, attachments and PDFs belong to their selected data root. Document
references should remain portable across a profile move and upgrades must still read
historic layouts. Preserve schema upgrades in `core.init_schema()` and cover older data in tests.

See [feature status](feature-status.md), [operations](operations/README.md) and
[pytest conventions](../features/README.md).
