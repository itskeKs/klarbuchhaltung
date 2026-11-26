# Hosted Klarbuchhaltung

This Compose stack serves two logins at one HTTPS origin. It runs a gateway and two independent bookkeeping processes. Each tenant has a separate bridge network, data volume and gateway token. The gateway is the only service on the edge network. No container publishes a host port.

## Start behind an existing HTTPS proxy

Provision once from the repository root, using a private operator terminal. The command prints two generated passwords. Deliver each password privately to its owner and keep any retained copy in your password manager.

```sh
python3 -m hosted.provision /etc/klarbuchhaltung Alex Blake
chown -R 10001:10001 /etc/klarbuchhaltung
export KLAR_PUBLIC_ORIGIN=https://ledger.example.org
export KLAR_SECRETS_DIR=/etc/klarbuchhaltung
docker compose -f compose.hosted.yml up -d --build
```

Set `KLAR_PUBLIC_ORIGIN` to the HTTPS origin your users visit. The gateway joins the existing external Docker network `buha-proxy` as `klarbuchhaltung-gateway:8000`. Forward the original `Host`, replace `X-Real-IP` with the actual client address, and allow up to 25 MiB request bodies. Route `/api/bank/callback` to the same gateway with its query string intact. Disable or redact callback access logs at the edge because they contain one-time bank authorization codes.

## Connect a bank

Each person signs in, completes the bookkeeping setup and opens **Banking**. Create a separate Enable Banking application for each person and register the displayed redirect URL, normally `https://ledger.example.org/api/bank/callback`. A production application must be activated or have its owner's accounts allowlisted with Enable Banking. Enter the application ID and upload its corresponding private RSA PEM in Banking. The app stores the key in that tenant's volume and never displays it after upload.

For operator provisioning instead, put `application-id` and `private-key.pem` in the corresponding tenant's directory under `KLAR_SECRETS_DIR`. Use ownership `10001:10001` and mode `0600` for both. Do not reuse another tenant's app ID or key.

Select the country, bank and account type. Complete the bank's consent screen on
`auth.enablebanking.com` or `tilisy.enablebanking.com` in the browser session that
started it. The return link works once.

The first import retrieves the longest available history. With the tenant running, the
scheduler checks daily, even with every browser closed. **Jetzt synchronisieren** requests
an additional check. Reload **Banking** for the result. Each check follows all pages of
booked transactions. Pending entries stay at the bank until booked. Under **Zahlungen**,
new entries are open for categorization. Repeated checks preserve assignments. A bank
reference can be reused on another date. Compatible copies of a booking with the same
dated reference count once. A copy can add a posting date, balance or structured
reference when the matching dates and known details agree.
Different known balances or structured references can distinguish separate payments.
**Banking** flags conflicting memos and entries with multiple possible matches. Compare
them with the statement. The next fetch retries them as the bank supplies more detail.
Reauthorizing the same account preserves its payment history, including when the bank
adds an IBAN.

When a consent expires, use **Bank verbinden** and complete consent again. **Verbindung
trennen** stops imports for that connection. Its payments and their categories remain in
your ledger. See the [two-login walkthrough](../docs/acceptance/journeys.md).

## Banking screens

| Step | Desktop | 360 px |
| --- | --- | --- |
| Select the fixture bank | [Bank selection](../docs/screenshots/hosted-banking/banking-before-desktop.png) | [Bank selection](../docs/screenshots/hosted-banking/banking-before-mobile.png) |
| Check the completed sync | [Connection status](../docs/screenshots/hosted-banking/banking-after-desktop.png) | [Connection status](../docs/screenshots/hosted-banking/banking-after-mobile.png) |
| Review the imported payments | [Payments](../docs/screenshots/hosted-banking/payments-desktop.png) | [Payments](../docs/screenshots/hosted-banking/payments-mobile.png) |

## Back up and restore

Protect backups as banking data and secrets. Preserve `KLAR_SECRETS_DIR` and the complete tenant volumes `klarbuchhaltung_tenant-a-data` (first login) and `klarbuchhaltung_tenant-b-data` (second login). Stop the services before a volume-level copy or take an application-consistent snapshot. Keep each tenant's backup in a separate protected location and restore it only to its original tenant volume. Gateway sessions live in `klarbuchhaltung_gateway-data`. They can be discarded during a restore to require both users to sign in again.
