# Hosted Klarbuchhaltung

This Compose stack serves two logins at one HTTPS origin. It runs a gateway and two independent bookkeeping processes. Each tenant has a separate bridge network, data volume and gateway token. The gateway is the only service on the edge network. No container publishes a host port.

## Start behind an existing HTTPS proxy

Provision once from the repository root, using a private operator terminal. The command prints two generated passwords. Deliver each password privately to its owner and keep any retained copy in your password manager.

```sh
python3 -m hosted.provision /etc/klarbuchhaltung Chris Kiki
chown -R 10001:10001 /etc/klarbuchhaltung
export KLAR_SECRETS_DIR=/etc/klarbuchhaltung
docker compose -f compose.hosted.yml up -d --build
```

The default public origin is `https://buha.fogu.app`. Set `KLAR_PUBLIC_ORIGIN` before starting the stack if you use a different HTTPS origin. The gateway joins the existing external Docker network `buha-proxy` as `klarbuchhaltung-gateway:8000`. Forward the original `Host`, replace `X-Real-IP` with the actual client address, and allow up to 25 MiB request bodies. Route `/api/bank/callback` to the same gateway with its query string intact. Disable or redact callback access logs at the edge because they contain one-time bank authorization codes.

## Connect a bank

Each person signs in, completes the bookkeeping setup and opens **Banking**. Create a separate Enable Banking application for each person and register the displayed redirect URL, normally `https://buha.fogu.app/api/bank/callback`. A production application must be activated or have its owner's accounts allowlisted with Enable Banking. Enter the application ID and upload its corresponding private RSA PEM in Banking. The app stores the key in that tenant's volume and never displays it after upload.

For operator provisioning instead, put `application-id` and `private-key.pem` in the corresponding tenant's directory under `KLAR_SECRETS_DIR`. Use ownership `10001:10001` and mode `0600` for both. Do not reuse another tenant's app ID or key.

Select the country, bank and account type, then complete consent in the same logged-in browser. The first import runs after authorization and requests the longest history available from that bank. It checks daily thereafter, even when browsers are closed. **Jetzt synchronisieren** queues an immediate import. Transactions arrive as open items and can be categorized in **Zahlungen**. For an EUR ledger using cash-basis VAT under the regular VAT regime, you can book a positive domestic EUR payment directly at 19% or 7%, or assign it to an invoice. The former uses the receipt date. Reports use the selected treatment once. If your consent expires, reconnect the same account to continue importing.

## Back up and restore

Protect backups as banking data and secrets. Preserve `KLAR_SECRETS_DIR` and the complete tenant volumes `klarbuchhaltung_tenant-a-data` (Chris) and `klarbuchhaltung_tenant-b-data` (Kiki). Stop the services before a volume-level copy or take an application-consistent snapshot. Keep each tenant's backup in a separate protected location and restore it only to its original tenant volume. Gateway sessions live in `klarbuchhaltung_gateway-data`. They can be discarded during a restore to require both users to sign in again.
