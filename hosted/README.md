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
dated reference count once. A copy can add a posting date, balance or reference
when the matching dates and known details agree. The ledger remembers alternate
dates and a newly supplied bank reference when it can identify an existing payment.
Different known balances, structured references or comparable counterparty account
identifiers can distinguish separate payments, even when the bank reuses a reference.
When two bookings with the same reference appear together, different known dates of
the same kind can identify the separate payments and match later replays. A shared
running balance and structured reference can corroborate a secondary-date correction.
Dated statement movements, including movements on the same day, can show that a
balance recurred after a separate payment. Compatible copies can supply missing
balances. Signed movements can bridge missing balances when other amounts and
reported balances support the same sequence. The check keeps booking, value,
and transaction dates separate. Booking dates set the order of posting days.
Value and transaction dates help order movements where they fit the recorded
balances. Surrounding balances can show
which of two bank versions fits the statement. When those balances leave both
counts possible, **Banking** asks for review before adding a second payment.
For several versions, the statement can establish how many payments share a
reported posting day even when their secondary dates remain unclear.
Compatible bank facts can support that check when an optional reference is
missing. Reported balances can also confirm two otherwise identical payments.
The balance check considers related repeated movements together and preserves
the bank's reported dates when other date fields are missing. Independent
balances can establish the number of payments even when a movement has only
a booking date. A payment without a reported booking date can use the ledger
day established by the surrounding statement. A proven booking date replaces
a fallback on an unassigned payment in open periods and uses the exchange rate
for the booking day. For assigned payments and closed periods, **Banking** flags
changes to the period or conversion date for review.
Balances on neighboring booking days can establish the count while the precise
booking day remains open. A named payment keeps its fallback in that case.
If a confirmed payment could fall in different months, **Zahlungen** shows the
amount with its month open. It counts once in periods that cover every possible
booking month and stays outside the individual monthly totals until assigned
by bank evidence. Use **Alle Jahre** if the possible months span a year boundary.
For a foreign-currency payment, the home-currency totals use the exchange rate
once the booking date is known.
If the statement proves an additional payment on a known booking date and
leaves its bank reference unresolved, **Zahlungen** shows it once as an open
payment. Check the statement before assigning it. The import leaves the
reference, counterparty and category of that payment open.
Compatible versions, including copies with missing dates or a changed lookup
ID, contribute to the balance check without deciding the reference. A proven
reference correction keeps the existing payment and its posting date. If the
balances support different totals, check the statement before adding another payment.
**Zahlungen** shows a possible unbooked amount separately when the statement
cannot establish its existence. It contributes to neither the booked count nor
the gross or net totals. A later verified opening balance can confirm or clear
the review without reposting the existing payments.
An overlapping reply can still resolve the review when it omits a balance
already observed for the same uniquely identified payment. An explicitly
reported balance or conflicting bank fact is assessed as new evidence.
A shorter reply can identify the booking date of a previously confirmed
payment. Saved observations from that statement can support the decision
without importing those movements again. One reply can resolve several
statements independently, even when another statement still needs review.
The same reported balance can support more than one statement. The importer
checks repeated reports together and uses the balances to identify any
additional equal movements. Compatible booking facts can link repeated
reports after their temporary lookup IDs change. When compatible reports
show the same movement and ending balance, the other signed movements
can establish how many times that balance was reached. The importer
checks which movements can connect one reported balance to the next,
including repeated reports of the surrounding transactions. When those
surrounding movements also match the ledger, a later report with amended
details can match the original payment. When the dated statement window
still supports several counts, the importer books the supported minimum.
Any possible additional amount appears in Payments for review outside the
totals until further bank evidence settles it. When a later page omits a
balance, the same signed statement can establish the total count across
several compatible payments. An additional observation without a balance
can support another payment when it connects reported balances. Movements
without a reported balance stay in the interval between checkpoints. The
surrounding balances can establish the count even if no version of a
payment reports its own balance. If pages overlap and a checkpoint is
missing, the established
payment is booked and a possible extra amount remains in review. A bank
reference can identify a report even when another copy omits it. A short sync that cannot resolve an
amended report against the established booking flags it for review and
preserves the original amount and assignment. Updated bank descriptions
can still corroborate an earlier statement when the monetary facts agree.
After the bank establishes a payment's booking month, replays of its confirmed
reports can use the same statement evidence even if the fetch only covers that month.
Previously confirmed movements on that day can also help check a new report
for multiple occurrences.
Value and transaction dates can help identify a movement or place it when
its booking date is missing.
Movements on the same known booking day can follow any order consistent
with the reported balances. A balance on that day can establish the number
of payments even when those payments have no individual balances. When the
possible counts still differ, the extra amount stays in review until a
reported balance resolves it.
Related repeated reports are checked against every booked movement between
their shared checkpoints. **Zahlungen** counts each payment established by
all compatible histories once, including payments already recorded by
name. An unresolved purpose remains open for review. A possible receipt
or reversal stays outside the gross amounts and net total until the
statement establishes it.
When the statement proves one additional payment and leaves a further payment
possible, **Zahlungen** includes the proven amount and shows the possible
remainder separately. Later balances that close the period can clear this
notice. The established payment stays linked to the same ledger entry when
the bank revises a reference or supplies a previously missing balance.
Independent earlier and later balances can establish the payment count
when each repeated report omits its own balance. A complete replay can
reuse corroborated balances from the same account if the bank omits them.
A checkpoint on the same booking day can prove a minimum while leaving
another payment possible after that checkpoint. A later closing balance
can resolve the remaining amount, and a weaker replay keeps that resolution.
Receiving the same observations on one page or several pages leaves the booked
amount unchanged. If the statement establishes both the amount and its purpose,
**Zahlungen** shows the observed purpose.
An entry reference can also change on a later page or fetch. Matching dates,
amounts and independent statement facts can identify the existing payment.
Where the statement leaves a repeat possible, check it before posting again.
If a later statement contradicts a payment already in the ledger, **Banking**
flags it and keeps the posted payment and category.
The ledger remembers account identifiers as fingerprints and learns missing evidence
from later matches. Temporary transaction IDs help identify copies within one fetch.
**Banking** flags conflicting memos, contradictory posting dates for a corroborated
booking, and entries with multiple possible matches. Compare them with the statement.
An existing payment keeps its posting date and category while the conflict is reviewed.
The next fetch retries flagged entries as the bank supplies more detail.
Reauthorizing the same account preserves its payment history when the bank adds an
IBAN or reports a previously known primary account hash. If multiple accounts claim
the same historical identity, Banking asks you to review the connection.

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
