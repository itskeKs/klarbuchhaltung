# Hosted bank import

Use two fresh EUR ledgers and separate browser sessions for Alex and Blake. The fixture
bank for Alex returns a EUR 119.00 credit on the first page and a EUR 23.00 debit on the
second. It also returns a pending payment. All three carry synthetic descriptions.

1. Sign in as Alex, open **Banking**, select the fixture bank and complete consent in
   the same session. Wait for two imported transactions.
2. Choose **Jetzt synchronisieren** twice. Reload the banking page after each completed
   sync. Both report zero new transactions.
3. Open **Zahlungen**. **Geldeingang** is EUR 119.00, **Geldausgang** is EUR −23.00 and
   **Netto** is EUR 96.00. **Nicht zugeordnet** shows the two booked payments.
4. Open **Zahlungen** as Blake. The list is empty and the net is EUR 0.00.
5. Categorize a payment as Alex and sync again. Its category stays assigned. Disconnect
   the account. Both payments remain under **Zahlungen**.

For a statement totaling EUR 205.00 that proves one extra EUR 119.00 receipt
with either of two references, find one **Kontoauszug prüfen** payment under
**Zahlungen**. It stays open for statement review. Repeating the import leaves
the total, the other payments and their assignments intact.

When the same reported movements lack a verified opening balance, **Zahlungen**
shows five booked payments and EUR 86.00 net. The possible EUR 119.00 appears in
a separate statement-review notice and stays outside the totals. A verified
opening balance of EUR 0.00 confirms the neutral payment and clears the notice.
A verified opening balance of EUR 119.00 clears the notice without a new receipt.

When the statement confirms the EUR 119.00 payment but cannot determine
whether November or December contains it, the combined period shows six
payments and EUR 205.00 net. Each month shows the confirmation below its own
totals and keeps the EUR 119.00 outside them. Sync again with the booking day
provided. Only the identified month's totals change. The combined period
still shows six payments and EUR 205.00 net.

[Banking guide](../../hosted/README.md) · [Regression tests](../../tests/test_hosted.py)
