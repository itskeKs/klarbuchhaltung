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

[Banking guide](../../hosted/README.md) · [Regression tests](../../tests/test_hosted.py)
