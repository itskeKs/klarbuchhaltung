# Assign a recurring payment

Import two debits for the current year. Give both the description “Office supplies”
and use amounts of €23 and €17. In **Zahlungen**, assign the €23 payment to
**4930 – Bürobedarf** and save. Reopen **Zahlungen** from the navigation.

Both payments are visible. The €23 row shows account 4930 and the €17 row is
still open. **Geldausgang** shows **-40,00 €**.

The [Flask route test](../../tests/test_web_routes.py) covers the assignment and
both visits. The [hosted test](../../tests/test_hosted_recurring_payment.py) repeats
the journey through the gateway and checks that the other tenant's ledger stays empty.
