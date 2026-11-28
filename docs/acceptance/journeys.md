# Hosted core journeys

Run each journey on fresh synthetic data or reset to the stated starting point. The two
people in the sample have separate browser sessions and temporary ledgers. Use the local
fixture from [acceptance setup](README.md).

## Sample world

- Alex runs **Sample Studio A** and Blake runs **Sample Studio B**. Neither ledger starts
  with invoices, payments or documents. Both use EUR. Alex uses regular VAT with cash-basis
  accounting and quarterly VAT reports.
- The stub bank for Alex returns one settled domestic payment of EUR 119.00 on
  2026-03-10 with the same provider reference on every refresh.
- The domestic customer is **Sample Customer GmbH**. An invoice dated 2026-03-05 has
  one consulting item for EUR 100.00 net at 19% VAT.
- Use a one-page synthetic receipt named `sample-receipt.pdf` with the visible text
  "Sample Studio A, 10 March 2026, EUR 119.00".

These fixture values define the browser walkthrough. The pytest `StubProvider` returns a
booked EUR 119.00 credit, a booked EUR 23.00 debit on the next page and a pending payment.
It uses dates relative to the test run. For the reporting and invoice browser walkthroughs,
set the stub credit's date to 10 March 2026.

## 1. Keep two ledgers separate

**Goal** Alex and Blake can finish setup and return to their own bookkeeping.

**Do** Sign in as each person in separate browser sessions. Complete each setup with the
sample business name, then open its profile. Sign Alex out and attempt to revisit
**Dokumente** in that session.

**Expected** Each profile shows its own business name. Alex is sent to sign-in when trying
to reopen files while signed out. Hosted navigation does not offer the terminal or local
profile switching.

**Browser checks** Sign-in and setup at desktop width and 360 px.

**Automated coverage** [Hosted integration](../../tests/test_hosted.py).

## 2. Import a bank payment once

**Goal** Alex can connect the fixture bank and receive a payment once.

**Do** From Alex's **Banking** page, start consent with the stub bank and complete the
return in the same browser. Wait for the import, then sync again using **Jetzt synchronisieren**.
Open **Zahlungen** in both ledgers.

**Expected** Alex sees one open EUR 119.00 payment. The second sync reports zero new
transactions and the payment still appears once. Blake's ledger contains no matching payment.

**Browser checks** Banking status and the payment list at desktop width and 360 px.

**Automated coverage** [Hosted integration and scheduled sync](../../tests/test_hosted.py).

## 3. Book and report income directly

**Goal** Alex can report a received payment without creating an invoice.

**Do** Starting with the open EUR 119.00 bank payment, book it as domestic income at 19% VAT
without assigning an invoice. Open reports for Q1 2026.

**Expected** The payment contributes EUR 100.00 net and EUR 19.00 VAT, exactly once in
the reporting period that contains 10 March. The gross income contribution is EUR 119.00.
There is no invoice for the payment.

**Browser checks** Payment booking and report values at desktop width and 360 px.

**Automated coverage** [Direct hosted income reporting](../../tests/test_hosted.py) and
[report boundaries](../../tests/test_reports.py).

## 4. Assign a payment to an invoice

**Goal** Alex can see that the customer's invoice has been paid.

**Do** In a fresh ledger, create the sample consulting invoice and open its PDF.
Confirm that it is unpaid before assigning the open EUR 119.00 payment with receipt
date 10 March. Open the Q1 report.

**Expected** The PDF shows EUR 100.00 net, EUR 19.00 VAT and EUR 119.00 due.
The invoice shows as paid after assignment. The report still contains one EUR 100.00
net contribution and EUR 19.00 VAT for the payment.

**Browser checks** Invoice list and the payment assignment at desktop width and 360 px.

**Automated coverage** [Invoices](../../tests/test_invoices.py) and
[hosted assignment and reporting](../../tests/test_hosted.py).

## 5. Retrieve a private receipt

**Goal** Alex can find the saved receipt while Blake has access only to their own files.

**Do** Upload the sample receipt in Alex's **Dokumente** and open or download it from the
list. In Blake's session, open **Dokumente** and then visit the copied receipt link.

**Expected** Alex receives the receipt containing the sample text. Blake sees no
matching list entry and receives no document when using Alex's link.

**Browser checks** Files list and document viewer at desktop width and 360 px.

**Automated coverage** [Hosted tenant file isolation](../../tests/test_hosted.py) and
[document storage](../../tests/test_documents.py).

After uploading the receipt, open it for review. Try to book it without a payment, amount
or date and confirm that the form asks for the missing fields. Enter a gross amount of
EUR 119.00 and the receipt date, then book it. Expect one expense on 10 March 2026 and
a receipt shown as booked.

## 6. Reconcile incomplete bank statements and export confirmed payments

Run the two-page fixture with Alex's clean ledger in one browser session. Open **Banking**,
connect the fixture bank and wait for two imports. Choose **Jetzt synchronisieren** twice.
Reload the banking page after each completed sync. Both report zero new transactions.
Open **Zahlungen**. **Geldeingang** is EUR 119.00, **Geldausgang** is EUR −23.00 and
**Netto** is EUR 96.00. **Nicht zugeordnet** shows both booked payments. Blake's list is
empty and its net is EUR 0.00. Categorize a payment as Alex and sync again. Its category
stays assigned. Disconnect the account. Both payments remain under **Zahlungen**.

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

Download **Export CSV** before and after the bank supplies the date. Both files
contain six movements totaling EUR 205.00. Before resolution, the confirmed
receipt has a blank date and **Buchungsmonat noch offen** in its description.
After resolution it appears once with its booking date. Blake's CSV has only
the column headers.

[Banking guide](../../hosted/README.md) · [Regression tests](../../tests/test_hosted.py)
