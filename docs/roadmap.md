# Roadmap

Maintain a self-hostable bookkeeping application with private ledgers and reliable
invoice, payment and reporting workflows. See [feature status](feature-status.md)
for the current scope.

## Work tracker

The [fork issue tracker](https://github.com/itskeKs/klarbuchhaltung/issues) is the source for
work items, tier labels, milestone ordering and owner decisions. Use the
[task template](../.github/ISSUE_TEMPLATE/task.md). One issue has one branch and one PR.
Use `Closes #N` when every acceptance box has passed and `Refs #N` for partial work.

## 1. Foundation

1. Establish the Make gates, pre-commit hook and pull-request checks.
2. Document the existing architecture, status, design, operations and acceptance journeys.
3. Scope paired agent rules around the existing code and verify their hook contracts.
4. Use [core journeys](acceptance/journeys.md) and the existing pytest suite to check
   future changes to the hosted ledger.

Add later commitments and unresolved product decisions here when the maintainer records
them in the fork tracker.
