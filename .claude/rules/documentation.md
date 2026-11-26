---
description: Documentation and acceptance updates
paths:
  - "*.md"
  - "docs/**"
  - "features/**"
  - ".github/ISSUE_TEMPLATE/**"
---

Update the documentation that owns behavior in the same change. Use the feature catalog for
status, architecture for dependencies and invariants, and the operations map for user and
operator instructions. Record binding decisions in an ADR and unresolved scope in the
fork issue tracker. Keep real data and secret material out of examples.

A visible change updates the relevant design or journey text and has a user check with
concrete expected results. Run `make docs-check` and keep local links usable from a clone.

See the [documentation map](../../docs/README.md).
