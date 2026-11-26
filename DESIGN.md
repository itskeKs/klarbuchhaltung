# Klarbuchhaltung design contract

The German bookkeeping interface uses a Jinja app shell and shared local assets. Update
this document when changing the visible design or copy. The public site maintains its own
styles and tokens.

## Foundations

- Load [tokens.css](static/tokens.css) before [components.css](static/components.css).
  Use `--paper` for the shell, `--surface` for cards and `--ink` for primary text.
  Reuse semantic green for income, coral for expense or error, amber for warnings and azure
  for information. User-selected accents and row density are set by the existing data attributes.
- Use locally hosted Space Grotesk for headings and Instrument Sans for UI text. Use the
  existing type scale, 4 px spacing increments, radius and elevation variables.
- Use [base_klar.html](templates/base_klar.html) and the
  [sidebar partial](templates/_sidebar.html) for app pages. Use existing cards, tables,
  labeled fields and button variants. Reuse the [dialog](templates/_dialog.html) and
  [document viewer](templates/_docviewer.html) for their existing roles.

## States and interaction

Use a clear active navigation state and preserve visible focus. Give icon buttons an
accessible action name. Show an actionable empty state, immediate validation feedback and
specific failures. Report completion only after a confirmed result. Keep in-progress bank
sync distinct from its completion message. Preserve accessible keyboard behavior and the
existing confirmation flow for destructive actions.

On hosted pages, retain the correct login and CSRF context when submitting forms and
hide standalone-only actions. Keep principal actions and feedback usable on narrow screens.
Verify changed views in a real browser at desktop width and 360 px with synthetic data.
Attach before and after evidence to the PR.

## Copy and formats

Use direct German verbs and existing labels such as **Zahlungen**, **Rechnungen** and
**Berichte**. Keep action wording consistent across buttons, dialogs and feedback. Use the
existing formatters and conventions for currency and localized dates. Preserve meaningful
amount signs, the configured currency and the distinction between gross, net and VAT.
Use stable invoice numbers and dates in documents and exports.

The existing [screenshots](docs/screenshots) illustrate the application's visual vocabulary.
The [acceptance journeys](docs/acceptance/journeys.md) describe current hosted user checks.
