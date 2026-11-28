# Agent notes for Klarbuchhaltung

Klarbuchhaltung helps German freelancers and small businesses manage invoices, payments,
documents and reports. The software uses Flask, Jinja and SQLite, with a pywebview desktop shell and a
Gunicorn/Compose hosted stack. Develop with Python 3.13. The fork maintainer is
Christian Kunkel (`itskeKs`). The [MIT license](LICENSE) retains upstream copyright.

See the [roadmap](docs/roadmap.md), [feature status](docs/feature-status.md),
[design contract](DESIGN.md) and [contribution guide](CONTRIBUTING.md).
The UI copy is German. New repository documentation, issues, comments, test code and commits
are in English. Tests may quote the actual German interface.

## Project boundaries

- The fork tracks `lennardevertz/klarbuchhaltung`. Preserve desktop, CLI, MCP and the public
  site when working on the hosted app. Work and decisions for this fork live in its own tracker.
- `core.py` owns bookkeeping behavior and storage. Keep it independent of Flask, hosted
  routing and tool transports. Change the storage or domain layer before the callers that
  need its new behavior.
- Hosted uses one private SQLite ledger and one banking credential set per tenant. A tenant
  trusts only its own gateway token and login context. Keep the explicit endpoint allowlist,
  CSRF checks and disabled local-only features in force. Cover any changed entry point in
  `tests/test_hosted.py` and relevant route or domain tests.
- Keep money, VAT treatment, closed periods, reference matching and import deduplication
  consistent across entry points. Protect earlier databases and attachment paths. An existing
  imported payment contributes to reports exactly once, including after invoice assignment.
- A hosted deployment contains real bookkeeping data. Use synthetic local data and the stub
  bank client for testing. The fork maintainer authorizes any production or provider activity
  separately. See [operations](docs/operations/README.md).
- Product decisions are the owner's and live in issues under comments headed "Owner decision".
  Record unresolved product scope in the roadmap rather than deciding it in implementation.

## Agent host integrations

Claude Code reads `CLAUDE.md` (a symlink to this file) and loads `.claude/rules/*.md`. Cursor
loads the equivalent `.cursor/rules/*.mdc`. Codex reads `AGENTS.md` and uses `.codex/hooks.json`
to attach always-on rules at session start and scoped rules before `apply_patch`, `Edit` or
`Write`. Approve the hooks with `/hooks` once per clone; see
[CONTRIBUTING.md](CONTRIBUTING.md#agent-host-setup).

Keep both rule trees equivalent in the same commit. A Claude rule without `paths` uses
Cursor `alwaysApply: true`. A scoped rule uses matching `paths` and `globs` with
`alwaysApply: false`. The Codex hook reads the Cursor tree directly.
`make test-agent-rules` checks parity, the symlink and the hook. Baseline and safety rules
apply regardless of scoped context.

## Work comes from issues

- A task is a GitHub issue written as a spec: What → Why it happens → Proposed change →
  User check → Acceptance → Out of scope (`.github/ISSUE_TEMPLATE/task.md`). Read it with `gh issue view N -R itskeKs/klarbuchhaltung`.
  There is no task list file.
- Scope is the issue's acceptance list: nothing less, nothing unasked. Do not add request or
  response fields, parameters, configuration keys, endpoints or options the issue does not name,
  and do not refactor neighbours in passing. One issue, one branch, one PR.
  `Closes #N` only when every acceptance box is done; otherwise `Refs #N` plus what remains.
- Red first: the scenario and the unit tests fail without the change, then the smallest change
  turns them green, then refactor with the tests still green.
- A finding outside the scope is recorded, never extra code and not an issue per finding: after
  searching the open issues, one comment line `- [ ] <class or ?> | <screen or file:line> | <what was seen> | <SHA> | PR #M`
  goes on the open bundle of its class (label `bundle`: one open issue per class of defect), on the
  open issue that already covers it, or on the inbox issue (label `inbox`: one standing issue); a
  triage run later turns the lines into issues. Only a finding in a blocker category (below, plus
  security and data loss) or a step of a core journey that a user cannot finish becomes a new issue
  at once, from `.github/ISSUE_TEMPLATE/task.md`; outside that a session files at most one new issue per
  PR, for a self-contained defect on the PR's own journey that has no class.
  A sentence in the PR description is not a record. Before asking the owner a question,
  check the decisions already recorded (comments headed "Owner decision").
- What repeats becomes a script. Before a procedure of several commands, look in `make help` and
  `scripts/`. A procedure of three or more commands that you run by hand and that an earlier
  session ran too (it is in an earlier PR or merge comment, or you needed it twice)
  gets one line on the inbox issue with the class `repeat`:
  `- [ ] repeat | <what the procedure is for> | <the commands, shortened> | <SHA> | PR #M`.
  A triage run asks the owner whether it becomes a script; do not write the script in passing.
- Work is picked by tier, not by issue number: labels `tier:1` (launch blocker), `tier:2` (before
  launch), `tier:3` (after launch), inside a tier the roadmap order. The inbox and an issue without
  a tier are never picked; bundles are ordinary work items.
- Cut before coding: an issue that touches more than one domain mechanism (for example a
  data model plus its validation rules plus an import) is split into issues of one mechanism each,
  one PR per issue, before the first branch exists.
- Three rounds, then freeze: a round is a fresh review of the open PR plus the push that
  fixes its findings; the implementer's own verifier pass before the PR does not count.
  After the third review the scope is frozen: continue only for data loss or corruption, wrong bookkeeping results,
  cross-tenant access, data exposure, failed checks, a failed user check or merge conflicts.
  Record every other finding as above. At most five rounds: a finding that still needs a push after the
  fifth means no merge. Blind acceptance runs: at most two per PR; a repeat checks only
  the changed steps.
- When the owner authorizes publication, the primary issue session may push its own PR
  branch and merge its own PR after independent review, green CI and under the merge lock.
  An authorized maintainer session may finish an abandoned PR under the same gates. Leaf
  agents leave publication to the primary session. Never push directly to `main`.
- Progress is code, tests and a commit. Keep transient plans, handoffs and evidence out of
  version control. Record decisions in the issue, the PR description or an ADR under
  `docs/adr/` when they bind future work.

## Verification

- Follow the testing rule under `.claude/rules/` and [features/README.md](features/README.md).
- Check every changed entry point against the project boundaries above. The hosted route and
  isolation tests exercise two independent tenant processes and a gateway.
- For a visible change, exercise the running app with synthetic data in a real browser and put
  before and after screenshots at desktop and 360 px in the PR. Use a disposable local
  environment with the hosted fixtures where tenant behavior matters.
- Write the user check before a change a user will notice. See [acceptance](docs/acceptance/README.md).
  The PR must pass the user check on its own state. Have an independent reviewer walk the
  running product or have the owner perform checks that require owner access.
- Use the [core journeys](docs/acceptance/journeys.md) for milestone acceptance. Add an
  executable regression in the existing pytest suite for a confirmed acceptance finding
  before fixing it. The goal and expected values come from the documented journey.
- Run tests selectively, `make lint` before every push, and `make test` before a merge.

## Gates

| Command | Runs |
|---|---|
| `make lint` | Python compilation and Bash syntax checks |
| `make test` | agent rules, then `python -m pytest` (about 23 seconds for pytest on the onboarding machine) |
| `make test-agent-rules` | paired rule parity, `CLAUDE.md` symlink and Codex hook contracts (no DB) |
| `make docs-check` | local links in tracked and new non-ignored Markdown outside `docs/archive/` |
| `make hooks` | enables `.githooks/pre-commit` for lint and documentation checks on staged content |

The Kit workflow runs lint, agent-rule and docs checks on pull requests and pushes to `main`.
The existing application workflow retains its macOS, Linux and Windows test jobs.
Fix failed checks before merging. Enable the local pre-commit hook and run it as configured.

Update docs in the same PR under the documentation contract (the docs rule under
`.claude/rules/`); a change to the look or copy of the user interface updates [DESIGN.md](DESIGN.md).
`docs/archive/` is legacy: do not read it or treat it as rules unless the user asks for a
specific question.

## Design rules

1. One source of truth: when several places decide the same thing (mode, permission, status),
   they read one table or function.
2. No configuration keys for tuning numbers or lists; documented constants. A key only for a real
   on/off switch or a deployment fact (host, secret, path).
3. State that must survive a restart lives in the database, not in memory.
4. No field, parameter or interface without a reader in the same PR.
5. Simple checks after the action beat predictive checks before it.
6. Classify errors by structured fields (codes, types), never by message text.
7. UI reports real outcomes only; no placeholder text, no "everything OK" when there is nothing
   to report. Follow [DESIGN.md](DESIGN.md) for components and formats.
8. Test representative long inputs and many rows.
9. Use what exists and works (libraries, modules, fixtures) before writing new mechanisms.

## Commits

`type(scope): lowercase imperative summary` (~70 chars), e.g. `feat(auth): …`, `fix(import): …`,
`test(bdd): …`, `docs(roadmap): …`, `ci: …`. Body: cause → change → tests. `Refs #N` or
`Closes #N` at the end. Push only the branch of the PR you work on; never `main`.

No attribution anywhere: no `Co-Authored-By` trailer for an assistant, no "Generated with …" line,
no mention of any AI assistant or agent as author, in commits, PR descriptions,
issues, comments, code comments or docs. Naming a tool the repo supports (`.claude/rules`, the
Codex hook) is subject matter, not attribution.

## Context economy

One issue per session, cut to fit a 64k context. Read only the files the issue names; read large
files with `rg -n` and line ranges.

Use one session per issue. A session reports the next eligible issue at handoff. Start a further
session only when the owner authorizes it. Record what another session needs on the issue or PR
through an authorized tracker workflow. An issue given up before opening its PR carries a
comment starting with `Blocked:`. Resume it after the necessary owner decision.

A maintainer serializes merges under `/tmp/klar-buha-merge.lock`. Hold it while updating the
branch, verifying that state and merging. Release it after the merge. The maximum duration is
twice the measured suite time plus 30 minutes. Store the PR number and time in the lock's
`info` file. Verify ownership, age and live users before removing a stale lock. A shared
acceptance environment, if authorized, uses `/tmp/klar-buha-acceptance.lock` the same way.
Local acceptance fixtures use isolated roots and dynamically allocated test ports.
A maintainer review worktree is detached on `origin/<branch>` while the issue worktree owns
the branch.

## Worktrees and cleanup

Work in a git worktree outside the main checkout with a predictable name: `<repo>-issue-N` for an
issue, `<repo>-review-N` for a PR under review. A worktree lives exactly as long as its
PR and belongs to the issue or PR, not to the session that created it: once that
is merged or closed, check that the tree is clean and that nothing runs there (after a merge
also that it landed on `main`), then remove the worktree and its local task branch. The session that merges cleans up the
merged PR's worktrees when they meet those conditions. Keep unknown or active resources and
report confirmed leftovers. An existing
`<repo>-issue-N` means issue N is being worked on.

Every agent cleans up after itself. What a session creates, it removes when its task ends:

- git worktrees and local branches once their PR is merged or closed (above);
- compose projects it started for acceptance or verifier runs, completely: containers, volumes,
  networks and the locally built images of this project (`docker compose -p <name> down -v
  --rmi local`), excluding every production or shared resource;
- scratch directories, briefs, logs, screenshots and reports, once their content is in the
  issue or PR;
- background processes it started (dev servers, watchers, browsers, test runs);
- lock files it holds (`/tmp/klar-buha-merge.lock` and the like), only after verifying that no process still uses them.

Before starting, look for known leftovers from the task and verify ownership before
removing them. Report resources that belong to the owner or another active session.

## Databases and containers

- Tests use disposable per-test SQLite files. Root fixtures redirect local runtime paths and
  guard against writes to real ledgers. Hosted integration fixtures start two separate tenant
  processes against temporary directories and stub the bank provider. No test DB lock,
  provider account or running Compose stack is required.
- Preserve upgrade behavior in `core.init_schema()` and legacy profile migration. Use tests
  with copied or synthesized historic schemas. Keep SQLite changes, document files and profile
  paths compatible, and preserve transaction and period-lock semantics.
- Treat live volumes, provisioned secrets, bank consent, uploads, exports and backups as
  private. Never test or develop against the deployed host, its proxy, its volumes or its bank
  accounts. Never remove a real volume. Keep production data out of test evidence, Git and CI.
