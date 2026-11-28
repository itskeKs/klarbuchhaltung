# Contributing to Klarbuchhaltung

The app interface is German. Write new repository documentation, issues, code comments and
commit messages in English. [AGENTS.md](AGENTS.md) defines the repository workflow.

## Development environment

Use Python 3.13, Git 2.31 or later, Bash and Make. From the checkout root on macOS or Linux:

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -r hosted/requirements.txt pytest
make hooks
make test
```

For Linux system packages used by pywebview, follow the installation step in the
[existing application test workflow](.github/workflows/test.yml).
On Windows, the upstream workflow shows the equivalent direct Python commands.
The Makefile uses `.venv/bin/python` when present and falls back to `python3`. To point it
at another environment, use `make test PYTHON=/path/to/venv/bin/python`.

Tests use disposable SQLite files with sample data. Hosted fixtures use a local gateway,
two isolated tenant processes and a stub banking client. Start a local demo with `BB_HOME`
pointing to a fresh temporary directory. Source execution without it can use the checkout
as the data root. See the installed-app and source-run instructions in the [README](README.md).
Keep personal data, credentials and bank statements out of the repository.

## Checks

| Command | What it runs |
| --- | --- |
| `make lint` | Python compilation and Bash syntax checks. |
| `make test` | Agent rule contracts and then `python -m pytest`. The suite takes about 23 seconds on the onboarding machine. |
| `make test-agent-rules` | Paired rule parity, the `CLAUDE.md` symlink and supported Codex hook payloads. |
| `make docs-check` | Local links and images in tracked and new Markdown. It skips ignored files and `docs/archive/`. |
| `make hooks` | Enables the repository pre-commit hook, which runs lint and docs checks on the staged tree. |

Use `.venv/bin/python -m pytest tests/test_hosted.py` for the focused hosted suite.
The [Kit workflow](.github/workflows/tests-on-pr.yaml) runs `make lint`, `make test-agent-rules`
and `make docs-check` on Linux.
The [upstream matrix](.github/workflows/test.yml) also runs the application tests on macOS,
Linux and Windows.

## Agent host setup

`AGENTS.md` carries project-wide rules and `CLAUDE.md` is a symlink to it.
Claude Code reads `.claude/rules/*.md` and Cursor reads their `.cursor/rules/*.mdc`
counterparts. Keep descriptions, scopes and bodies equivalent. A Claude rule with `paths`
uses matching Cursor `globs` and `alwaysApply: false`. A Claude rule without `paths`
uses Cursor `alwaysApply: true`. Use quoted block lists for paths and globs. The Kit
adapter accepts its documented block-list format.

In Codex run **`/hooks` once per clone** to review and approve the two project handlers.
Review them again when either hook file changes. The adapter requires Python 3. It attaches
always-on Cursor rules at session start and attaches matching scoped rules when a supported
`apply_patch`, `Edit` or `Write` payload names a path. An opaque shell write can provide no
path context. The adapter fails open and the rules in [AGENTS.md](AGENTS.md) apply regardless
of hook approval. The Git hook enabled by `make hooks` is separate.

## Issues and pull requests

- Read the issue in the [fork tracker](https://github.com/itskeKs/klarbuchhaltung/issues)
  and check its acceptance and out-of-scope sections. Use one branch and PR per issue.
- Start a behavior change with a failing test and follow the existing [pytest
  conventions](features/README.md). Run the relevant tests during implementation.
- Update the documentation that owns any changed behavior. Update
  [DESIGN.md](DESIGN.md) for a visible design or copy change.
- Run the Make checks. For visible changes, exercise the synthetic scenario in a real
  browser and attach before and after evidence at desktop width and 360 px. Record the
  [user check](docs/acceptance/README.md) on the PR.
- Use `type(scope): lowercase imperative summary` for commit subjects. Use `Closes #N`
  when all acceptance boxes are satisfied and `Refs #N` for partial work.
- With the owner's authorization for publication, the primary issue or maintainer session
  can publish its branch and merge the reviewed PR after green CI, under the merge lock.
  Releases, production access and deployment require separate authorization.

Find the architecture, feature catalog and operations references in the
[documentation map](docs/README.md).
