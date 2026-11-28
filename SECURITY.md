# Security policy

Report vulnerabilities privately to the fork maintainer. Use
[GitHub private vulnerability reporting](https://github.com/itskeKs/klarbuchhaltung/security/advisories/new)
when available, or an established private channel to the maintainer. Keep security details
and any affected records out of public issues.

Include the code revision, affected component and a minimal description of the problem.
Use synthetic data and redact secrets, account identifiers, callback URLs with codes,
business records and private file paths. Reproduce against a disposable local environment.

Relevant reports include cross-tenant access, unsafe downloads, authentication or request
validation failures, banking credential or consent exposure, and data corruption.
See [repository rules](AGENTS.md), [architecture](docs/architecture.md) and
[hosted operations](hosted/README.md) for the intended boundaries.
