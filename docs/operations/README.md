# Operations

| Task | Reference |
| --- | --- |
| Install or run the standalone app | [Project README](../../README.md) covers packages, source execution and local profiles. |
| Exercise a local scenario | [Contributing](../../CONTRIBUTING.md) covers test setup. [Acceptance](../acceptance/README.md) covers isolated hosted fixtures and representative user checks. |
| Configure the authorized hosted deployment | [Hosted guide](../../hosted/README.md) covers provisioning, reverse proxy settings, bank consent, backup and restore. |
| Report a vulnerability privately | [Security policy](../../SECURITY.md). |

Keep the full tenant volume with its corresponding backup. Protect secrets and backups
separately from engineering artifacts. Restore into the matching tenant only.
A contribution, branch check or acceptance run uses temporary roots and synthetic data.
Deployments, host access, production data changes and provider setup require separate
authorization.
