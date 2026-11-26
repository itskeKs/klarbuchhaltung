# Acceptance from the user's side

Walk the [core journeys](journeys.md) through the running product using the synthetic
sample world and the stated expected results. An independent reviewer sees only the
product, the sample data and the journeys. Record success or failure for each step in the
PR or milestone issue. Keep credentials, local paths and personal data out of the evidence.

Use a disposable local gateway and two tenant ledgers for hosted checks. Provide the stub
bank client for journeys covering consent and sync. The setup in
[tests/test_hosted.py](../../tests/test_hosted.py) shows the fixtures and can be used for
automated checks. A browser run needs a local HTTPS gateway and a stub configured
with the journey's sample world. The pytest fixture supplies its own separate scenarios.
Product data and real banking credentials belong outside acceptance runs.

## Writing a user check

- State what the user wants to do, then give the actions in their words.
- Give observable, independently calculated amounts or states. Name the reporting period
  and calculation basis when they matter.
- The reviewer walks the journey against the PR state. Use the owner for steps requiring
  owner access.
- Name views that should also be checked at 360 px. Include desktop width and 360 px
  screenshots for a changed view.

Keep journeys and expected values current where the owner has agreed on a behavior
change. For a confirmed finding, add a failing scenario in the existing
[pytest suite](../../features/README.md) before the fix. The automated scenario provides
regression evidence and the browser walkthrough verifies how the user reaches the result.
