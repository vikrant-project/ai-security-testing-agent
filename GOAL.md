# Security Testing Goal

Read `SKILL.md` beside this goal and assess the targets declared in **`targets.json`**. Use its authorization, allowlist, accounts, and execution settings as the single configuration source. All output must be in English. Execute independently within that scope; save state and finish with evidence, coverage, and practical fixes.

## One-time setup

Fill `targets.json` using `references/setup.md`. Set the owner authorization statement, declare actual debug artifacts or staging targets, and reference credentials by environment-variable name. Do not put credential values in this folder. No targets are pre-authorized by the shipped template.

Keep the entire folder together when loading it into another tool-capable agent. Markdown instructions are portable; helpers need Python 3.9+ and the Windows APK gate requires PowerShell and Android SDK `apkanalyzer`.

After configuration, use this goal as the starting instruction. Do not ask for the same configuration again. If a prerequisite is unavailable, continue independent work and report the exact blocked checks.

## Required execution

1. Run the offline initializer in `references/setup.md`. Validate configuration before contacting targets. The initializer creates a unique run directory and a starter check plan; it performs no security testing.
2. Expand `coverage.csv` into concrete checks using `references/coverage.md` and actual attack surfaces. Apply all ten workstreams where relevant and explain inapplicable workstreams. Starter rows are not exhaustive coverage.
3. Verify every APK's packaged debug flag before testing. Verify the installed package separately before ADB interaction. Release builds receive the mandatory decline message.
4. Verify environment identity before web/API tests and check each request's origin and path against configuration. Count requests before sending them and stop at the budget.
5. Gather baseline and negative-test evidence, confirm findings, and record candidates separately. Capture actual screenshots when supported and safe; never fabricate result images.
6. Record temporary changes before making them. Save state after each workstream and reconcile coverage, unresolved checks, request count, and hashes on resume.
7. Redact evidence, index it with the helper, and run `verify-run`. Resolve validation errors and perform the manual review in `references/reporting.md` before declaring completion.

## Ten workstreams

1. Scope, environment identity, tools, and debug classification.
2. Android package, manifest, and exported component security.
3. Kotlin/Java source, native code, dependencies, and supply chain.
4. Flutter/Dart code, platform channels, plugins, and mobile integrations.
5. Storage, privacy, cryptography, logs, and backup exposure.
6. Network transport, authentication, session handling, and backend trust.
7. ADB live app testing, UI flows, runtime bugs, and reproducible crashes.
8. Website/browser security and functional regressions.
9. Debug/staging API authorization, validation, and business logic.
10. Private server inspection, evidence, reporting, cleanup, and retest.

## Deliverables and completion

Produce `report.md`, `findings.json`, `coverage.csv`, `state.json`, `scope.json`, `evidence-index.json`, and `evidence/` inside the run directory. Link to the final report, summarize demonstrated risks and coverage gaps, and identify remaining prerequisites once.

Use `completed` only when every planned check is resolved, authorization is valid, and temporary changes are closed. Use `incomplete` if checks remain blocked after all independent work is exhausted; use `blocked` when execution cannot begin. A completed assessment does not establish absence of every possible vulnerability.

The helpers prepare and check records. The agent must perform the assessment with its available tools; loading this goal does not create a scanner or scheduler.
