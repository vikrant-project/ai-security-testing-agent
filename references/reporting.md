# Evidence, state, and reports

Create one run directory under the configured output root. Record UTC timestamps and tool versions; explain times in the user's timezone only when requested. Keep secrets out of all persisted outputs. Use stable target aliases and finding IDs.

`coverage.csv` columns: `check_id,target,workstream,check,status,reason,evidence`. Use a proper CSV writer, not string concatenation. Separate evidence paths with semicolons in the evidence cell. Use forward-slash paths relative to the run, starting with `evidence/`. A passed row requires an actual check and observed expected result; unexecuted checks must never pass. Use `pending` only for unfinished rows; resolve them before completion.

`findings.json` is an object with `schema_version: 1`, `confirmed`, and `candidates` arrays. Each finding includes `id`, `title`, `target`, `severity`, `confidence`, `category`, `preconditions`, `steps`, `expected`, `actual`, `impact`, `evidence`, `remediation`, and `retest`. Use severity `critical`, `high`, `medium`, `low`, or `informational`. Preconditions, steps, and retest are nonempty arrays of strings; evidence is a nonempty array of indexed file paths. Cite exact source locations when available. Severity follows demonstrated impact and prerequisites; do not assign numeric CVSS without its vector and justification. Store no raw secrets.

`state.json` contains `schema_version`, `run_id`, `updated_utc`, `status`, `scope_sha256`, `scope_summary`, `artifact_hashes`, `apk_gates`, `completed_checks`, `pending_checks`, `request_count`, `blockers`, `temporary_changes`, and `resume_instructions`. Follow `references/execution.md` for consistency. On resume verify unchanged target identity and hashes; invalidate checks affected by new artifacts or configuration. Preserve prior evidence; do not assume a prior session's tokens still work.

`report.md` includes:

1. Result: completed assessment or incomplete/blocked, with scope and artifact identifiers.
2. Confirmed findings ordered by impact, each with reproducible steps, redacted evidence links, fix, and retest.
3. Unconfirmed candidates separated from confirmed results.
4. Coverage totals and explicit exclusions/blockers, including declined release APKs.
5. Cleanup performed and any remaining temporary changes.
6. Practical next actions and an honest statement that tested coverage does not establish absence of all vulnerabilities.

Debuggable mode, a debug signing key, and debug symbols are expected properties of the allowed test build. Report downstream security effects only when a concrete requirement or boundary is violated, and explain which results are specific to debug builds.

Stop a check when the minimum proof is established. Stop active testing on scope mismatch, unexpected production data, repeated instability, budget exhaustion, or expired authorization. Save available findings and continue only independent work still within scope. Do not silently retry a blocked check forever.

## Final review

After redaction, run `seal` and `verify-run` using the commands in `references/setup.md`. The verifier checks indexed file hashes, evidence paths, APK gate/hash relationships for executed Android checks, request counts, coverage/state consistency, required finding fields, and completion prerequisites. It does not execute reproductions, prove exploitability, enforce runtime networking, detect every secret, or judge report quality.

Manually confirm that every finding has an observed baseline and changed-condition test, the report agrees with structured outputs, debug-only observations are labeled, candidates are not presented as confirmed, blocked checks have concrete reasons, and evidence contains no passwords, tokens, private keys, personal data, or unrelated device content. Link each confirmed finding to a corresponding coverage row with status `finding`; link candidates to `candidate` rows. Keep all ten workstreams accounted for, including reasons for those inapplicable to the configured target types.
