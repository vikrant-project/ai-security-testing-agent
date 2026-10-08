# Planning, checkpoints, and regression

## Turn a goal into concrete tests

Begin with offline preflight; PATH discovery does not prove working tooling. Resolve Android SDK locations from local installations without executing arbitrary downloaded tools. Block an individual target when prerequisites are missing and continue others.

After admission, map actual screens, components, roles, data objects, operations, plugins, and trust boundaries. Expand starter rows into individual check IDs such as `staging-api:tenant-isolation:invoice-read`. Derive expected behavior from requirements, schemas, server enforcement, or defensible security properties; do not invent product requirements. Workstream 4 can be inapplicable to Kotlin-only targets; device checks remain blocked if the phone is unavailable.

Prioritize role/tenant boundaries, sensitive storage/transport, reachable components, and demonstrated source-to-sink paths. Broader checks follow within configured budgets. Vulnerable dependencies require exact shipped versions and applicability analysis, not name matching.

For each suspected issue:

1. Record target version/hash, account role, fixture, and expected result.
2. Capture a normal baseline and change one relevant condition.
3. Record the actual response/state and smallest demonstrated impact.
4. Repeat once under the same conditions when safe. If not reproducible, retain a candidate and explain uncertainty.
5. Trace the likely cause where source exists and recommend a fix to the violated boundary.
6. Add a negative regression check and normal-flow check to show the fix preserves expected behavior.

Do not modify application source unless the user also requests fixes. Source-level recommendations and regression steps can be delivered without committing product changes.

## Bookkeeping before side effects

Budgets accumulate across accounts, targets, retries, resumes, and identity probes. Increment and persist `request_count` before dispatch, so interruptions do not lose usage. A reserved unsent request may conservatively remain counted. Serialize writes; use temporary files plus atomic replacement.

For browser/device traffic, count requests through available routing/proxy/network instrumentation without weakening TLS globally. If traffic cannot be bounded, block active network-dependent checks while continuing offline work. Never reset the budget on resume. Expired authorization, scope mismatch, or changed environment immediately blocks affected work.

Before a temporary setting/data change, append target, prior value, intended change, reason, and cleanup action to `temporary_changes`. Close only after observing restoration, archive cleanup evidence, and remove from the unresolved list. Report failed cleanup; do not claim completion while it remains unresolved.

## State consistency and resume

Use `pending_checks` for all `pending` and `blocked` coverage rows, and `completed_checks` for `passed`, `finding`, `candidate`, or `not-applicable` rows. IDs must match coverage exactly. Never mark a blocked check inapplicable just to obtain completion.

For each admitted APK or installed package record:

- `artifact_hashes[target_id]`: `path` and `sha256` of the verified base APK.
- `apk_gates[target_id]`: relative path to its gate JSON under `evidence/`.
- Package/version, device serial, split hashes, source revision, and SDK details in accompanying evidence.

Keep the verified APK available for resume/verification and rehash before reusing a gate. Changed APKs invalidate their gates. Verify installed package identity independently; supplied APK hashes do not prove an installed match.

On resume, run `verify-run`, compare current configuration with `scope.json`, check expiry, and confirm target/device identity. A changed scope starts a new run unless the owner explicitly requests continuation and affected checks are invalidated with documented reasons. Never edit a scope snapshot/hash merely to suppress a failure.

Retests after fixes use new runs and hashes linked to original finding IDs. Report `fixed`, `still-reproducible`, or `unable-to-retest` for each issue; unavailable environments do not prove fixes.
