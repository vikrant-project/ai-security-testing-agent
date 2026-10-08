# Configure once and start a run

Edit `targets.json`, keeping `schema_version` at 1. Unknown keys and malformed types are rejected so misspelled scope or permission settings cannot silently take effect. Relative `output_root` paths resolve beside the configuration file. Artifact/source paths must be absolute. Python helpers use only the standard library.

## Authorization and accounts

Set `authorization.confirmed` to `true` only when the owner has authorized the declared systems, and put that declaration in `authorization.statement`. Optional `expires_utc` is a UTC ISO timestamp ending in `Z` or `+00:00`; expired authorization blocks active testing. The template starts unconfigured.

Credentials contain references only:

```json
{"id": "user-a", "role": "normal test user in tenant A", "env_var": "TEST_USER_A_TOKEN"}
```

Place that object in `credentials`, and reference its ID in relevant targets. The agent reads the variable only when needed and must not print it. Use separate synthetic users for normal-user, second-user/tenant, and administrator comparisons. Missing roles block only checks requiring them.

## Target forms

These objects are examples, not pre-authorized live targets. Replace paths and hosts with actual owner-controlled testing systems. Every target needs a unique lowercase `id`, `environment` (`local`, `test`, or `staging`), and `credential_ids` array, even when empty.

```json
{"id":"app-debug","type":"apk","environment":"test","credential_ids":[],"path":"C:\\test-artifacts\\app-debug.apk"}
```

```json
{"id":"flutter-source","type":"source","environment":"test","credential_ids":[],"path":"C:\\projects\\test-app","framework":"flutter","build_variant":"debug"}
```

Source frameworks: `flutter`, `kotlin`, `java`, `android`, or `native`. Restrict source analysis to the debug variant and relevant shared code. Do not use that declaration to admit an unverified binary. Associate source with APK commit/version where possible and document mismatches.

```json
{"id":"test-phone","type":"android-device","environment":"test","credential_ids":[],"serial":"REPLACE_WITH_ADB_SERIAL","package_id":"com.example.testapp"}
```

The serial is required to avoid selecting the wrong phone. APK install/update is controlled by `allow_apk_install`; an installed release package is declined regardless of that setting.

```json
{"id":"staging-api","type":"api","environment":"staging","credential_ids":["user-a"],"origin":"https://staging.example.test:8443","path_prefixes":["/api"],"identity":{"path":"/api/health","contains":"staging-test-environment"}}
```

Use type `web` for browser targets with the same fields. An origin is exactly scheme, hostname, and port; do not put a path, token, or query in it. Prefix `/api` permits `/api` and `/api/...`, never `/api-admin`. The identity endpoint must fall within the allowlist. Choose a stable non-secret environment marker and compare the actual response before testing; a substring alone is not ownership proof. Ambiguous encodings and path normalization are conservatively refused. Declare a separate target for each additional origin.

```json
{"id":"ubuntu-staging","type":"server","environment":"staging","credential_ids":["ssh-test"],"host":"staging.example.test","port":22,"identity":"Verify the known host key and documented staging hostname"}
```

Add a credential reference for `ssh-test` and enable `allow_ssh_inspection`. Verify the known SSH host key; do not turn off host verification. Server configuration changes remain outside this skill's scope.

## Execution commands

On Windows use `py -3`; elsewhere use your Python 3 executable. From the skill folder:

```powershell
py -3 scripts/testing_support.py validate-config --config targets.json
py -3 scripts/testing_support.py init --config targets.json
```

`validate-config` exit 0 means structurally valid configuration with a current owner declaration and targets. It does not verify debug status, credentials, reachability, environment identity, or tool availability. Exit 3 means valid configuration with missing/expired authorization or no targets; exit 2 means invalid configuration.

`init` creates a run even for valid blocked configuration so the owner receives a useful report. Exit 0 means setup created; exit 3 means globally blocked. Per-target prerequisites appear in `evidence/preflight.json` and `state.json`; independent targets can proceed. Neither command makes network requests, executes ADB, or runs a security scanner.

Before an HTTP request, optionally check its declared URL:

```powershell
py -3 scripts/testing_support.py check-url --config targets.json --target staging-api --url 'https://staging.example.test:8443/api/health'
```

Exit 0 means declared origin/path and current authorization match; exit 2 refuses it. This offline check is not a firewall or environment verification. The agent must still check resolved hosts, redirects, identity, and budgets. Do not pass secret query parameters to this command.

At each evidence checkpoint, redact files first, then index and verify:

```powershell
py -3 scripts/testing_support.py seal --run 'runs/ACTUAL_RUN_ID'
py -3 scripts/testing_support.py verify-run --run 'runs/ACTUAL_RUN_ID'
```

Sealing replaces the index with hashes of current evidence. Use it after intentionally adding/redacting evidence; do not re-seal unexpected changes to hide verification failures. Hashes detect changes relative to the index, not malicious changes to both files and index. Preserve previous evidence/index snapshots when required.

Run regression checks without targets, devices, or network access:

```powershell
py -3 -m unittest discover -s scripts -p 'test_*.py' -v
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Test-GateBehavior.ps1
```

Integration tests use a simulated manifest tool and synthetic APK in a temporary directory. They validate decisions and evidence persistence; they do not substitute for real APK testing with the Android SDK.
