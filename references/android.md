# Debug Android and ADB workflow

## Artifact gate and static analysis

On Windows run:

```powershell
& ./scripts/Test-DebugApk.ps1 -ApkPath 'C:\test-artifacts\app.apk' -ApkAnalyzer 'C:\Android\Sdk\cmdline-tools\latest\bin\apkanalyzer.bat' -OutputPath './runs/<run>/evidence/apk-gate.json'
```

Use actual discovered paths. Exit 0 plus `admitted: true` admits testing; 2 declines non-debug; 3 blocks unknown or tool errors. Inspect the record, and do not treat stdout text alone as success. Bind downstream work to the recorded SHA-256 and rehash before use. Use a unique output filename: gate evidence must not overwrite an existing file. The gate checks the packaged flag, not developer intent or backend environment.

If a local Windows execution policy prevents running this reviewed script, invoke it in a child process with `powershell -NoProfile -ExecutionPolicy Bypass -File <script-path>` and the same parameters. This applies only to that process; do not change the machine or user execution policy. Managed policy restrictions may still block execution; report that limitation.

After admission, use available tools such as jadx, apktool, Android SDK tools, dependency analysis, and source search. Record missing tools rather than install arbitrary binaries or execute the app's build scripts without inspecting them. Extraction output must stay under the run directory. Cross-reference decompiled output with supplied source and version; decompiler artifacts are not authoritative source semantics.

For split installs, inventory and hash every installed package part. Verify the base APK's manifest and reject inconsistent package/version parts; do not treat a split without the application flag as an independent admitted base. Analyze only parts tied to the admitted base and record that relationship.

## Installed app and phone control

1. Inventory `adb devices -l`. Select the declared serial, and pass `adb -s <serial>` to every device operation. If multiple devices exist and no serial is supplied, block device tests while continuing static tests.
2. Confirm the declared package with package-manager metadata and `pm path <package>`. Retrieving installed APK files for hash/manifest classification is allowed before the gate; app execution or analysis is not. Pull the installed base and split APKs into the run evidence directory and gate the base. A supplied APK does not prove the installed app is the same build.
3. If the installed package is non-debug, use the exact decline message from `SKILL.md`. Do not uninstall it or replace it automatically. Installation requires the goal setting; package IDs/signatures and upgrade behavior must match the intended target.
4. Restrict UI input, launching activities, logs, screenshots, permission experiments, test intents, and app data access to the admitted package and its test flows. Never navigate personal apps, scrape unrelated files, or use personal accounts. Stop a flow before an out-of-scope external app or host.
5. Use available UI automation (for example UIAutomator/Appium) or ADB input plus actual screen/UI observations. Never guess tap coordinates. Capture a baseline, perform the flow, and record expected/actual behavior. Test login/logout, role transitions, forms, navigation, lifecycle, offline behavior, duplicate submissions, and malformed input where relevant.
6. Limit logcat evidence to the app process and relevant crash records; redact identifiers and tokens. `run-as` can inspect synthetic test data only after admission. Root-only checks remain blocked if the declared device lacks an already-authorized capability.
7. Where instrumentation is enabled, distinguish observations made after instrumentation from behavior of the unmodified debug app. A modified client bypassing a local check is not proof that the server accepted an unauthorized operation.
8. Record and restore temporary app settings, permissions, proxy settings, and device forwarding. Do not clear all app data, kill unrelated processes, or reset the device for convenience.

Screenshots can contain account information, notifications, and keyboard content. Use a dedicated test device and redact before placing images in the report. If the agent cannot safely capture or redact images, report that evidence limitation and retain a safe text reproduction.
