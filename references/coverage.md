# Coverage planner

Expand the following into target-specific checks. Each concrete check must have a result: `passed`, `finding`, `candidate`, `blocked`, or `not-applicable`. A workstream title alone is not a test. Record the version/date of guidance used and avoid claims of exhaustive coverage.

| Workstream | Checks to consider | Useful evidence |
| --- | --- | --- |
| 1. Preconditions | Authorization, identity, allowlist, APK hash/debug gate, installed artifact match, tool/device capabilities | Gate JSON, identity response, tool versions |
| 2. Android package | Permissions, exported activities/services/receivers/providers, intents, URI grants, deep links, app links, WebViews, JavaScript bridges, file loading, install/signature assumptions | Manifest location plus minimal test-component reproduction |
| 3. Source and supply chain | Kotlin/Java nullability and exception paths, injection sinks, trust decisions, JNI/native memory boundaries, unsafe deserialization, dependency advisories, build configuration, bundled secrets | Source locations, locked version, advisory prerequisites, reproduction |
| 4. Flutter | Dart storage and logging, assets, platform channels, plugin permissions, WebViews, deep links, certificate validation, debug service exposure, build mode, state/navigation and async lifecycle | Source/plugin paths and observed app behavior |
| 5. Data protection | Preferences, SQLite, caches, files, backups, screenshots, clipboard, logs, keys, algorithms, IV/nonces, randomness, keystore behavior, privacy minimization | Synthetic marker trace and redacted output |
| 6. Network and identity | TLS validation, cleartext, pinning if required, token storage/expiry/refresh/revocation, logout, session fixation, replay, OAuth redirect/state/PKCE, client-side trust decisions | Paired baseline/negative request and expected result |
| 7. Device runtime | Happy/negative UI flows, validation, rotation, background/resume, process death, connectivity loss, interrupted requests, rapid taps, navigation, permission denial, crashes/ANRs, accessibility | App-scoped UI steps, log excerpt, screenshot, replay |
| 8. Browser | Access control, XSS, CSRF, injection, traversal, uploads, redirects, CORS, cookie attributes, CSP, caching, clickjacking, session handling, frontend secrets, error handling and accessibility | Test account, harmless marker, browser capture/request |
| 9. API | Object/property/function authorization, authentication, tenant isolation, mass assignment, schema/type validation, resource bounds, sensitive workflows, SSRF, inventory/version drift, downstream response trust, GraphQL/WebSocket where present | Two controlled account roles, synthetic object, paired requests |
| 10. Server and closure | Service exposure, test/prod separation, SSH/TLS settings, file permissions, logs, secret handling, cloud IAM/configuration when scoped, patch versions, cleanup and retest | Read-only configuration excerpts with identifiers redacted |

For resource exhaustion and rate limiting, inspect code/configuration and use bounded requests within the goal budget; do not generate load to demonstrate an outage. For SSRF, use a declared controlled callback endpoint; do not query metadata services or internal ranges beyond scope. Missing headers, outdated versions, exported components, or absent pinning are not automatically exploitable findings.

Authoritative starting points (checked October 8, 2026; refresh as needed):
- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [OWASP MASTG tests](https://mas.owasp.org/MASTG/tests/)
- [OWASP debug mechanism guidance](https://mas.owasp.org/MASWE-0063/)
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
