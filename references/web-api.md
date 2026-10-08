# Local/private website, API, and server workflow

## Establish the environment

Read the exact origins, path prefixes, environment identity evidence, account roles, and credential references from the goal's `targets.json`. Check a documented health/version endpoint or server configuration for the intended staging identity before active tests. A screenshot of curl output can guide reproduction but is not executable evidence, ownership proof, or a substitute for the original response.

Keep redirects disabled until each destination is checked against scope. Resolve names and ensure configured hosts match the declared environment; recheck after redirects or DNS changes. Permit the explicitly configured staging service even if it has a public address, without expanding scope to adjacent infrastructure.

Use native `curl.exe` on Windows to avoid PowerShell's historical curl alias. Keep TLS verification enabled; document an explicitly configured test CA where needed. Use bounded timeouts and the run-wide budget. Never place passwords, tokens, or cookies in command arguments, screenshots, shell history, or captured verbose logs; use protected temporary configuration/header files or secret-store injection and remove them afterward.

## Practical tests

- Map documented routes, UI flows, API schemas and roles, then compare anonymous, normal test user, second tenant/user, and administrator behavior. Use accounts and objects created for this run.
- Confirm authorization at the server: switch a synthetic object or property between controlled accounts and compare responses. Status alone is insufficient; inspect the response and resulting state.
- Probe validation with small harmless inputs. For suspected injection, use a non-destructive marker and a control request; avoid filesystem/OS commands or extracting data beyond the synthetic fixture.
- For XSS use a harmless visible marker in the test browser; verify execution context and remove the fixture. Test uploads with benign files and confirm content handling without deploying executable shells.
- Validate sessions, logout/revocation, cookie settings, CSRF protection, CORS, response caching, error handling, and business logic against concrete requirements. A `200` response can contain a denial; a `403` can coexist with an unintended mutation.
- For debug APIs, inspect documented debug routes and ensure they are confined to the declared environment and appropriate roles. Use the same scope and role checks as other APIs; the debug label does not authorize neighboring release/production endpoints.
- For rate/resource controls, favor source and configuration review plus low-volume negative tests. Respect global request limits even when a scanner has its own defaults.

## Server inspection

Only use SSH when enabled and a scoped host plus credential reference are supplied. Prefer read-only service/configuration/log inspection; minimize privileges. Do not change firewall rules, restart services, install agents, alter cloud IAM, or enumerate an entire AWS account. Audit only named services/resources. Do not display full environment files or secret stores in tool output. If shell access is unavailable, continue HTTP checks and mark server internals blocked.

## Request and screenshot proof

For each confirmed issue capture a sanitized request method, allowed URL, non-secret headers, test body, response status, relevant response excerpt, UTC time, account role alias, and resulting state. Keep baseline and test pairs. Use reproducible `curl` examples with `<TOKEN>` placeholders, never actual secrets.

When screenshot capability exists, capture the actual redacted curl result or browser/device state and link it to the textual evidence. Do not generate an image depicting a result that was never observed. Screenshots supplement structured requests and responses; they do not replace them. If unavailable, provide exact reproduction text and label screenshot evidence unavailable.
