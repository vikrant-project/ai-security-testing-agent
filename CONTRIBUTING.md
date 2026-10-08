# Contributing

Help make the skill easier to run and its results easier to trust. Contributions should preserve debug-only APK admission, owner-declared scope, reversible test fixtures, and explicit evidence for findings.

## Good contributions

- A reproducible bug in configuration, scope matching, evidence validation, or the APK gate.
- A concrete coverage check with applicability, expected behavior, required capabilities, and minimal evidence.
- A clearer setup example that uses synthetic accounts and placeholder hosts.
- A tested portability improvement or regression check.

## Before a pull request

1. Explain the concrete failure or missing behavior, with a minimal redacted reproduction.
2. Keep product changes separate from testing instructions and update affected documentation.
3. Run `python -m unittest discover -s scripts -p "test_*.py" -v`.
4. On Windows, run `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Test-GateBehavior.ps1`.
5. Keep tests offline and isolated in temporary directories. Do not contact real targets in CI.
6. Check every new instruction/link and label simulated results clearly.

Do not commit tokens, private keys, personal APKs, populated target configurations, or unredacted assessment evidence. Generated run directories and local publication helpers are ignored. For security-sensitive issues, see [SECURITY.md](SECURITY.md).
