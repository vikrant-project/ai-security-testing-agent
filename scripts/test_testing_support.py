"""Behavioral regression tests; all artifacts are isolated in temporary directories."""
import copy
import csv
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import testing_support as support


ROOT = Path(__file__).resolve().parents[1]


class SupportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="testing-agent-tests-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.config = support.load_json(ROOT / "targets.json")
        self.config["settings"]["output_root"] = str(self.base / "runs")

    def website(self):
        return {"id": "staging-web", "type": "web", "environment": "staging", "credential_ids": [],
                "origin": "https://staging.example.test", "path_prefixes": ["/app"],
                "identity": {"path": "/app/health", "contains": "test-environment"}}

    def configured(self):
        self.config["authorization"] = {"confirmed": True, "statement": "I own the declared test fixture.", "expires_utc": None}
        self.config["targets"] = [self.website()]
        return self.config

    def init_run(self, configured=True):
        if configured:
            self.configured()
        path = self.base / "targets.json"
        support.write_json(path, self.config)
        return support.initialize(path)

    def test_empty_configuration_is_valid_but_blocked(self):
        support.validate_config(self.config)
        run, blocked = self.init_run(configured=False)
        self.assertTrue(blocked)
        self.assertEqual(support.verify_run(run)["status"], "blocked")
        self.assertEqual(support.load_json(run / "findings.json")["confirmed"], [])

    def test_setup_never_marks_unexecuted_checks_passed(self):
        run, blocked = self.init_run()
        self.assertFalse(blocked)
        result = support.verify_run(run)
        self.assertEqual(result["status"], "in-progress")
        self.assertGreater(result["coverage_rows"], 0)
        with (run / "coverage.csv").open(newline="", encoding="utf-8") as stream:
            self.assertTrue(all(row["status"] == "pending" for row in csv.DictReader(stream)))
        self.assertFalse(support.load_json(run / "evidence/preflight.json")["network_contacted"])

    def test_scope_accepts_only_exact_origin_and_path_boundary(self):
        target = self.website()
        for url in ["https://staging.example.test/app", "https://STAGING.example.test:443/app/a?x=1", "https://staging.example.test/app/a%20b"]:
            with self.subTest(url=url):
                # Encoded whitespace is conservatively refused, even if some servers accept it.
                self.assertEqual(support.url_allowed(target, url), "%20" not in url)
        for url in ["https://staging.example.test/application", "https://staging.example.test/app-evil",
                    "http://staging.example.test/app", "https://staging.example.test:8443/app",
                    "https://evil.example.test/app", "https://staging.example.test.evil.test/app",
                    "https://user:secret@staging.example.test/app", "https://staging.example.test./app",
                    "https://staging.example.test/app#fragment"]:
            with self.subTest(url=url):
                self.assertFalse(support.url_allowed(target, url))

    def test_scope_rejects_ambiguous_path_normalization(self):
        for suffix in ["/../admin", "/%2e%2e/admin", "/%252e%252e/admin", "/a%2fb", "/a%252fb",
                       "/a%5cb", "//admin", "/x;ignored", "/%00", "/%zz", "/x\\admin", "/./x"]:
            with self.subTest(suffix=suffix):
                self.assertFalse(support.url_allowed(self.website(), self.website()["origin"] + "/app" + suffix))

    def test_ipv6_and_default_ports_are_canonical(self):
        target = self.website()
        target["origin"] = "http://[::1]:8080"
        self.assertTrue(support.url_allowed(target, "http://[0:0:0:0:0:0:0:1]:8080/app/a"))
        self.assertFalse(support.url_allowed(target, "http://[::1]:8081/app/a"))

    def test_config_rejects_mistakes_and_scope_expansion(self):
        base = self.configured()
        modifications = [
            lambda c: c.update({"password": "literal-secret"}),
            lambda c: c["settings"].update({"request_budget": True}),
            lambda c: c["settings"].update({"requests_per_second": 2}),
            lambda c: c["settings"].update({"allow_instrumentation": "false"}),
            lambda c: c["targets"][0].update({"environment": "production"}),
            lambda c: c["targets"][0].update({"credential_ids": ["unknown"]}),
            lambda c: c["targets"][0]["identity"].update({"path": "/outside/health"}),
            lambda c: c["authorization"].update({"statement": ""}),
            lambda c: c["targets"].append(copy.deepcopy(c["targets"][0])),
        ]
        for modify in modifications:
            current = copy.deepcopy(base)
            modify(current)
            with self.subTest(config=current), self.assertRaises(support.ValidationError):
                support.validate_config(current)

    def test_expired_authorization_blocks_url_command(self):
        self.configured()["authorization"]["expires_utc"] = "2000-01-01T00:00:00Z"
        config_path = self.base / "expired.json"
        support.write_json(config_path, self.config)
        import sys
        result = subprocess.run([sys.executable, str(ROOT / "scripts/testing_support.py"), "check-url", "--config", str(config_path),
                                 "--target", "staging-web", "--url", "https://staging.example.test/app"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(json.loads(result.stdout)["allowed_by_declaration"])

    def test_duplicate_json_keys_rejected(self):
        path = self.base / "duplicate.json"
        path.write_text('{"confirmed":false,"confirmed":true}', encoding="utf-8")
        with self.assertRaises(support.ValidationError):
            support.load_json(path)

    def test_evidence_tampering_is_detected(self):
        run, _ = self.init_run()
        path = run / "evidence" / "observed.txt"
        path.write_text("observed baseline", encoding="utf-8")
        support.seal(run)
        support.verify_run(run)
        path.write_text("changed baseline", encoding="utf-8")
        with self.assertRaisesRegex(support.ValidationError, "integrity mismatch"):
            support.verify_run(run)

    def test_evidence_cannot_escape_run(self):
        run, _ = self.init_run()
        for relative in ["../secret.txt", "evidence/../../secret.txt", "C:/secret.txt", "evidence\\secret.txt", "evidence/missing.txt"]:
            with self.subTest(relative=relative), self.assertRaises(support.ValidationError):
                support.evidence_file(run, relative)

    def test_evidence_symlinks_rejected_when_supported(self):
        run, _ = self.init_run()
        outside = self.base / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        try:
            (run / "evidence" / "linked.txt").symlink_to(outside)
        except OSError:
            self.skipTest("Host does not permit creation of symlinks.")
        with self.assertRaises(support.ValidationError):
            support.seal(run)

    def test_scope_change_invalidates_run(self):
        run, _ = self.init_run()
        scope = support.load_json(run / "scope.json")
        scope["targets"][0]["path_prefixes"] = ["/"]
        support.write_json(run / "scope.json", scope)
        with self.assertRaisesRegex(support.ValidationError, "Scope changed"):
            support.verify_run(run)

    def test_request_budget_and_false_completion_rejected(self):
        run, _ = self.init_run()
        state = support.load_json(run / "state.json")
        state["request_count"] = 301
        support.write_json(run / "state.json", state)
        with self.assertRaisesRegex(support.ValidationError, "budget exceeded"):
            support.verify_run(run)
        state["request_count"] = 0
        state["status"] = "completed"
        support.write_json(run / "state.json", state)
        with self.assertRaisesRegex(support.ValidationError, "unresolved"):
            support.verify_run(run)

    def test_executed_apk_checks_require_matching_debug_gate(self):
        self.configured()
        artifact = self.base / "app.apk"
        artifact.write_bytes(b"synthetic-verification-fixture")
        self.config["targets"] = [{"id": "test-apk", "type": "apk", "environment": "test", "credential_ids": [], "path": str(artifact)}]
        run, _ = self.init_run(configured=False)
        with (run / "coverage.csv").open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        first = rows[0]
        first.update(status="passed", reason="Simulated verification fixture", evidence="evidence/gate.json")
        with (run / "coverage.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=support.FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        state = support.load_json(run / "state.json")
        state["pending_checks"].remove(first["check_id"])
        state["completed_checks"].append(first["check_id"])
        state["apk_gates"]["test-apk"] = "evidence/gate.json"
        support.write_json(run / "state.json", state)
        gate = {"admitted": False, "classification": "non-debug", "sha256": support.digest(artifact)}
        support.write_json(run / "evidence/gate.json", gate)
        support.seal(run)
        with self.assertRaisesRegex(support.ValidationError, "admitted debug gate"):
            support.verify_run(run)
        gate.update(admitted=True, classification="debug", sha256="0" * 64)
        support.write_json(run / "evidence/gate.json", gate)
        support.seal(run)
        with self.assertRaisesRegex(support.ValidationError, "tracked artifact hash"):
            support.verify_run(run)
        gate["sha256"] = support.digest(artifact)
        support.write_json(run / "evidence/gate.json", gate)
        support.seal(run)
        support.verify_run(run)
        artifact.write_bytes(b"new-build")
        with self.assertRaisesRegex(support.ValidationError, "APK changed"):
            support.verify_run(run)

    def test_confirmed_finding_needs_reproduction_evidence(self):
        run, _ = self.init_run()
        finding = {"id": "F-001", "target": "staging-web", "severity": "low",
                   "title": "Synthetic fixture issue", "confidence": "high", "category": "fixture",
                   "expected": "expected", "actual": "actual", "impact": "test impact", "remediation": "fix",
                   "preconditions": ["fixture"], "steps": ["reproduce"], "retest": ["retest"], "evidence": []}
        support.write_json(run / "findings.json", {"confirmed": [finding], "candidates": []})
        with self.assertRaisesRegex(support.ValidationError, "require evidence"):
            support.verify_run(run)
        (run / "evidence" / "fixture.txt").write_text("Test evidence", encoding="utf-8")
        finding["evidence"] = ["evidence/fixture.txt"]
        support.write_json(run / "findings.json", {"confirmed": [finding], "candidates": []})
        with self.assertRaisesRegex(support.ValidationError, "not indexed"):
            support.verify_run(run)
        support.seal(run)
        self.assertEqual(support.verify_run(run)["confirmed_findings"], 1)


@unittest.skipUnless(os.name == "nt" and shutil.which("powershell"), "Windows PowerShell integration fixture")
class GateIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="apk-gate-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.apk = self.base / "fixture.apk"
        # This is a simulated tool response, not a real APK security assessment.
        self.apk.write_bytes(b"synthetic-gate-fixture")
        self.tool = self.base / "simulated-apkanalyzer.cmd"
        self.tool.write_text('@echo off\r\ntype "%~dp0manifest.xml"\r\nexit /b 0\r\n', encoding="ascii")

    def invoke(self, flag, output="gate.json", tool=None):
        xml = '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application' + flag + ' /></manifest>'
        (self.base / "manifest.xml").write_text(xml, encoding="utf-8")
        return subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                               str(ROOT / "scripts/Test-DebugApk.ps1"), "-ApkPath", str(self.apk),
                               "-ApkAnalyzer", str(tool or self.tool), "-OutputPath", str(self.base / output)], capture_output=True, text=True, timeout=30)

    def test_gate_exit_codes_and_persisted_admission(self):
        for flag, code, classification in [(' android:debuggable="true"', 0, "debug"),
                                            (' android:debuggable="false"', 2, "non-debug"),
                                            ('', 2, "non-debug"),
                                            (' android:debuggable="@bool/unknown"', 3, "unknown")]:
            with self.subTest(flag=flag):
                output = classification + str(code) + str(len(flag)) + ".json"
                result = self.invoke(flag, output)
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                record = support.load_json(self.base / output)
                self.assertEqual(record["classification"], classification)
                self.assertEqual(record["admitted"], code == 0)
                self.assertEqual(record["sha256"].lower(), support.digest(self.apk))

    def test_tool_error_blocks_without_overwriting_evidence(self):
        result = self.invoke(' android:debuggable="true"', tool=self.base / "absent.cmd")
        self.assertEqual(result.returncode, 3)
        record = support.load_json(self.base / "gate.json")
        self.assertFalse(record["admitted"])
        before = (self.base / "gate.json").read_bytes()
        result = self.invoke(' android:debuggable="true"')
        self.assertEqual(result.returncode, 3)
        self.assertEqual((self.base / "gate.json").read_bytes(), before)

    def test_output_cannot_overwrite_input(self):
        before = self.apk.read_bytes()
        result = self.invoke(' android:debuggable="true"', output="fixture.apk")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(self.apk.read_bytes(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
