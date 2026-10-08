"""Offline run setup, scope checks, and evidence verification. Python 3.9+, stdlib only.

This utility does not perform security tests, contact a host, or authorize a target.
"""
import argparse
import csv
import hashlib
import ipaddress
import json
import math
import re
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit


class ValidationError(ValueError):
    pass


KINDS = {"apk", "source", "android-device", "web", "api", "server"}
STATUSES = {"pending", "passed", "finding", "candidate", "blocked", "not-applicable"}
FIELDS = ["check_id", "target", "workstream", "check", "status", "reason", "evidence"]
SETTING_KEYS = {
    "output_root", "request_budget", "requests_per_second", "concurrency",
    "request_timeout_seconds", "max_retries", "allow_apk_install",
    "allow_instrumentation", "allow_root_tests", "allow_ssh_inspection",
    "allow_synthetic_mutations",
}
TARGET_FIELDS = {
    "apk": {"path"},
    "source": {"path", "framework", "build_variant"},
    "android-device": {"serial", "package_id"},
    "web": {"origin", "path_prefixes", "identity"},
    "api": {"origin", "path_prefixes", "identity"},
    "server": {"host", "port", "identity"},
}
# Starting checks, not a full security catalog. The agent must expand these for the app.
CHECKS = {
    "apk": [(1, "debug-gate"), (2, "manifest-components"), (3, "dependency-review"),
            (5, "storage-crypto-privacy"), (6, "network-session-trust")],
    "source": [(1, "source-build-scope"), (3, "source-trust-boundaries"),
               (3, "dependency-review"), (5, "secrets-storage-crypto")],
    "android-device": [(1, "device-package-debug-gate"), (7, "happy-negative-flows"),
                       (7, "lifecycle-offline-permissions"), (7, "crash-anr-review")],
    "web": [(1, "environment-identity"), (8, "role-access-control"),
            (8, "input-output-validation"), (8, "browser-session-controls"),
            (8, "functional-regressions")],
    "api": [(1, "environment-identity"), (9, "object-property-function-authorization"),
            (9, "tenant-isolation"), (9, "validation-business-logic"),
            (9, "resource-controls-review")],
    "server": [(1, "environment-identity"), (10, "scoped-read-only-configuration")],
}


def now_utc():
    return datetime.now(timezone.utc)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def load_json(path):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValidationError("Duplicate JSON key: " + key)
            result[key] = value
        return result
    def invalid_number(value):
        raise ValidationError("Non-finite JSON number: " + value)
    with Path(path).open(encoding="utf-8-sig") as stream:
        return json.load(stream, object_pairs_hook=unique_pairs, parse_constant=invalid_number)


def write_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def text(value):
    return isinstance(value, str) and bool(value.strip())


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def safe_path(value):
    require(isinstance(value, str) and value.startswith("/"), "URL paths must begin with /.")
    require(not any(ord(c) < 33 or ord(c) == 127 for c in value), "Unsafe URL whitespace/control.")
    # Decode repeatedly to reject nested encoding rather than guessing server normalization.
    decoded = value
    for _ in range(6):
        require(not re.search(r"%(?![0-9a-fA-F]{2})", decoded), "Malformed path encoding.")
        require(not re.search(r"%(?:2f|5c)", decoded, re.I), "Encoded path separators are ambiguous.")
        next_value = unquote(decoded, errors="strict")
        if next_value == decoded:
            break
        decoded = next_value
    require("%" not in decoded, "Unresolved nested path encoding.")
    require(not any(ord(c) < 33 or ord(c) == 127 for c in decoded), "Decoded path contains controls.")
    require(not any(c in decoded for c in "\\;?#"), "Ambiguous path delimiter.")
    require("//" not in decoded, "Repeated path separators are ambiguous.")
    require(all(part not in {".", ".."} for part in decoded.split("/")), "Dot segments are out of scope.")
    return decoded


def url_parts(value, origin_only=False):
    require(text(value), "URL must be a nonempty string.")
    require(not any(ord(c) < 33 or ord(c) == 127 for c in value), "URL contains whitespace/control.")
    require("\\" not in value, "URL backslashes are ambiguous.")
    parsed = urlsplit(value)
    require(parsed.scheme in {"http", "https"} and bool(parsed.hostname), "Only explicit HTTP(S) origins are supported.")
    require(parsed.username is None and parsed.password is None, "Credentials in URLs are forbidden.")
    require(not parsed.fragment, "URL fragments are not request scope.")
    host = parsed.hostname
    require("%" not in host and not host.endswith("."), "Ambiguous host spelling.")
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        host = host.encode("idna").decode("ascii").lower()
        require(all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in host.split(".")), "Invalid hostname.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    require(1 <= port <= 65535, "Invalid URL port.")
    path = safe_path(parsed.path or "/")
    if origin_only:
        require(path == "/" and not parsed.query, "Origin must not contain a path or query.")
    return (parsed.scheme, host, port), path


def url_allowed(target, value):
    try:
        candidate_origin, candidate_path = url_parts(value)
        allowed_origin, _ = url_parts(target["origin"], origin_only=True)
        if candidate_origin != allowed_origin:
            return False
        for prefix in target["path_prefixes"]:
            normalized = safe_path(prefix).rstrip("/") or "/"
            if normalized == "/" or candidate_path == normalized or candidate_path.startswith(normalized + "/"):
                return True
        return False
    except (ValueError, KeyError, TypeError, UnicodeError):
        return False


def validate_config(config):
    require(isinstance(config, dict), "Configuration must be an object.")
    require(set(config) == {"schema_version", "authorization", "targets", "credentials", "settings"}, "Unexpected or missing top-level configuration keys.")
    require(type(config["schema_version"]) is int and config["schema_version"] == 1, "Unsupported schema_version.")
    auth = config["authorization"]
    require(isinstance(auth, dict) and set(auth) == {"confirmed", "statement", "expires_utc"}, "Invalid authorization fields.")
    require(type(auth["confirmed"]) is bool and isinstance(auth["statement"], str), "Invalid authorization declaration.")
    if auth["confirmed"]:
        require(text(auth["statement"]), "Confirmed authorization requires an owner statement.")
    if auth["expires_utc"] is not None:
        require(text(auth["expires_utc"]), "Expiry must be an ISO UTC timestamp.")
        expires = datetime.fromisoformat(auth["expires_utc"].replace("Z", "+00:00"))
        require(expires.tzinfo is not None and expires.utcoffset().total_seconds() == 0, "Expiry must include UTC timezone.")
    settings = config["settings"]
    require(isinstance(settings, dict) and set(settings) == SETTING_KEYS, "Unexpected or missing settings keys.")
    require(text(settings["output_root"]), "output_root is required.")
    for key in ("request_budget", "request_timeout_seconds"):
        require(integer(settings[key], 1), key + " must be a positive integer.")
    require(integer(settings["max_retries"]) and settings["max_retries"] <= 1, "max_retries must be 0 or 1.")
    require(type(settings["concurrency"]) is int and settings["concurrency"] == 1, "This workflow uses concurrency 1.")
    rate = settings["requests_per_second"]
    require(type(rate) in {int, float} and math.isfinite(rate) and 0 < rate <= 1, "requests_per_second must be greater than 0 and at most 1.")
    for key in SETTING_KEYS:
        if key.startswith("allow_"):
            require(type(settings[key]) is bool, key + " must be boolean.")
    credentials = config["credentials"]
    require(isinstance(credentials, list), "credentials must be a list.")
    credential_ids = set()
    for cred in credentials:
        require(isinstance(cred, dict) and set(cred) == {"id", "role", "env_var"}, "Use credential role and env_var references only.")
        require(text(cred["id"]) and cred["id"] not in credential_ids and text(cred["role"]), "Credential IDs must be unique and roles nonempty.")
        require(isinstance(cred["env_var"], str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", cred["env_var"]), "Invalid credential environment-variable name.")
        credential_ids.add(cred["id"])
    require(isinstance(config["targets"], list), "targets must be a list.")
    ids = set()
    for target in config["targets"]:
        require(isinstance(target, dict), "Each target must be an object.")
        kind = target.get("type")
        require(isinstance(kind, str) and kind in KINDS, "Unknown target type.")
        allowed = {"id", "type", "environment", "credential_ids"} | TARGET_FIELDS[kind]
        require(set(target) == allowed, "Unexpected or missing fields for " + kind + " target.")
        require(isinstance(target["id"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", target["id"]) and target["id"] not in ids, "Target IDs must be unique lowercase identifiers.")
        ids.add(target["id"])
        require(target["environment"] in {"local", "test", "staging"}, "Only local/test/staging environments qualify.")
        refs = target["credential_ids"]
        require(isinstance(refs, list) and all(isinstance(ref, str) and ref in credential_ids for ref in refs), "Target references an unknown credential.")
        if kind in {"apk", "source"}:
            require(text(target["path"]) and Path(target["path"]).is_absolute(), "Artifact/source paths must be absolute.")
        if kind == "source":
            require(target["framework"] in {"flutter", "kotlin", "java", "android", "native"}, "Unsupported source framework.")
            require(target["build_variant"] == "debug", "Source assessment must be scoped to the debug variant.")
        if kind == "android-device":
            require(text(target["serial"]) and not re.search(r"\s", target["serial"]), "An explicit ADB serial is required.")
            require(isinstance(target["package_id"], str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", target["package_id"]), "Invalid Android package ID.")
        if kind in {"web", "api"}:
            url_parts(target["origin"], origin_only=True)
            require(isinstance(target["path_prefixes"], list) and bool(target["path_prefixes"]), "Declare at least one path prefix.")
            for prefix in target["path_prefixes"]:
                safe_path(prefix)
            identity = target["identity"]
            require(isinstance(identity, dict) and set(identity) == {"path", "contains"} and text(identity["contains"]), "Identity requires path and a non-secret expected marker.")
            safe_path(identity["path"])
            require(url_allowed(target, target["origin"].rstrip("/") + identity["path"]), "Identity endpoint must be within declared path scope.")
        if kind == "server":
            require(text(target["host"]), "Server host is required.")
            require(integer(target["port"], 1) and target["port"] <= 65535, "Invalid SSH port.")
            url_parts("https://" + ("[" + target["host"] + "]" if ":" in target["host"] else target["host"]), origin_only=True)
            require(text(target["identity"]), "Server identity evidence description is required.")
    return config


def authorization_blockers(config):
    blockers = []
    if not config["authorization"]["confirmed"]:
        blockers.append("Owner authorization is not configured; no active testing is admitted.")
    expiry = config["authorization"]["expires_utc"]
    if expiry and datetime.fromisoformat(expiry.replace("Z", "+00:00")) <= now_utc():
        blockers.append("Owner authorization has expired.")
    if not config["targets"]:
        blockers.append("No targets configured.")
    return blockers


def initialize(config_path):
    config_path = Path(config_path).resolve()
    config = validate_config(load_json(config_path))
    blockers = authorization_blockers(config)
    output = Path(config["settings"]["output_root"])
    if not output.is_absolute():
        output = config_path.parent / output
    run_id = now_utc().strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    run = output.resolve() / run_id
    run.mkdir(parents=True, exist_ok=False)
    (run / "evidence").mkdir()
    # Snapshot references only: validate_config excludes literal credentials.
    write_json(run / "scope.json", config)
    tool_names = ["adb", "apkanalyzer", "aapt2", "jadx", "apktool", "flutter", "java", "curl"]
    preflight = {
        "created_utc": now_utc().isoformat(),
        "tools": {name: shutil.which(name) for name in tool_names},
        "targets": [],
        "blockers": blockers.copy(),
        "network_contacted": False,
        "note": "Tool paths only; no device, network, application, or tool binary was executed.",
    }
    hashes = {}
    rows = []
    for target in config["targets"]:
        kind = target["type"]
        target_blockers = blockers.copy()
        item = {"id": target["id"], "type": kind, "blockers": target_blockers}
        if kind in {"apk", "source"}:
            path = Path(target["path"])
            exists = path.is_file() if kind == "apk" else path.is_dir()
            if not exists:
                target_blockers.append("Declared artifact/source path is missing or has the wrong type.")
            elif kind == "apk":
                hashes[target["id"]] = {"path": str(path), "sha256": digest(path)}
                if not preflight["tools"]["apkanalyzer"]:
                    target_blockers.append("apkanalyzer is not on PATH; supply its SDK executable path to the APK gate.")
        if kind == "android-device" and not preflight["tools"]["adb"]:
            target_blockers.append("adb is not on PATH; supply its SDK executable path before device work.")
        if kind == "server" and not config["settings"]["allow_ssh_inspection"]:
            target_blockers.append("SSH inspection is disabled.")
        preflight["targets"].append(item)
        checks = list(CHECKS[kind])
        if kind == "source" and target["framework"] == "flutter":
            checks.append((4, "dart-plugins-platform-channels"))
        checks.append((10, "evidence-cleanup-retest"))
        for workstream, check in checks:
            rows.append({"check_id": target["id"] + ":" + check, "target": target["id"],
                         "workstream": str(workstream), "check": check,
                         "status": "blocked" if target_blockers else "pending",
                         "reason": "; ".join(target_blockers) if target_blockers else "Not executed; expand the starter plan before testing.",
                         "evidence": ""})
    write_json(run / "evidence" / "preflight.json", preflight)
    write_json(run / "findings.json", {"schema_version": 1, "confirmed": [], "candidates": []})
    with (run / "coverage.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    all_blockers = blockers + [t["id"] + ": " + b for t in preflight["targets"] for b in t["blockers"] if b not in blockers]
    state = {
        "schema_version": 1, "run_id": run_id, "updated_utc": now_utc().isoformat(),
        "status": "blocked" if blockers else "in-progress",
        "scope_sha256": digest(run / "scope.json"), "scope_summary": [t["id"] for t in config["targets"]],
        "artifact_hashes": hashes, "apk_gates": {}, "completed_checks": [],
        "pending_checks": [r["check_id"] for r in rows], "request_count": 0,
        "blockers": all_blockers, "temporary_changes": [],
        "resume_instructions": "Verify scope hash, authorization, artifact hashes, and target identity. Recheck blocked prerequisites; expand coverage and execute only admitted targets.",
    }
    write_json(run / "state.json", state)
    (run / "report.md").write_text(
        "# Assessment report\n\nResult: " + ("BLOCKED" if blockers else "NOT EXECUTED") +
        "\n\nThis run contains offline setup only. No security checks or active requests have been performed.\n\n" +
        "## Prerequisites\n\n" + ("\n".join("- " + b for b in all_blockers) or "Complete environment identity and APK gates before testing.") +
        "\n\n## Findings\n\nNo confirmed findings have been recorded. This is not evidence of security.\n", encoding="utf-8")
    seal(run)
    return run, bool(blockers)


def evidence_file(run, relative):
    require(text(relative) and "\\" not in relative, "Evidence references use nonempty forward-slash paths.")
    value = Path(relative)
    require(not value.is_absolute() and value.parts and value.parts[0] == "evidence", "Evidence must be under evidence/.")
    require(".." not in value.parts, "Evidence path traversal is forbidden.")
    run = Path(run).resolve()
    current = run
    for part in value.parts:
        current = current / part
        require(not current.is_symlink(), "Evidence symlinks are forbidden.")
        if hasattr(current, "is_junction"):
            require(not current.is_junction(), "Evidence junctions are forbidden.")
    resolved = current.resolve()
    require(run in resolved.parents and resolved.is_file(), "Evidence file is missing or outside the run.")
    return resolved


def seal(run):
    run = Path(run).resolve()
    require((run / "evidence").is_dir(), "Missing evidence directory.")
    require(not (run / "evidence").is_symlink(), "Evidence directory cannot be a symlink.")
    entries = {}
    for path in sorted((run / "evidence").rglob("*")):
        require(not path.is_symlink(), "Evidence symlinks are forbidden.")
        if path.is_file():
            relative = path.relative_to(run).as_posix()
            verified = evidence_file(run, relative)
            entries[relative] = {"sha256": digest(verified), "bytes": verified.stat().st_size}
    write_json(run / "evidence-index.json", {"schema_version": 1, "created_utc": now_utc().isoformat(), "files": entries})
    return len(entries)


def verify_run(run):
    run = Path(run).resolve()
    config = validate_config(load_json(run / "scope.json"))
    state = load_json(run / "state.json")
    require(state.get("scope_sha256") == digest(run / "scope.json"), "Scope changed; start a new run or explicitly invalidate affected checks.")
    require(state.get("status") in {"blocked", "in-progress", "incomplete", "completed"}, "Invalid run status.")
    require(integer(state.get("request_count")), "Invalid request_count.")
    require(state["request_count"] <= config["settings"]["request_budget"], "Request budget exceeded.")
    targets = {t["id"] for t in config["targets"]}
    index = load_json(run / "evidence-index.json")
    require(isinstance(index.get("files"), dict), "Missing evidence index.")
    for relative, entry in index["files"].items():
        path = evidence_file(run, relative)
        require(entry.get("sha256") == digest(path) and entry.get("bytes") == path.stat().st_size, "Evidence integrity mismatch: " + relative)

    def references(refs, required=False):
        require(isinstance(refs, list) and all(text(r) for r in refs), "Evidence references must be a list of paths.")
        require(not required or bool(refs), "Executed checks and findings require evidence.")
        for ref in refs:
            evidence_file(run, ref)
            require(ref in index["files"], "Evidence is not indexed: " + ref)

    findings = load_json(run / "findings.json")
    require(isinstance(findings.get("confirmed"), list) and isinstance(findings.get("candidates"), list), "Findings arrays are required.")
    finding_ids = set()
    for collection in ("confirmed", "candidates"):
        for finding in findings[collection]:
            require(isinstance(finding, dict) and text(finding.get("id")), "Each finding needs an ID.")
            require(finding["id"] not in finding_ids, "Duplicate finding ID.")
            finding_ids.add(finding["id"])
            require(finding.get("target") in targets, "Finding references undeclared target.")
            require(finding.get("severity") in {"critical", "high", "medium", "low", "informational"}, "Invalid finding severity.")
            for key in ("title", "confidence", "category", "expected", "actual", "impact", "remediation"):
                require(text(finding.get(key)), "Finding requires " + key + ".")
            for key in ("preconditions", "steps", "retest"):
                require(isinstance(finding.get(key), list) and bool(finding[key]) and all(text(x) for x in finding[key]), "Finding requires nonempty " + key + " steps.")
            references(finding.get("evidence"), required=True)
    with (run / "coverage.csv").open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        require(reader.fieldnames == FIELDS, "Invalid coverage columns.")
        rows = list(reader)
    ids = set()
    for row in rows:
        require(text(row["check_id"]) and row["check_id"] not in ids, "Duplicate or empty coverage check ID.")
        ids.add(row["check_id"])
        require(row["target"] in targets and row["status"] in STATUSES, "Unknown coverage target/status.")
        require(row["workstream"] in {str(i) for i in range(1, 11)}, "Invalid workstream.")
        require(text(row["reason"]) and text(row["check"]), "Coverage requires check and reason.")
        references([r for r in row["evidence"].split(";") if r], required=row["status"] in {"passed", "finding", "candidate"})
    for target in targets:
        require(any(row["target"] == target for row in rows), "Target has no coverage rows: " + target)
    for target in config["targets"]:
        if target["type"] not in {"apk", "android-device"}:
            continue
        executed = any(r["target"] == target["id"] and r["status"] in {"passed", "finding", "candidate"} for r in rows)
        if not executed:
            continue
        gate_ref = state.get("apk_gates", {}).get(target["id"])
        references([gate_ref] if gate_ref else [], required=True)
        gate = load_json(evidence_file(run, gate_ref))
        require(gate.get("admitted") is True and gate.get("classification") == "debug", "Executed APK checks require an admitted debug gate.")
        artifact = state.get("artifact_hashes", {}).get(target["id"], {})
        require(text(artifact.get("sha256")) and artifact["sha256"].lower() == str(gate.get("sha256", "")).lower(), "APK gate does not match the tracked artifact hash.")
        require(text(artifact.get("path")) and Path(artifact["path"]).is_file() and digest(artifact["path"]) == artifact["sha256"].lower(), "Tracked APK changed or is unavailable; re-gate before continuing.")
    pending = state.get("pending_checks")
    completed = state.get("completed_checks")
    require(isinstance(pending, list) and isinstance(completed, list), "Missing state check lists.")
    unresolved = {r["check_id"] for r in rows if r["status"] in {"pending", "blocked"}}
    resolved = ids - unresolved
    require(len(pending) == len(set(pending)) and set(pending) == unresolved, "Pending state does not match coverage.")
    require(len(completed) == len(set(completed)) and set(completed) == resolved, "Completed state does not match coverage.")
    if state["status"] == "completed":
        require(bool(rows) and not unresolved, "Completed runs cannot have empty coverage or unresolved checks.")
        require(not authorization_blockers(config), "Completed run lacks valid authorization or targets.")
        require(not state.get("temporary_changes"), "Completed run has unclosed temporary changes.")
    require((run / "report.md").is_file(), "Missing report.md.")
    return {"valid": True, "status": state["status"], "coverage_rows": len(rows), "confirmed_findings": len(findings["confirmed"]), "evidence_files": len(index["files"]),
            "note": "Structural and file-integrity validation only; this does not validate exploitability or guarantee security."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("validate-config", "init"):
        child = sub.add_parser(command)
        child.add_argument("--config", required=True)
    child = sub.add_parser("check-url")
    child.add_argument("--config", required=True)
    child.add_argument("--target", required=True)
    child.add_argument("--url", required=True, help="Never include credentials or sensitive query values.")
    for command in ("seal", "verify-run"):
        child = sub.add_parser(command)
        child.add_argument("--run", required=True)
    args = parser.parse_args()
    try:
        if args.command == "validate-config":
            config = validate_config(load_json(args.config))
            blockers = authorization_blockers(config)
            print(json.dumps({"valid": True, "ready_for_preflight": not blockers, "blockers": blockers}, indent=2))
            return 3 if blockers else 0
        if args.command == "init":
            run, blocked = initialize(args.config)
            print(json.dumps({"run": str(run), "status": "blocked" if blocked else "in-progress", "active_testing_performed": False}, indent=2))
            return 3 if blocked else 0
        if args.command == "check-url":
            config = validate_config(load_json(args.config))
            blockers = authorization_blockers(config)
            target = next((t for t in config["targets"] if t["id"] == args.target and t["type"] in {"web", "api"}), None)
            allowed = not blockers and target is not None and url_allowed(target, args.url)
            print(json.dumps({"allowed_by_declaration": bool(allowed), "identity_verified": False, "blockers": blockers}))
            return 0 if allowed else 2
        if args.command == "seal":
            print(json.dumps({"evidence_files": seal(args.run)}))
        else:
            print(json.dumps(verify_run(args.run), indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(json.dumps({"valid": False, "error": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
