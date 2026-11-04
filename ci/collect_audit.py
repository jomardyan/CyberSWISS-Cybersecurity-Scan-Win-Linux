"""Collect audit findings without treating scanner execution failures as success."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from utils import expected_exit_code  # noqa: E402


def validate_report(report, returncode):
    """Accept only the documented findings protocol, never a crashed scanner."""
    if not isinstance(report, dict):
        raise ValueError("Audit output must be a JSON object")
    results = report.get("results") if report.get("cyberswiss_report") else [report]
    if not isinstance(results, list) or not results:
        raise ValueError("Audit output contains no script results")
    findings = []
    for result in results:
        if not isinstance(result, dict) or result.get("error"):
            raise ValueError(f"Scanner execution error: {result}")
        if result.get("fix_report", {}).get("verification_error"):
            raise ValueError("Fix verification failed")
        if not isinstance(result.get("findings"), list):
            raise ValueError("Scanner did not emit a findings array")
        for finding in result["findings"]:
            if not isinstance(finding, dict) or finding.get("status") not in {"PASS", "WARN", "FAIL", "INFO"}:
                raise ValueError("Scanner emitted an invalid finding")
            findings.append(finding)
    expected = expected_exit_code(findings)
    if returncode != expected:
        raise ValueError(f"Unexpected audit exit code {returncode}; findings require {expected}")
    if report.get("error_count", 0):
        raise ValueError("Audit report contains execution errors")
    return findings


def main():
    destination, separator, *command = sys.argv[1:]
    if separator != "--" or not command:
        raise ValueError("Usage: collect_audit.py OUTPUT.json -- COMMAND [ARGS]")
    completed = subprocess.run(command, capture_output=True, text=True, timeout=900, check=False)
    if completed.stderr:
        print(completed.stderr, file=sys.stderr, end="")
    report = json.loads(completed.stdout)
    findings = validate_report(report, completed.returncode)
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    counts = {status: sum(item["status"] == status for item in findings)
              for status in ("PASS", "WARN", "FAIL", "INFO")}
    print(f"Audit execution verified; host findings (not software errors): {counts}. Report: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
