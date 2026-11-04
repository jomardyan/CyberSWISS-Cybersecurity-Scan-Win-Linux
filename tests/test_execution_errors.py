"""Regression checks for operational errors previously hidden by CI."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "common"))
import runner  # noqa: E402
from utils import run_script  # noqa: E402

spec = importlib.util.spec_from_file_location("ci_collector", ROOT / "ci/collect_audit.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def test_script_crash_after_valid_json_remains_an_error(tmp_path):
    script = tmp_path / "audit.sh"
    script.write_text("fixture")
    reply = subprocess.CompletedProcess([], 127, stdout='{"findings": []}', stderr="missing tool")
    with patch("utils.subprocess.run", return_value=reply):
        result = run_script(str(script))
    assert "error" in result
    assert result["exit_code"] == 127


@pytest.mark.parametrize("stdout", ["bad JSON", '{}', '{"findings": "not an array"}'])
def test_malformed_json_is_not_a_clean_scan(tmp_path, stdout):
    script = tmp_path / "audit.sh"
    script.write_text("fixture")
    with patch("utils.subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout, "")):
        result = run_script(str(script))
    assert "error" in result


@pytest.mark.parametrize("status,code", [("PASS", 0), ("WARN", 1), ("FAIL", 2)])
def test_collector_accepts_real_finding_exit_protocol(status, code):
    findings = [{"id": "fixture", "status": status}]
    assert collector.validate_report({"findings": findings}, code) == findings


@pytest.mark.parametrize("report,code", [
    ({"findings": []}, 127),
    ({"error": "timeout", "findings": []}, 0),
    ({"cyberswiss_report": True, "results": []}, 0),
    ({"findings": [{"status": "FAIL"}]}, 0),
])
def test_collector_rejects_broken_or_missing_scans(report, code):
    with pytest.raises(ValueError):
        collector.validate_report(report, code)


def test_runner_does_not_return_success_for_a_timed_out_script(capsys):
    metadata = {"id": "L10", "path": "fixture.sh", "os": "linux"}
    error = {"script": "L10", "findings": [], "error": "Script timed out", "exit_code": -2}
    with patch.object(sys, "argv", ["runner.py", "--json"]):
        with patch.object(runner, "select_scripts", return_value=[metadata]):
            with patch.object(runner, "run_script", return_value=error):
                code = runner.main()
    report = json.loads(capsys.readouterr().out)
    assert code == 3
    assert report["error_count"] == 1


@pytest.mark.skipif(sys.platform == "win32", reason="Real Bash filesystem metadata check runs on Linux CI")
def test_l10_single_pass_finds_world_writable_and_suid_files(tmp_path):
    ordinary = tmp_path / 'unsafe "file"'
    ordinary.write_text("fixture")
    ordinary.chmod(0o666)
    suid = tmp_path / "unexpected-suid"
    suid.write_text("fixture")
    suid.chmod(0o4755)
    directory = tmp_path / "unsafe-dir"
    directory.mkdir()
    directory.chmod(0o777)
    completed = subprocess.run(["bash", str(ROOT / "linux/L10_file_permissions.sh"),
                                "--json", "--root", str(tmp_path)],
                               capture_output=True, text=True, timeout=15, check=False)
    report = json.loads(completed.stdout)
    findings = {finding["id"]: finding for finding in report["findings"]}
    assert completed.returncode == 2
    assert findings["L10-C1"]["status"] == "WARN"
    assert str(suid) in findings["L10-C1"]["detail"]
    assert findings["L10-C3"]["status"] == "FAIL"
    assert str(ordinary) in findings["L10-C3"]["detail"]
    assert findings["L10-C4"]["status"] == "FAIL"
    assert str(directory) in findings["L10-C4"]["detail"]
