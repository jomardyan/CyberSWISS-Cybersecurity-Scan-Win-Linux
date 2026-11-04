# `ci/` — Pipeline Inputs

This directory holds inputs consumed by the CI pipeline. The workflow itself
lives at [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), which is
where GitHub Actions looks for it.

## `ci/baseline.json` (optional)

The accepted-risk baseline for the `baseline-gate` job. When present, findings
waived in it no longer fail the build, so the gate only breaks on genuinely new
risk. It is not committed by default — create it once the current findings have
been reviewed and signed off:

```bash
python3 common/runner.py --os linux --write-baseline ci/baseline.json
```

Then edit each entry to record the real justification, an owner, and an expiry
date before committing. See
[Baselines & Accepted Risk](../README.md#baselines--accepted-risk) for the file
format and matching rules.

## Execution checks and host findings

The Linux smoke/integration jobs collect valid audit JSON and verify the documented
exit code (0 passes, 1 warnings, 2 findings). Host configuration findings remain
visible in artifacts and summaries; they do not mean the software failed. Invalid
JSON, timeouts, script errors, unexpected exits, lint failures and report generation
errors fail CI. The orchestrator uses exit 3 for execution failures. No baseline
waivers are generated automatically. With a committed baseline, the strict baseline
gate retains its existing finding exit policy.

L10 now classifies permission checks in one filesystem traversal instead of five.
`bash linux/L10_file_permissions.sh --json --root DIRECTORY` scopes the filesystem
inventory for container/fixture checks; the default remains `/`. Scoped inventories
are read-only; system account-file checks still refer to `/etc`. Unreadable paths
are explicitly reported as incomplete coverage. The orchestration reporting tests
use controlled scanner results so the full Python suite runs on Linux and Windows;
Linux integration still executes the real audit scripts read-only.

Command-line output preserves the active console encoding and escapes unsupported
characters, so older Windows code pages and redirected output cannot crash banner,
trend or drift commands. JSON report files remain UTF-8.
