#!/usr/bin/env python3
"""ML2 checks for Regular Backups control."""

import argparse
import json
import os
from datetime import datetime, timedelta


def load(path):
    with open(path, "r") as f:
        return json.load(f)


def parse_ts(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", ""))
    except Exception:
        return None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="folder containing backup-jobs.json, coverage-audit.json, restore-test.json")
    args = p.parse_args()

    jobs = load(os.path.join(args.input, "backup-jobs.json"))
    coverage = load(os.path.join(args.input, "coverage-audit.json"))
    restore = load(os.path.join(args.input, "restore-test.json"))
    access = load(os.path.join(args.input, "access-control.json")) if os.path.exists(os.path.join(args.input, "access-control.json")) else {}

    total = len(jobs.get("jobs", []))
    success = len([j for j in jobs.get("jobs", []) if j.get("status") == "success"])
    job_success_pct = round((success / total * 100), 2) if total else 0

    restore_ts = parse_ts(restore.get("generatedAt", ""))
    restore_recent = bool(restore_ts and restore_ts >= datetime.now() - timedelta(days=31))

    checks = [
        {
            "id": "ml2-backup-01",
            "name": "Backups performed and retained",
            "status": "pass" if job_success_pct >= 80 else "fail",
            "evidence": f"Job success rate {job_success_pct}% ({success}/{total})",
        },
        {
            "id": "ml2-backup-02",
            "name": "Restore tests executed",
            "status": "pass" if restore.get("status") == "success" and restore_recent else "fail",
            "evidence": f"Restore status={restore.get('status')} recent_31d={restore_recent}",
        },
        {
            "id": "ml2-backup-03",
            "name": "Coverage gaps tracked",
            "status": "pass" if coverage.get("coveragePct", 0) >= 95 else "warn",
            "evidence": f"Coverage {coverage.get('coveragePct', 0)}% ({coverage.get('protectedAssets',0)}/{coverage.get('totalAssets',0)})",
        },
        {
            "id": "ml2-backup-04",
            "name": "Backup access restrictions reviewed",
            "status": "pass" if (access.get("unprivilegedModifyAccessDetected") is False and len(access.get("nonBackupPrivilegedWithModifyAccess", [])) == 0) else "fail",
            "evidence": f"unprivilegedModifyAccessDetected={access.get('unprivilegedModifyAccessDetected')} nonBackupPrivilegedWithModifyAccess={access.get('nonBackupPrivilegedWithModifyAccess', [])}",
        },
    ]

    out = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "checks": checks,
        "overall": "pass" if all(c["status"] in ("pass", "warn") for c in checks) else "fail",
    }

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
