#!/usr/bin/env python3
"""Generate synthetic demo data for E8CR Backup bot."""

import os
import json
import argparse
import subprocess
from datetime import datetime

from adapters import veeam_fetch_jobs_sample, azure_fetch_jobs_sample, normalize_jobs


def gen_jobs():
    return {
        "generatedAt": datetime.now().isoformat() + "Z",
        "jobs": normalize_jobs(veeam_fetch_jobs_sample()) + normalize_jobs(azure_fetch_jobs_sample()),
    }


def gen_coverage():
    assets = [
        {"id": "srv-001", "name": "FS01"},
        {"id": "srv-002", "name": "SQL01"},
        {"id": "srv-003", "name": "APP01"},
        {"id": "srv-004", "name": "AAD-CONFIG"},
    ]
    protected = {"srv-001", "srv-002", "srv-004"}
    uncovered = [a for a in assets if a["id"] not in protected]
    return {
        "generatedAt": datetime.now().isoformat() + "Z",
        "totalAssets": len(assets),
        "protectedAssets": len(assets) - len(uncovered),
        "coveragePct": round(((len(assets) - len(uncovered)) / len(assets) * 100), 2),
        "uncovered": uncovered,
    }


def gen_restore():
    return {
        "generatedAt": datetime.now().isoformat() + "Z",
        "target": "Finance Share",
        "sourceBackup": "daily-2026-03-01T00:15:00Z",
        "restoreDestination": "/restore-sandbox/finance-share",
        "timeToRestoreMin": 14,
        "integrityCheck": "passed",
        "checksumVerified": True,
        "status": "success",
        "notes": "Automated monthly restore drill",
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    p.add_argument("--full-pipeline", action="store_true")
    args = p.parse_args()

    os.makedirs(args.output, exist_ok=True)
    with open(os.path.join(args.output, "backup-jobs.json"), "w") as f:
        json.dump(gen_jobs(), f, indent=2)
    with open(os.path.join(args.output, "coverage-audit.json"), "w") as f:
        json.dump(gen_coverage(), f, indent=2)
    with open(os.path.join(args.output, "restore-test.json"), "w") as f:
        json.dump(gen_restore(), f, indent=2)

    # run access-control audit and persist output
    access_raw = subprocess.check_output([
        "python3", os.path.join(os.path.dirname(__file__), "access_control_audit.py"),
    ], text=True)
    with open(os.path.join(args.output, "access-control.json"), "w") as f:
        f.write(access_raw)

    # run ML2 checks and persist output
    ml2_raw = subprocess.check_output([
        "python3", os.path.join(os.path.dirname(__file__), "ml2_checks.py"),
        "--input", args.output,
    ], text=True)
    with open(os.path.join(args.output, "ml2-checks.json"), "w") as f:
        f.write(ml2_raw)

    if args.full_pipeline:
        report = os.path.join(args.output, "backup-report.html")
        subprocess.run([
            "python3", os.path.join(os.path.dirname(__file__), "generate_report.py"),
            "--input", args.output,
            "--output", report,
        ], check=True)
        print(report)
    else:
        print(args.output)


if __name__ == "__main__":
    main()
