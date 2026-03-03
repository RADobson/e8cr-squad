#!/usr/bin/env python3
"""Generate synthetic demo data for E8CR Application Control bot."""

import os
import json
import random
import argparse
import subprocess
from datetime import datetime, timedelta

COMPANY = "Meridian Civil Group"


def gen_appcontrol():
    policies = [
        {"id": "wdac-001", "name": "WDAC Base Policy - Audit", "isAssigned": True},
        {"id": "wdac-002", "name": "Microsoft Recommended Block Rules", "isAssigned": True},
        {"id": "applocker-001", "name": "Legacy AppLocker Exceptions", "isAssigned": True},
    ]
    return {
        "company": COMPANY,
        "appcontrol_policies_found": len(policies),
        "policies": policies,
        "severity": "P3",
        "escalation_reason": "Policies present and assigned",
    }


def gen_macros():
    policies = [
        {"id": "macro-001", "name": "Block macros from internet", "isAssigned": True},
        {"id": "macro-002", "name": "Allow trusted publishers only", "isAssigned": True},
    ]
    return {
        "company": COMPANY,
        "macro_policies_found": len(policies),
        "policies": policies,
        "severity": "P3",
        "escalation_reason": "Macro policies present and assigned",
    }


def gen_hardening():
    policies = [
        {"id": "hard-001", "name": "Edge security baseline", "isAssigned": True},
        {"id": "hard-002", "name": "Disable Office OLE/ActiveX", "isAssigned": True},
        {"id": "hard-003", "name": "Disable PowerShell 2.0", "isAssigned": True},
    ]
    return {
        "company": COMPANY,
        "hardening_policies_found": len(policies),
        "policies": policies,
        "severity": "P3",
        "escalation_reason": "Hardening policies present and assigned",
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    p.add_argument("--full-pipeline", action="store_true")
    args = p.parse_args()

    os.makedirs(args.output, exist_ok=True)
    with open(os.path.join(args.output, "appcontrol-audit.json"), "w") as f:
        json.dump(gen_appcontrol(), f, indent=2)
    with open(os.path.join(args.output, "macro-audit.json"), "w") as f:
        json.dump(gen_macros(), f, indent=2)
    with open(os.path.join(args.output, "hardening-audit.json"), "w") as f:
        json.dump(gen_hardening(), f, indent=2)

    if args.full_pipeline:
        state_file = os.path.join(args.output, "_state.json")
        subprocess.run([
            "python3", os.path.join(os.path.dirname(__file__), "drift_detect.py"),
            "--current-dir", args.output,
            "--state-file", state_file,
            "--output", os.path.join(args.output, "drift.json"),
        ], check=True)

        report = os.path.join(args.output, "appcontrol-report.html")
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
