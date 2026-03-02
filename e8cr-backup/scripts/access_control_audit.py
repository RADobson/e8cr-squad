#!/usr/bin/env python3
"""Backup access control evidence stub (provider-agnostic input)."""

import argparse
import json
from datetime import datetime


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", help="Optional JSON file with IAM findings")
    args = p.parse_args()

    if args.input:
        with open(args.input, "r") as f:
            out = json.load(f)
        print(json.dumps(out, indent=2))
        return

    # synthetic baseline posture
    out = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "backupAdmins": ["svc-backup-admin"],
        "mfaEnforced": True,
        "nonBackupPrivilegedWithModifyAccess": ["global-admin-01"],
        "unprivilegedModifyAccessDetected": False,
        "notes": "global-admin-01 should be removed from backup modify scope",
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
