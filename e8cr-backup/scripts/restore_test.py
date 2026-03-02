#!/usr/bin/env python3
"""Restore test simulator for backup evidence pipeline."""

import argparse
import json
import random
from datetime import datetime


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["simulate"], default="simulate")
    p.add_argument("--target", default="Finance Share")
    args = p.parse_args()

    ok = random.random() > 0.2
    out = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "target": args.target,
        "sourceBackup": "daily-2026-03-01T00:15:00Z",
        "restoreDestination": "/restore-sandbox/" + args.target.lower().replace(" ", "-"),
        "timeToRestoreMin": random.randint(6, 27),
        "integrityCheck": "passed" if ok else "failed",
        "checksumVerified": ok,
        "status": "success" if ok else "failed",
        "notes": "Automated monthly restore drill",
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
