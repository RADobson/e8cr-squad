#!/usr/bin/env python3
"""Coverage gap audit: compare asset inventory vs protected set."""

import argparse
import json
from datetime import datetime


def read_json(path):
    with open(path, "r") as f:
        return json.load(f)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--assets", required=True, help="JSON list of assets (id/name)")
    p.add_argument("--protected", required=True, help="JSON list of protected asset IDs")
    args = p.parse_args()

    assets = read_json(args.assets)
    protected = set(read_json(args.protected))

    uncovered = [a for a in assets if str(a.get("id")) not in protected]

    out = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "totalAssets": len(assets),
        "protectedAssets": len(assets) - len(uncovered),
        "coveragePct": round(((len(assets) - len(uncovered)) / len(assets) * 100.0), 2) if assets else 0,
        "uncovered": uncovered,
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
