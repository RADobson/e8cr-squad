#!/usr/bin/env python3
"""Create a signed evidence pack manifest for an evidence directory.

Signature mode:
- HMAC-SHA256 over canonical manifest JSON using E8CR_SIGNING_KEY env var.
- If key missing, writes signatureMode="none" and no signature file.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(input_dir: Path, period: str) -> Dict:
    files: List[Dict] = []
    for p in sorted(input_dir.rglob("*")):
        if not p.is_file():
            continue
        if p.name in {"manifest.json", "manifest.sig"}:
            continue
        rel = str(p.relative_to(input_dir))
        files.append(
            {
                "path": rel,
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
            }
        )

    return {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "period": period,
        "fileCount": len(files),
        "files": files,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", required=True)
    ap.add_argument("--period", choices=["daily", "weekly"], required=True)
    ap.add_argument("--manifest", default="manifest.json")
    ap.add_argument("--signature", default="manifest.sig")
    args = ap.parse_args()

    input_dir = Path(args.input_dir)
    input_dir.mkdir(parents=True, exist_ok=True)

    manifest = build_manifest(input_dir, period=args.period)

    key = os.getenv("E8CR_SIGNING_KEY", "")
    if key:
        payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        manifest["signatureMode"] = "hmac-sha256"
        manifest["signatureFile"] = args.signature
        (input_dir / args.signature).write_text(sig)
    else:
        manifest["signatureMode"] = "none"
        manifest["signatureFile"] = None

    (input_dir / args.manifest).write_text(json.dumps(manifest, indent=2))
    print(json.dumps({"status": "ok", "manifest": str(input_dir / args.manifest), "signatureMode": manifest["signatureMode"]}))


if __name__ == "__main__":
    main()
