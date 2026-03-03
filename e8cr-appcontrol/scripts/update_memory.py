#!/usr/bin/env python3
import argparse
import json
import os
from datetime import datetime


def _load(path, default):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--memory", required=True)
    p.add_argument("--drift", required=True)
    p.add_argument("--evidence-dir", required=True)
    args = p.parse_args()

    drift = _load(args.drift, {"summary": {}, "severity": "P3", "escalation_reason": "No drift file"})
    app = _load(os.path.join(args.evidence_dir, "appcontrol-audit.json"), {})
    mac = _load(os.path.join(args.evidence_dir, "macro-audit.json"), {})
    hard = _load(os.path.join(args.evidence_dir, "hardening-audit.json"), {})

    stamp = datetime.now().strftime("%Y-%m-%d %H:%M AEST")
    section = f"""
### {stamp} — Automated cycle update
- Severity: {drift.get('severity','P3')}
- Escalation reason: {drift.get('escalation_reason','')}
- Policy counts:
  - AppControl: {app.get('appcontrol_policies_found', 0)}
  - Macros: {mac.get('macro_policies_found', 0)}
  - Hardening: {hard.get('hardening_policies_found', 0)}
- Drift summary:
  - Profiles deleted: {', '.join(drift.get('summary',{}).get('profiles_deleted', [])) or 'none'}
  - Assignment changes: {', '.join(drift.get('summary',{}).get('assignment_changes', [])) or 'none'}
  - New exceptions/exclusions: {', '.join(drift.get('summary',{}).get('new_exclusions_or_exceptions', [])) or 'none'}
"""

    with open(args.memory, "a") as f:
        f.write("\n" + section + "\n")

    print(json.dumps({"status": "ok", "memory": args.memory}))


if __name__ == "__main__":
    main()
