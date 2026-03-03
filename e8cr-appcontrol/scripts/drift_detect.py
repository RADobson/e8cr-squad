#!/usr/bin/env python3
import argparse
import json
import os
from datetime import datetime, timezone


def _load(path, default):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)


def _snapshot(cur_dir):
    files = ["appcontrol-audit.json", "macro-audit.json", "hardening-audit.json"]
    profiles = {}
    exceptions = []
    for fn in files:
        data = _load(os.path.join(cur_dir, fn), {})
        for p in data.get("policies", []):
            pid = p.get("id") or p.get("name")
            if not pid:
                continue
            profiles[pid] = {
                "name": p.get("name", ""),
                "isAssigned": bool(p.get("isAssigned", False)),
            }
            txt = f"{p.get('name','')} {p.get('description','')}".lower()
            if any(k in txt for k in ["exception", "exclude", "exclusion", "allow all"]):
                exceptions.append(p.get("name", pid))
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "profiles": profiles, "exceptions": sorted(set(exceptions))}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--current-dir", required=True)
    p.add_argument("--state-file", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    current = _snapshot(args.current_dir)
    prev = _load(args.state_file, {"profiles": {}, "exceptions": []})

    cur_ids = set(current["profiles"].keys())
    prev_ids = set(prev.get("profiles", {}).keys())

    profiles_deleted = sorted(prev_ids - cur_ids)
    assignment_changes = []
    for pid in sorted(cur_ids & prev_ids):
        if current["profiles"][pid].get("isAssigned") != prev["profiles"][pid].get("isAssigned"):
            assignment_changes.append(pid)

    new_ex = sorted(set(current.get("exceptions", [])) - set(prev.get("exceptions", [])))

    sev = "P3"
    reason = "No material drift detected"
    if profiles_deleted:
        sev, reason = "P1", "Critical app-control profile deletion detected"
    elif assignment_changes or new_ex:
        sev, reason = "P2", "Assignment or exception drift detected"

    out = {
        "has_drift": bool(profiles_deleted or assignment_changes or new_ex),
        "severity": sev,
        "escalation_reason": reason,
        "summary": {
            "profiles_deleted": profiles_deleted,
            "assignment_changes": assignment_changes,
            "new_exclusions_or_exceptions": new_ex,
        },
        "current_snapshot": current,
    }

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(out, f, indent=2)

    os.makedirs(os.path.dirname(args.state_file) or ".", exist_ok=True)
    with open(args.state_file, "w") as f:
        json.dump(current, f, indent=2)

    print(json.dumps({"status": "ok", "drift": out["has_drift"], "severity": sev}))


if __name__ == "__main__":
    main()
