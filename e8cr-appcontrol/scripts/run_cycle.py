#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
SHARED_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "shared"))


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return {"cmd": " ".join(cmd), "returncode": r.returncode, "stdout": r.stdout[-500:], "stderr": r.stderr[-500:]}


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)


def save_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--period", choices=["daily", "weekly"], required=True)
    p.add_argument("--demo", action="store_true", help="Use synthetic demo evidence instead of live Graph calls")
    p.add_argument("--incremental", action="store_true", help="Use last successful cycle timestamp for changed-since polling")
    p.add_argument("--output-root", default=os.path.join(ROOT_DIR, "evidence"))
    p.add_argument("--state-file", default=os.path.join(ROOT_DIR, "state", "last_snapshot.json"))
    p.add_argument("--cycle-state-file", default=os.path.join(ROOT_DIR, "state", "cycle_state.json"))
    p.add_argument("--memory-file", default=os.path.join(ROOT_DIR, "MEMORY.md"))
    p.add_argument("--update-memory", action="store_true", help="Append cycle summary to MEMORY.md")
    p.add_argument("--date", help="Override date folder YYYY-MM-DD")
    args = p.parse_args()

    date_folder = args.date or datetime.now().strftime("%Y-%m-%d")
    out = os.path.join(args.output_root, date_folder)
    os.makedirs(out, exist_ok=True)

    cycle_state = load_json(args.cycle_state_file, {"last_success_at": None})
    since = cycle_state.get("last_success_at") if args.incremental else None

    if args.demo:
        steps = [[sys.executable, os.path.join(SCRIPT_DIR, "demo_generate.py"), "--output", out, "--full-pipeline"]]
    else:
        steps = [
            [sys.executable, os.path.join(SCRIPT_DIR, "intune_appcontrol.py"), "--mode", "audit", "--output", os.path.join(out, "appcontrol-audit.json")]
            + (["--since", since] if since else []),
            [sys.executable, os.path.join(SCRIPT_DIR, "intune_macros.py"), "--mode", "audit", "--output", os.path.join(out, "macro-audit.json")]
            + (["--since", since] if since else []),
            [sys.executable, os.path.join(SCRIPT_DIR, "intune_hardening.py"), "--mode", "audit", "--output", os.path.join(out, "hardening-audit.json")]
            + (["--since", since] if since else []),
            [sys.executable, os.path.join(SCRIPT_DIR, "intune_appcontrol.py"), "--mode", "events", "--output", os.path.join(out, "events.json")],
        ]

        if args.period == "weekly":
            steps.extend(
                [
                    [sys.executable, os.path.join(SCRIPT_DIR, "intune_appcontrol.py"), "--mode", "compliance", "--output", os.path.join(out, "appcontrol-compliance.json")],
                    [sys.executable, os.path.join(SCRIPT_DIR, "intune_macros.py"), "--mode", "compliance", "--output", os.path.join(out, "macro-compliance.json")],
                    [sys.executable, os.path.join(SCRIPT_DIR, "intune_hardening.py"), "--mode", "compliance", "--output", os.path.join(out, "hardening-compliance.json")],
                ]
            )

    results = [run(s) for s in steps]
    ok = all(r["returncode"] == 0 for r in results)

    if ok and not args.demo:
        results.append(
            run(
                [
                    sys.executable,
                    os.path.join(SCRIPT_DIR, "drift_detect.py"),
                    "--current-dir",
                    out,
                    "--state-file",
                    args.state_file,
                    "--output",
                    os.path.join(out, "drift.json"),
                ]
            )
        )
        results.append(run([sys.executable, os.path.join(SCRIPT_DIR, "generate_report.py"), "--input", out, "--output", os.path.join(out, "appcontrol-report.html")]))

    if ok:
        results.append(
            run(
                [
                    sys.executable,
                    os.path.join(SHARED_DIR, "evidence_pack.py"),
                    "--input-dir",
                    out,
                    "--period",
                    args.period,
                ]
            )
        )

    if ok and args.update_memory:
        results.append(run([sys.executable, os.path.join(SCRIPT_DIR, "update_memory.py"), "--memory", args.memory_file, "--drift", os.path.join(out, "drift.json"), "--evidence-dir", out]))

    ok = all(r["returncode"] == 0 for r in results)

    if ok and not args.demo:
        cycle_state["last_success_at"] = datetime.now(timezone.utc).isoformat()
        save_json(args.cycle_state_file, cycle_state)

    code = 0 if ok else 2
    status = {
        "status": "ok" if ok else "failed",
        "period": args.period,
        "output_dir": out,
        "incremental": bool(args.incremental),
        "since": since,
        "steps": results,
    }
    print(json.dumps(status, indent=2))
    raise SystemExit(code)


if __name__ == "__main__":
    main()
