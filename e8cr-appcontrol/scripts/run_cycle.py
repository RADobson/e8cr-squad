#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return {"cmd": " ".join(cmd), "returncode": r.returncode, "stdout": r.stdout[-500:], "stderr": r.stderr[-500:]}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--period", choices=["daily", "weekly"], required=True)
    p.add_argument("--demo", action="store_true", help="Use synthetic demo evidence instead of live Graph calls")
    p.add_argument("--output-root", default=os.path.join(ROOT_DIR, "evidence"))
    p.add_argument("--state-file", default=os.path.join(ROOT_DIR, "state", "last_snapshot.json"))
    p.add_argument("--memory-file", default=os.path.join(ROOT_DIR, "MEMORY.md"))
    p.add_argument("--update-memory", action="store_true", help="Append cycle summary to MEMORY.md")
    p.add_argument("--date", help="Override date folder YYYY-MM-DD")
    args = p.parse_args()

    date_folder = args.date or datetime.now().strftime("%Y-%m-%d")
    out = os.path.join(args.output_root, date_folder)
    os.makedirs(out, exist_ok=True)

    if args.demo:
        steps = [[sys.executable, os.path.join(SCRIPT_DIR, "demo_generate.py"), "--output", out, "--full-pipeline"]]
    else:
        steps = [
            [sys.executable, os.path.join(SCRIPT_DIR, "intune_appcontrol.py"), "--mode", "audit", "--output", os.path.join(out, "appcontrol-audit.json")],
            [sys.executable, os.path.join(SCRIPT_DIR, "intune_macros.py"), "--mode", "audit", "--output", os.path.join(out, "macro-audit.json")],
            [sys.executable, os.path.join(SCRIPT_DIR, "intune_hardening.py"), "--mode", "audit", "--output", os.path.join(out, "hardening-audit.json")],
            [sys.executable, os.path.join(SCRIPT_DIR, "intune_appcontrol.py"), "--mode", "events", "--output", os.path.join(out, "events.json")],
        ]

        if args.period == "weekly":
            steps.extend([
                [sys.executable, os.path.join(SCRIPT_DIR, "intune_appcontrol.py"), "--mode", "compliance", "--output", os.path.join(out, "appcontrol-compliance.json")],
                [sys.executable, os.path.join(SCRIPT_DIR, "intune_macros.py"), "--mode", "compliance", "--output", os.path.join(out, "macro-compliance.json")],
                [sys.executable, os.path.join(SCRIPT_DIR, "intune_hardening.py"), "--mode", "compliance", "--output", os.path.join(out, "hardening-compliance.json")],
            ])

    results = [run(s) for s in steps]
    ok = all(r["returncode"] == 0 for r in results)

    if ok and not args.demo:
        results.append(run([sys.executable, os.path.join(SCRIPT_DIR, "drift_detect.py"), "--current-dir", out, "--state-file", args.state_file, "--output", os.path.join(out, "drift.json")]))
        results.append(run([sys.executable, os.path.join(SCRIPT_DIR, "generate_report.py"), "--input", out, "--output", os.path.join(out, "appcontrol-report.html")]))

    if ok and args.update_memory:
        results.append(run([sys.executable, os.path.join(SCRIPT_DIR, "update_memory.py"), "--memory", args.memory_file, "--drift", os.path.join(out, "drift.json"), "--evidence-dir", out]))

    ok = all(r["returncode"] == 0 for r in results)

    code = 0 if ok else 2
    status = {"status": "ok" if ok else "failed", "period": args.period, "output_dir": out, "steps": results}
    print(json.dumps(status, indent=2))
    raise SystemExit(code)


if __name__ == "__main__":
    main()
