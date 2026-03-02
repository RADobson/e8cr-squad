#!/usr/bin/env python3
"""Generate HTML report for E8CR Backup bot evidence."""

import argparse
import json
import os
from datetime import datetime


def load(path):
    with open(path, "r") as f:
        return json.load(f)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--type", choices=["evidence", "executive"], default="evidence")
    args = p.parse_args()

    jobs = load(os.path.join(args.input, "backup-jobs.json"))
    coverage = load(os.path.join(args.input, "coverage-audit.json"))
    restore = load(os.path.join(args.input, "restore-test.json"))
    ml2 = load(os.path.join(args.input, "ml2-checks.json")) if os.path.exists(os.path.join(args.input, "ml2-checks.json")) else {"checks": [], "overall": "unknown"}

    summary = {
        "success": len([j for j in jobs["jobs"] if j["status"] == "success"]),
        "failed": len([j for j in jobs["jobs"] if j["status"] == "failed"]),
        "missed": len([j for j in jobs["jobs"] if j["status"] == "missed"]),
    }

    html = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>E8CR Backup Report</title>
<style>body{{font-family:-apple-system,Arial,sans-serif;max-width:960px;margin:40px auto;padding:0 16px}} .ok{{color:#166534}} .bad{{color:#991b1b}} table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #ddd;padding:8px}}</style>
</head><body>
<h1>E8CR Backup Bot Report ({args.type.title()})</h1>
<p>Generated: {datetime.now().isoformat()}Z</p>
<h2>Summary</h2>
<ul>
<li>Successful jobs: <strong>{summary['success']}</strong></li>
<li>Failed jobs: <strong class='bad'>{summary['failed']}</strong></li>
<li>Missed jobs: <strong class='bad'>{summary['missed']}</strong></li>
<li>Coverage: <strong>{coverage['coveragePct']}%</strong> ({coverage['protectedAssets']}/{coverage['totalAssets']})</li>
<li>Restore test: <strong class='{'ok' if restore['status']=='success' else 'bad'}'>{restore['status']}</strong> ({restore['timeToRestoreMin']} min)</li>
</ul>
<h2>Backup Jobs</h2>
<table><tr><th>Job</th><th>Status</th><th>Last Run</th><th>Duration (min)</th></tr>
{''.join([f"<tr><td>{j['job']}</td><td>{j['status']}</td><td>{j['lastRun']}</td><td>{j['durationMin']}</td></tr>" for j in jobs['jobs']])}
</table>
<h2>Coverage Gaps</h2>
<ul>{''.join([f"<li>{a.get('name','unknown')} ({a.get('id','n/a')})</li>" for a in coverage['uncovered']]) or '<li>None</li>'}</ul>
<h2>Restore Evidence</h2>
<pre>{json.dumps(restore, indent=2)}</pre>
<h2>ML2 Checks</h2>
<p>Overall: <strong>{ml2.get('overall','unknown')}</strong></p>
<ul>{''.join([f"<li>[{c.get('status')}] {c.get('name')} — {c.get('evidence')}</li>" for c in ml2.get('checks',[])]) or '<li>No checks available</li>'}</ul>
</body></html>"""

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        f.write(html)
    print(args.output)


if __name__ == "__main__":
    main()
