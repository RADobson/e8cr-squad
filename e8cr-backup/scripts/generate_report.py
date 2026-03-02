#!/usr/bin/env python3
"""Generate HTML report for E8CR Backup bot evidence."""

import argparse
import json
import os
from datetime import datetime


def load(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def badge(ok):
    if ok:
        return '<span style="background:#166534;color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">PASS</span>'
    return '<span style="background:#991b1b;color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">FAIL</span>'


def status_badge(status):
    colours = {
        "success": "background:#166534",
        "failed": "background:#991b1b",
        "missed": "background:#92400e",
        "warning": "background:#92400e",
    }
    colour = colours.get(status.lower(), "background:#475569")
    return f'<span style="{colour};color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">{status.upper()}</span>'


def check(ok, text):
    icon = "✅" if ok else "❌"
    return f'<li style="padding:0.4rem 0">{icon} {text}</li>'


def generate_html(jobs_data, coverage, restore, ml2):
    now = datetime.now().strftime("%Y-%m-%d %H:%M AEST")

    jobs = jobs_data.get("jobs", [])
    success = sum(1 for j in jobs if j.get("status") == "success")
    failed = sum(1 for j in jobs if j.get("status") == "failed")
    missed = sum(1 for j in jobs if j.get("status") == "missed")

    cov_pct = coverage.get("coveragePct", 0)
    total_assets = coverage.get("totalAssets", 0)
    protected = coverage.get("protectedAssets", 0)
    uncovered = coverage.get("uncovered", [])

    restore_ok = restore.get("status") == "success"
    restore_time = restore.get("timeToRestoreMin", "?")
    integrity_ok = restore.get("integrityCheck") == "passed"

    ml2_overall = ml2.get("overall", "unknown")
    ml2_checks = ml2.get("checks", [])
    ml2_pass = ml2_overall == "pass"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>E8CR Backup Report — {now}</title>
<style>
  :root {{ --bg: #0f172a; --surface: #1e293b; --card: #334155; --border: #475569;
           --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8; --green: #22c55e;
           --red: #ef4444; --orange: #f97316; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; background: var(--bg);
          color: var(--text); line-height: 1.6; max-width: 1000px; margin: 0 auto; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.3rem; }}
  h2 {{ font-size: 1.2rem; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }}
  .meta {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 2rem; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; }}
  .card .label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .card .value {{ font-size: 2rem; font-weight: 800; margin: 0.3rem 0; }}
  .card .sub {{ color: var(--muted); font-size: 0.85rem; }}
  .green {{ color: var(--green); }} .red {{ color: var(--red); }} .orange {{ color: var(--orange); }} .accent {{ color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; margin: 0.5rem 0 1.5rem; }}
  th, td {{ padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
  th {{ color: var(--accent); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }}
  td {{ color: var(--muted); }}
  ul {{ list-style: none; padding: 0; margin: 0 0 1.5rem; }}
</style>
</head>
<body>
<h1>💾 E8CR Backup Report</h1>
<p class="meta">Generated: {now}</p>

<div class="cards">
  <div class="card">
    <div class="label">Successful Jobs</div>
    <div class="value {'green' if failed == 0 and missed == 0 else 'orange'}">{success}</div>
    <div class="sub">of {len(jobs)} total</div>
  </div>
  <div class="card">
    <div class="label">Failed Jobs</div>
    <div class="value {'green' if failed == 0 else 'red'}">{failed}</div>
  </div>
  <div class="card">
    <div class="label">Missed Jobs</div>
    <div class="value {'green' if missed == 0 else 'red'}">{missed}</div>
  </div>
  <div class="card">
    <div class="label">Coverage</div>
    <div class="value {'green' if cov_pct >= 100 else 'orange'}">{cov_pct}%</div>
    <div class="sub">{protected}/{total_assets} assets</div>
  </div>
  <div class="card">
    <div class="label">Restore Test</div>
    <div class="value {'green' if restore_ok else 'red'}">{'PASS' if restore_ok else 'FAIL'}</div>
    <div class="sub">{restore_time} min</div>
  </div>
  <div class="card">
    <div class="label">ML2 Status</div>
    <div class="value {'green' if ml2_pass else 'red'}">{ml2_overall.upper()}</div>
  </div>
</div>

<h2>ML2 Compliance Checklist</h2>
<ul>
  {check(success == len(jobs), f'All backup jobs succeeding ({success}/{len(jobs)})')}
  {check(cov_pct >= 100, f'All critical assets protected ({cov_pct}% coverage)')}
  {check(restore_ok, f'Restore test passed ({restore_time} min recovery time)')}
  {check(integrity_ok, 'Restore integrity check passed')}
  {check(len(uncovered) == 0, f'No coverage gaps ({len(uncovered)} uncovered assets)')}
  {check(ml2_pass, f'ML2 checks passed (overall: {ml2_overall})')}
</ul>

<h2>Backup Jobs</h2>
<table>
<thead><tr><th>Job</th><th>Status</th><th>Last Run</th><th>Duration (min)</th><th>Provider</th></tr></thead>
<tbody>
{''.join([f"""<tr>
  <td style='color:var(--text)'>{j.get('job', '?')}</td>
  <td>{status_badge(j.get('status', 'unknown'))}</td>
  <td>{(j.get('lastRun') or '')[:19].replace('T', ' ')}</td>
  <td>{j.get('durationMin', '?')}</td>
  <td>{j.get('provider', '?')}</td>
</tr>""" for j in jobs])}
</tbody>
</table>

<h2>Coverage</h2>
{'<p style="color:var(--green)">✅ All critical assets are protected.</p>' if not uncovered else f"""
<p style="color:var(--red);margin-bottom:0.75rem">⚠️  {len(uncovered)} asset(s) not covered by backup:</p>
<table><thead><tr><th>Asset</th><th>ID</th></tr></thead><tbody>
{''.join([f"<tr><td style='color:var(--text)'>{a.get('name','?')}</td><td style='font-family:monospace;font-size:0.85em'>{a.get('id','?')}</td></tr>" for a in uncovered])}
</tbody></table>"""}

<h2>Restore Test Evidence</h2>
<table>
<thead><tr><th>Field</th><th>Value</th></tr></thead>
<tbody>
  <tr><td>Target</td><td style="color:var(--text)">{restore.get('target', '?')}</td></tr>
  <tr><td>Source Backup</td><td style="color:var(--text)">{restore.get('sourceBackup', '?')}</td></tr>
  <tr><td>Restore Destination</td><td style="color:var(--text)">{restore.get('restoreDestination', '?')}</td></tr>
  <tr><td>Time to Restore</td><td style="color:var(--text)">{restore_time} minutes</td></tr>
  <tr><td>Integrity Check</td><td>{badge(integrity_ok)}</td></tr>
  <tr><td>Checksum Verified</td><td>{badge(restore.get('checksumVerified', False))}</td></tr>
  <tr><td>Overall Status</td><td>{status_badge(restore.get('status', 'unknown'))}</td></tr>
  <tr><td>Notes</td><td style="color:var(--muted)">{restore.get('notes', '')}</td></tr>
</tbody>
</table>

{''.join([f"""<h2>ML2 Check Results</h2><table>
<thead><tr><th>Check</th><th>Status</th><th>Evidence</th></tr></thead><tbody>
{"".join([f"<tr><td style='color:var(--text)'>{c.get('name','?')}</td><td>{badge(c.get('status','') == 'pass')}</td><td style='color:var(--muted)'>{c.get('evidence','')}</td></tr>" for c in ml2_checks])}
</tbody></table>""" if ml2_checks else ""])}

<hr style="border-color:var(--border);margin:2rem 0">
<p style="color:var(--muted);font-size:0.85rem">E8CR Backup Bot — Apache 2.0 — {now}</p>
</body></html>"""


def main():
    p = argparse.ArgumentParser(description="Generate E8CR backup evidence report")
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--type", choices=["evidence", "executive"], default="evidence")
    args = p.parse_args()

    jobs_data = load(os.path.join(args.input, "backup-jobs.json"))
    coverage = load(os.path.join(args.input, "coverage-audit.json"))
    restore = load(os.path.join(args.input, "restore-test.json"))
    ml2 = load(os.path.join(args.input, "ml2-checks.json"))

    html = generate_html(jobs_data, coverage, restore, ml2)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        f.write(html)
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
