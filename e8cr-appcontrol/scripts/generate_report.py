#!/usr/bin/env python3
"""Generate HTML report for Application Control bot evidence pack."""

import os
import json
import argparse
from datetime import datetime


def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def badge(ok):
    if ok:
        return '<span style="background:#166534;color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">PASS</span>'
    return '<span style="background:#991b1b;color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">FAIL</span>'


def policy_rows(policies):
    if not policies:
        return "<tr><td colspan='3' style='color:var(--muted)'>No policies found</td></tr>"
    rows = ""
    for p in policies:
        assigned = p.get("isAssigned", False)
        rows += f"""<tr>
  <td style="color:var(--text)">{p.get('name', '?')}</td>
  <td style="color:var(--muted);font-family:monospace;font-size:0.85em">{p.get('id', '?')}</td>
  <td>{badge(assigned)}</td>
</tr>"""
    return rows


def generate_html(app, macro, hard):
    now = datetime.now().strftime("%Y-%m-%d %H:%M AEST")
    company = app.get("company", hard.get("company", macro.get("company", "—")))

    app_count = app.get("appcontrol_policies_found", 0)
    macro_count = macro.get("macro_policies_found", 0)
    hard_count = hard.get("hardening_policies_found", 0)

    app_pass = app_count > 0
    macro_pass = macro_count > 0
    hard_pass = hard_count > 0

    def check(ok, text):
        icon = "✅" if ok else "❌"
        return f'<li style="padding:0.4rem 0">{icon} {text}</li>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>E8CR Application Control Report — {now}</title>
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
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; }}
  .card .label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .card .value {{ font-size: 2rem; font-weight: 800; margin: 0.3rem 0; }}
  .green {{ color: var(--green); }} .red {{ color: var(--red); }} .accent {{ color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; margin: 0.5rem 0 1.5rem; }}
  th, td {{ padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
  th {{ color: var(--accent); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }}
  td {{ color: var(--muted); }}
  ul {{ list-style: none; padding: 0; margin: 0 0 1.5rem; }}
</style>
</head>
<body>
<h1>🔒 E8CR Application Control Report</h1>
<p class="meta">Generated: {now} | Company: {company}</p>

<div class="cards">
  <div class="card">
    <div class="label">App Control Policies</div>
    <div class="value {'green' if app_pass else 'red'}">{app_count}</div>
  </div>
  <div class="card">
    <div class="label">Macro Policies</div>
    <div class="value {'green' if macro_pass else 'red'}">{macro_count}</div>
  </div>
  <div class="card">
    <div class="label">Hardening Policies</div>
    <div class="value {'green' if hard_pass else 'red'}">{hard_count}</div>
  </div>
  <div class="card">
    <div class="label">Overall</div>
    <div class="value {'green' if (app_pass and macro_pass and hard_pass) else 'red'}">
      {'PASS' if (app_pass and macro_pass and hard_pass) else 'GAPS'}
    </div>
  </div>
</div>

<h2>ML2 Compliance Checklist</h2>
<ul>
  {check(app_pass, f'Application control policies deployed ({app_count} found)')}
  {check(macro_pass, f'Office macro restriction policies deployed ({macro_count} found)')}
  {check(hard_pass, f'User application hardening policies deployed ({hard_count} found)')}
  {check(any(p.get("name","").lower().find("block") >= 0 for p in app.get("policies",[])), 'Microsoft recommended block rules present')}
  {check(any(p.get("name","").lower().find("internet") >= 0 or p.get("name","").lower().find("motw") >= 0 for p in macro.get("policies",[])), 'Macros from internet blocked (Mark of the Web)')}
  {check(any(p.get("name","").lower().find("edge") >= 0 or p.get("name","").lower().find("browser") >= 0 for p in hard.get("policies",[])), 'Browser hardening policy deployed')}
</ul>

<h2>Application Control Policies</h2>
<table>
<thead><tr><th>Policy Name</th><th>ID</th><th>Assigned</th></tr></thead>
<tbody>{policy_rows(app.get("policies", []))}</tbody>
</table>

<h2>Macro Settings Policies</h2>
<table>
<thead><tr><th>Policy Name</th><th>ID</th><th>Assigned</th></tr></thead>
<tbody>{policy_rows(macro.get("policies", []))}</tbody>
</table>

<h2>User Application Hardening Policies</h2>
<table>
<thead><tr><th>Policy Name</th><th>ID</th><th>Assigned</th></tr></thead>
<tbody>{policy_rows(hard.get("policies", []))}</tbody>
</table>

<hr style="border-color:var(--border);margin:2rem 0">
<p style="color:var(--muted);font-size:0.85rem">E8CR App Control Bot — Apache 2.0 — {now}</p>
</body></html>"""


def main():
    p = argparse.ArgumentParser(description="Generate E8CR Application Control evidence report")
    p.add_argument("--input", required=True, help="Dir with appcontrol-audit.json, macro-audit.json, hardening-audit.json")
    p.add_argument("--output", required=True)
    p.add_argument("--type", choices=["weekly", "executive"], default="weekly")
    args = p.parse_args()

    app = load_json(os.path.join(args.input, "appcontrol-audit.json"))
    macro = load_json(os.path.join(args.input, "macro-audit.json"))
    hard = load_json(os.path.join(args.input, "hardening-audit.json"))

    html = generate_html(app, macro, hard)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        f.write(html)
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
