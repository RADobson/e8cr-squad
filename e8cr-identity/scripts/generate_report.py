#!/usr/bin/env python3
"""Generate identity compliance HTML report from audit JSON outputs.

Usage:
    python3 generate_report.py --input demo/identity --output identity-report.html
    python3 generate_report.py --input demo/identity --output identity-report.html --type executive
"""

import argparse
import json
import os
from datetime import datetime


def load(path):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def pct(n, total):
    if total == 0:
        return "0%"
    return f"{n / total * 100:.0f}%"


def badge_ok(ok: bool) -> str:
    if ok:
        return '<span style="background:#166534;color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">PASS</span>'
    return '<span style="background:#991b1b;color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">FAIL</span>'


def generate_html(mfa_data: dict, role_data: dict, ca_data: dict) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M AEST")

    # ── MFA metrics ──────────────────────────────────────────────────────
    total_users = mfa_data.get("total_users", 0)
    mfa_registered = mfa_data.get("mfa_registered", 0)
    mfa_gaps = total_users - mfa_registered
    mfa_pct = pct(mfa_registered, total_users)
    mfa_pass = mfa_registered == total_users

    methods = mfa_data.get("method_breakdown", {})
    phishing_resistant = methods.get("fido2", 0) + methods.get("windowsHelloForBusiness", 0)
    pr_pct = pct(phishing_resistant, total_users)

    gaps_list = mfa_data.get("users_without_mfa", [])

    # ── Role metrics ─────────────────────────────────────────────────────
    roles = role_data.get("roles", [])
    total_admins = role_data.get("total_admin_users", 0)
    global_admins = role_data.get("global_admin_count", 0)
    permanent_assignments = role_data.get("permanent_count", 0)
    pim_enabled = role_data.get("pim_assignments", 0)
    service_accounts = role_data.get("service_account_admins", 0)

    ga_pass = global_admins <= 4  # ML2: minimise GA count
    perm_pass = permanent_assignments <= 5

    # ── CA metrics ───────────────────────────────────────────────────────
    ca_policies = ca_data.get("policies", [])
    ca_audit = ca_data.get("audit_results", {})
    legacy_blocked = ca_audit.get("block_legacy_auth", {}).get("pass", False)
    risk_blocked = ca_audit.get("block_high_risk_signin", {}).get("pass", False)

    # ── Build HTML ───────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>E8CR Identity Compliance Report — {now}</title>
<style>
  :root {{ --bg: #0f172a; --surface: #1e293b; --card: #334155; --border: #475569;
           --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8; --green: #22c55e;
           --red: #ef4444; --orange: #f97316; --yellow: #eab308; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; background: var(--bg);
          color: var(--text); line-height: 1.6; max-width: 1000px; margin: 0 auto; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.3rem; }}
  h2 {{ font-size: 1.3rem; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }}
  .meta {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 2rem; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; }}
  .card .label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .card .value {{ font-size: 2rem; font-weight: 800; margin: 0.3rem 0; }}
  .card .value.green {{ color: var(--green); }}
  .card .value.red {{ color: var(--red); }}
  .card .value.orange {{ color: var(--orange); }}
  .card .value.accent {{ color: var(--accent); }}
  .card .sub {{ color: var(--muted); font-size: 0.85rem; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th, td {{ padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
  th {{ color: var(--accent); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }}
  td {{ color: var(--muted); }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; }}
  .badge-pass {{ background: #166534; color: white; }}
  .badge-fail {{ background: #991b1b; color: white; }}
  .badge-warn {{ background: #92400e; color: white; }}
  .section-status {{ float: right; }}
  .checklist {{ list-style: none; }}
  .checklist li {{ padding: 0.4rem 0; }}
  .checklist li::before {{ content: ""; display: inline-block; width: 1.2em; }}
  .pass::before {{ content: "✅ "; }}
  .fail::before {{ content: "❌ "; }}
  .warn::before {{ content: "⚠️ "; }}
</style>
</head>
<body>
<h1>🔑 E8CR Identity Compliance Report</h1>
<p class="meta">Generated: {now} | Company: {mfa_data.get("company", "—")}</p>

<div class="cards">
  <div class="card">
    <div class="label">Total Users</div>
    <div class="value accent">{total_users}</div>
  </div>
  <div class="card">
    <div class="label">MFA Coverage</div>
    <div class="value {'green' if mfa_pass else 'red'}">{mfa_pct}</div>
    <div class="sub">{mfa_registered}/{total_users} registered</div>
  </div>
  <div class="card">
    <div class="label">Phishing-Resistant</div>
    <div class="value {'green' if phishing_resistant > total_users * 0.5 else 'orange'}">{pr_pct}</div>
    <div class="sub">{phishing_resistant} users (FIDO2/WHfB)</div>
  </div>
  <div class="card">
    <div class="label">Global Admins</div>
    <div class="value {'green' if ga_pass else 'red'}">{global_admins}</div>
    <div class="sub">Target: ≤ 4</div>
  </div>
  <div class="card">
    <div class="label">Permanent Assignments</div>
    <div class="value {'green' if perm_pass else 'orange'}">{permanent_assignments}</div>
    <div class="sub">Use PIM for just-in-time</div>
  </div>
  <div class="card">
    <div class="label">Admin Accounts</div>
    <div class="value accent">{total_admins}</div>
    <div class="sub">{service_accounts} service accounts</div>
  </div>
</div>

<h2>ML2 Compliance Checklist</h2>
<ul class="checklist">
  <li class="{'pass' if mfa_pass else 'fail'}">MFA enforced for all users ({mfa_pct} coverage)</li>
  <li class="{'pass' if phishing_resistant > 0 else 'warn'}">Phishing-resistant MFA available ({phishing_resistant} users)</li>
  <li class="{'pass' if legacy_blocked else 'fail'}">Legacy authentication blocked via Conditional Access</li>
  <li class="{'pass' if risk_blocked else 'fail'}">High-risk sign-ins blocked or require MFA</li>
  <li class="{'pass' if ga_pass else 'fail'}">Global Admin count minimised ({global_admins} active)</li>
  <li class="{'pass' if perm_pass else 'warn'}">Permanent admin assignments minimised ({permanent_assignments} permanent)</li>
  <li class="{'pass' if service_accounts == 0 else 'warn'}">Service accounts with admin roles reviewed ({service_accounts} found)</li>
</ul>
"""

    # MFA Gaps table
    if gaps_list:
        html += f"""
<h2>MFA Gaps ({len(gaps_list)} users)</h2>
<table>
<thead><tr><th>User</th><th>Display Name</th><th>Account Type</th><th>Last Sign-In</th></tr></thead>
<tbody>
"""
        for u in gaps_list[:30]:
            html += f"""<tr>
  <td style="color:var(--text)">{u.get('userPrincipalName', '?')}</td>
  <td>{u.get('displayName', '')}</td>
  <td>{u.get('accountType', '?')}</td>
  <td>{(u.get('lastSignIn') or 'never')[:10]}</td>
</tr>"""
        if len(gaps_list) > 30:
            html += f'<tr><td colspan="4" style="color:var(--muted)">... and {len(gaps_list) - 30} more</td></tr>'
        html += "</tbody></table>"

    # Roles table
    if roles:
        html += """
<h2>Admin Role Assignments</h2>
<table>
<thead><tr><th>Role</th><th>Assignments</th><th>Type</th></tr></thead>
<tbody>
"""
        for r in roles:
            name = r.get("role_name", "?")
            count = r.get("assignment_count", 0)
            rtype = r.get("assignment_type", "permanent")
            html += f"""<tr>
  <td style="color:var(--text)">{name}</td>
  <td>{count}</td>
  <td>{'<span class="badge badge-warn">Permanent</span>' if rtype == 'permanent' else '<span class="badge badge-pass">PIM</span>'}</td>
</tr>"""
        html += "</tbody></table>"

    # CA Policies table
    if ca_policies:
        html += """
<h2>Conditional Access Policies</h2>
<table>
<thead><tr><th>Policy</th><th>State</th><th>Purpose</th></tr></thead>
<tbody>
"""
        for p in ca_policies:
            name = p.get("displayName", "?")
            state = p.get("state", "?")
            state_badge = '<span class="badge badge-pass">Enabled</span>' if state == "enabled" else f'<span class="badge badge-warn">{state}</span>'
            purpose = p.get("purpose", "")
            html += f"""<tr>
  <td style="color:var(--text)">{name}</td>
  <td>{state_badge}</td>
  <td>{purpose}</td>
</tr>"""
        html += "</tbody></table>"

    html += f"""
<hr style="border-color:var(--border);margin:2rem 0">
<p style="color:var(--muted);font-size:0.85rem">E8CR Identity Bot — Apache 2.0 — Generated {now}</p>
</body></html>"""
    return html


def main():
    parser = argparse.ArgumentParser(description="Generate E8CR identity compliance report")
    parser.add_argument("--input", required=True, help="Directory containing audit JSON files")
    parser.add_argument("--output", required=True, help="Output HTML file")
    parser.add_argument("--type", choices=["weekly", "executive"], default="weekly")
    args = parser.parse_args()

    mfa_data = load(os.path.join(args.input, "mfa-audit.json"))
    role_data = load(os.path.join(args.input, "role-audit.json"))
    ca_data = load(os.path.join(args.input, "ca-audit.json"))

    html = generate_html(mfa_data, role_data, ca_data)

    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
    with open(args.output, "w") as f:
        f.write(html)
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
