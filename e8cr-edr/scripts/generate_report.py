#!/usr/bin/env python3
"""Generate EDR operations HTML report — daily summary, incidents, response actions, evidence."""

import argparse
import json
import os
from datetime import datetime

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "informational": "#6b7280",
}

SEVERITY_BADGE = {
    "critical": "background:#dc2626;color:white",
    "high": "background:#ea580c;color:white",
    "medium": "background:#d97706;color:white",
    "low": "background:#65a30d;color:white",
    "informational": "background:#6b7280;color:white",
}


def badge(severity: str) -> str:
    style = SEVERITY_BADGE.get(severity, SEVERITY_BADGE["informational"])
    return f'<span style="{style};padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">{severity.upper()}</span>'


def generate_html(alerts_data: dict, incidents_data: dict, actions_data: dict) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M AEST")
    triaged = alerts_data.get("triaged", [])
    summary = alerts_data.get("summary", {})
    incidents = incidents_data.get("incidents", [])
    actions = actions_data.get("actions", [])

    # Summary cards
    total_alerts = alerts_data.get("alertCount", 0)
    auto_resolved = summary.get("auto_resolve", 0)
    escalated = summary.get("escalate_immediate", 0) + summary.get("escalate", 0)
    investigating = summary.get("investigate", 0)
    monitoring = summary.get("monitor", 0)
    attack_chains = incidents_data.get("attackChains", 0)

    # Alerts table
    alert_rows = ""
    for t in triaged[:20]:
        sev = t.get("severity", "informational")
        devices = ", ".join(t.get("devices", [])) or "—"
        users = ", ".join(t.get("users", [])) or "—"
        mitre = ", ".join(t.get("mitre_techniques", [])) or "—"
        action = t.get("action", "").replace("_", " ").title()
        reason = t.get("reason", "")
        alert_rows += f"""<tr>
            <td>{badge(sev)}</td>
            <td>{t.get('title','')}</td>
            <td>{devices}</td>
            <td>{users}</td>
            <td>{mitre}</td>
            <td><strong>{action}</strong>{f'<br><small>{reason}</small>' if reason else ''}</td>
        </tr>"""

    # Incidents table
    incident_rows = ""
    for inc in incidents:
        sev = inc.get("severity", "low")
        chain_badge = ' <span style="background:#7c3aed;color:white;padding:2px 6px;border-radius:4px;font-size:0.75em">ATTACK CHAIN</span>' if inc.get("isAttackChain") else ""
        stages = " → ".join(inc.get("killChainStages", []))
        devices = ", ".join(inc.get("devices", []))
        timeline_html = ""
        for event in inc.get("timeline", []):
            timeline_html += f'<div style="border-left:2px solid {SEVERITY_COLORS.get(event.get("severity",""),"#ccc")};padding-left:8px;margin:4px 0"><small>{event.get("time","")[:16]}</small> — <strong>{event.get("title","")}</strong> [{event.get("stage","")}]</div>'

        incident_rows += f"""<tr>
            <td><strong>{inc.get('incidentId','')}</strong>{chain_badge}</td>
            <td>{badge(sev)}</td>
            <td>{inc.get('alertCount',0)}</td>
            <td>{stages}</td>
            <td>{devices}</td>
            <td>{timeline_html}</td>
        </tr>"""

    # Actions table
    action_rows = ""
    for act in actions:
        result_color = "#16a34a" if act.get("result") == "success" else "#dc2626" if act.get("result") == "failed" else "#d97706"
        action_rows += f"""<tr>
            <td><small>{act.get('timestamp','')[:16]}</small></td>
            <td><strong>{act.get('action','').replace('_',' ').title()}</strong></td>
            <td>{act.get('target','')}</td>
            <td>{act.get('reason','')}</td>
            <td style="color:{result_color};font-weight:600">{act.get('result','').upper()}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>E8CR EDR Operations Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; padding: 24px; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    h1 {{ font-size: 1.8em; margin-bottom: 4px; }}
    h2 {{ font-size: 1.3em; margin: 24px 0 12px; color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
    .subtitle {{ color: #64748b; margin-bottom: 24px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 24px; }}
    .card {{ background: #1e293b; border-radius: 8px; padding: 16px; text-align: center; }}
    .card .value {{ font-size: 2em; font-weight: 700; }}
    .card .label {{ font-size: 0.85em; color: #94a3b8; margin-top: 4px; }}
    .card.critical {{ border-left: 4px solid #dc2626; }}
    .card.warning {{ border-left: 4px solid #d97706; }}
    .card.success {{ border-left: 4px solid #16a34a; }}
    .card.info {{ border-left: 4px solid #3b82f6; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; margin-bottom: 16px; }}
    th {{ background: #334155; padding: 10px 12px; text-align: left; font-size: 0.85em; color: #94a3b8; text-transform: uppercase; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #334155; font-size: 0.9em; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    .footer {{ text-align: center; margin-top: 32px; color: #475569; font-size: 0.8em; }}
    .tag {{ display: inline-block; background: #334155; padding: 2px 6px; border-radius: 3px; font-size: 0.8em; margin: 1px; }}
</style>
</head>
<body>
<div class="container">
    <h1>🛡️ EDR Operations Report</h1>
    <p class="subtitle">Generated {now} by E8CR EDR Operator</p>

    <div class="cards">
        <div class="card info"><div class="value">{total_alerts}</div><div class="label">Total Alerts</div></div>
        <div class="card critical"><div class="value">{escalated}</div><div class="label">Escalated</div></div>
        <div class="card warning"><div class="value">{investigating}</div><div class="label">Investigating</div></div>
        <div class="card success"><div class="value">{auto_resolved}</div><div class="label">Auto-Resolved (FP)</div></div>
        <div class="card info"><div class="value">{monitoring}</div><div class="label">Monitoring</div></div>
        <div class="card critical"><div class="value">{attack_chains}</div><div class="label">Attack Chains</div></div>
    </div>

    <h2>Alert Triage</h2>
    <table>
        <thead><tr><th>Severity</th><th>Alert</th><th>Devices</th><th>Users</th><th>MITRE</th><th>Action</th></tr></thead>
        <tbody>{alert_rows}</tbody>
    </table>

    <h2>Correlated Incidents</h2>
    <table>
        <thead><tr><th>Incident</th><th>Severity</th><th>Alerts</th><th>Kill Chain</th><th>Devices</th><th>Timeline</th></tr></thead>
        <tbody>{incident_rows}</tbody>
    </table>

    <h2>Automated Response Actions</h2>
    <table>
        <thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Reason</th><th>Result</th></tr></thead>
        <tbody>{action_rows}</tbody>
    </table>

    <div class="footer">
        <p>E8CR EDR Operator — Autonomous Tier-1 SOC | Dobson Development</p>
        <p>This report constitutes evidence for Essential Eight ML2 assessment — endpoint detection and response operations.</p>
    </div>
</div>
</body>
</html>"""
    return html


def main():
    p = argparse.ArgumentParser(description="Generate EDR operations HTML report")
    p.add_argument("--input", required=True, help="Directory containing alerts.json, incidents.json, actions.json")
    p.add_argument("--output", help="Output HTML file (default: stdout)")
    args = p.parse_args()

    with open(os.path.join(args.input, "alerts.json"), "r") as f:
        alerts = json.load(f)
    with open(os.path.join(args.input, "incidents.json"), "r") as f:
        incidents = json.load(f)
    with open(os.path.join(args.input, "actions.json"), "r") as f:
        actions = json.load(f)

    html = generate_html(alerts, incidents, actions)

    if args.output:
        with open(args.output, "w") as f:
            f.write(html)
        print(f"Report written to {args.output}")
    else:
        print(html)


if __name__ == "__main__":
    main()
