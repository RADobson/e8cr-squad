#!/usr/bin/env python3
"""E8CR Squad — Unified Compliance Assessment

Run all 4 bots in sequence and produce a combined Essential Eight ML2
compliance report. Works in demo mode (synthetic data) or live mode
(real Microsoft 365 tenant).

Usage:
    # Demo mode — no tenant needed, generates synthetic data + reports
    python3 run_all.py --demo --output /tmp/e8cr-assessment

    # Live mode — requires configured tenant credentials
    python3 run_all.py --output /tmp/e8cr-assessment

    # Run specific bots only
    python3 run_all.py --demo --output /tmp/e8cr-assessment --bots vmpm identity

    # Custom company name for report branding
    python3 run_all.py --demo --output /tmp/e8cr-assessment --company "Acme Corp"
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

BOTS = {
    "vmpm": {
        "name": "Vulnerability & Patch Management",
        "dir": "e8cr-vmpm",
        "controls": ["Patch Applications", "Patch OS"],
        "demo_cmd": lambda out: [
            sys.executable, os.path.join(SCRIPT_DIR, "e8cr-vmpm", "scripts", "demo_generate.py"),
            "--output", out, "--full-pipeline"
        ],
        "report_file": "weekly-report.html",
        "evidence_files": ["patch-compliance.json", "prioritised.json", "scan-results.json"],
    },
    "identity": {
        "name": "Identity & Access Management",
        "dir": "e8cr-identity",
        "controls": ["Multi-factor Authentication", "Restrict Admin Privileges"],
        "demo_cmd": lambda out: [
            sys.executable, os.path.join(SCRIPT_DIR, "e8cr-identity", "scripts", "demo_generate.py"),
            "--output", out, "--full-pipeline"
        ],
        "report_file": "identity-report.html",
        "evidence_files": ["mfa-audit.json", "role-audit.json", "ca-audit.json"],
    },
    "appcontrol": {
        "name": "Application Control & Hardening",
        "dir": "e8cr-appcontrol",
        "controls": ["Application Control", "Configure Office Macros", "User Application Hardening"],
        "demo_cmd": lambda out: [
            sys.executable, os.path.join(SCRIPT_DIR, "e8cr-appcontrol", "scripts", "demo_generate.py"),
            "--output", out, "--full-pipeline"
        ],
        "report_file": "appcontrol-report.html",
        "evidence_files": ["appcontrol-audit.json", "macros-audit.json", "hardening-audit.json"],
    },
    "backup": {
        "name": "Regular Backups",
        "dir": "e8cr-backup",
        "controls": ["Regular Backups"],
        "demo_cmd": lambda out: [
            sys.executable, os.path.join(SCRIPT_DIR, "e8cr-backup", "scripts", "demo_generate.py"),
            "--output", out, "--full-pipeline"
        ],
        "report_file": "backup-report.html",
        "evidence_files": ["backup-jobs.json", "coverage-audit.json", "restore-test.json", "ml2-checks.json"],
    },
}

E8_CONTROLS = [
    "Patch Applications",
    "Patch OS",
    "Multi-factor Authentication",
    "Restrict Admin Privileges",
    "Application Control",
    "Configure Office Macros",
    "User Application Hardening",
    "Regular Backups",
]


def run_bot(bot_key, bot_cfg, output_dir, demo=True):
    """Run a single bot and return (success, report_path, evidence_paths)."""
    bot_output = os.path.join(output_dir, bot_key)
    os.makedirs(bot_output, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  🤖 Running: {bot_cfg['name']}")
    print(f"  Controls: {', '.join(bot_cfg['controls'])}")
    print(f"  Output: {bot_output}")
    print(f"{'='*60}")

    if demo:
        cmd = bot_cfg["demo_cmd"](bot_output)
    else:
        print("  ⚠️  Live mode not yet implemented in orchestrator.")
        print("  Run individual bot scripts with tenant credentials.")
        return False, None, []

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=SCRIPT_DIR,
        )
        if result.returncode != 0:
            print(f"  ❌ Failed (exit {result.returncode})")
            if result.stderr:
                print(f"  stderr: {result.stderr[:500]}")
            return False, None, []

        print(f"  ✅ Complete")

    except subprocess.TimeoutExpired:
        print(f"  ❌ Timed out (120s)")
        return False, None, []
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False, None, []

    # Find report and evidence
    report_path = None
    for root, dirs, files in os.walk(bot_output):
        for f in files:
            if f == bot_cfg["report_file"]:
                report_path = os.path.join(root, f)
                break

    evidence_paths = []
    for ef in bot_cfg["evidence_files"]:
        for root, dirs, files in os.walk(bot_output):
            for f in files:
                if f == ef:
                    evidence_paths.append(os.path.join(root, f))

    return True, report_path, evidence_paths


def parse_bot_results(bot_key, bot_output):
    """Extract summary metrics from bot evidence files. Returns dict of findings."""
    findings = {"status": "unknown", "issues": [], "stats": {}}

    if bot_key == "vmpm":
        patch_file = os.path.join(bot_output, "patch-compliance.json")
        prio_file = os.path.join(bot_output, "prioritised.json")
        if os.path.exists(patch_file):
            try:
                data = json.load(open(patch_file))
                devices = data if isinstance(data, list) else data.get("devices", [])
                total = len(devices)
                compliant = sum(1 for d in devices if d.get("complianceState") == "compliant")
                findings["stats"]["devices"] = total
                findings["stats"]["compliant"] = compliant
                findings["stats"]["compliance_pct"] = round(compliant / total * 100, 1) if total else 0
            except Exception:
                pass
        if os.path.exists(prio_file):
            try:
                data = json.load(open(prio_file))
                vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
                critical = sum(1 for v in vulns if v.get("priority") == "critical" or v.get("epss_percentile", 0) > 0.9)
                findings["stats"]["total_vulns"] = len(vulns)
                findings["stats"]["critical_vulns"] = critical
                if critical > 0:
                    findings["issues"].append(f"{critical} critical vulnerabilities need patching within 48h")
            except Exception:
                pass

    elif bot_key == "identity":
        mfa_file = os.path.join(bot_output, "mfa-audit.json")
        role_file = os.path.join(bot_output, "role-audit.json")
        if os.path.exists(mfa_file):
            try:
                data = json.load(open(mfa_file))
                users = data if isinstance(data, list) else data.get("users", [])
                total = len(users)
                mfa_enabled = sum(1 for u in users if u.get("mfaRegistered") or u.get("mfa_registered") or u.get("strongAuthenticationMethods"))
                findings["stats"]["users"] = total
                findings["stats"]["mfa_registered"] = mfa_enabled
                findings["stats"]["mfa_pct"] = round(mfa_enabled / total * 100, 1) if total else 0
                gap = total - mfa_enabled
                if gap > 0:
                    findings["issues"].append(f"{gap} users without MFA registration")
            except Exception:
                pass
        if os.path.exists(role_file):
            try:
                data = json.load(open(role_file))
                admins = data if isinstance(data, list) else data.get("admins", data.get("role_assignments", []))
                ga_count = sum(1 for a in admins if "global" in str(a.get("role", a.get("roleName", ""))).lower())
                findings["stats"]["admin_roles"] = len(admins)
                findings["stats"]["global_admins"] = ga_count
                if ga_count > 4:
                    findings["issues"].append(f"{ga_count} Global Admins (ML2 recommends ≤4)")
            except Exception:
                pass

    elif bot_key == "appcontrol":
        for audit_file in ["appcontrol-audit.json", "macros-audit.json", "hardening-audit.json"]:
            fpath = os.path.join(bot_output, audit_file)
            if os.path.exists(fpath):
                try:
                    data = json.load(open(fpath))
                    policies = data if isinstance(data, list) else data.get("policies", data.get("profiles", []))
                    findings["stats"][audit_file.replace("-audit.json", "_policies")] = len(policies)
                except Exception:
                    pass

    elif bot_key == "backup":
        jobs_file = os.path.join(bot_output, "backup-jobs.json")
        ml2_file = os.path.join(bot_output, "ml2-checks.json")
        if os.path.exists(jobs_file):
            try:
                data = json.load(open(jobs_file))
                jobs = data if isinstance(data, list) else data.get("jobs", [])
                failed = sum(1 for j in jobs if j.get("status") in ("failed", "Failed", "error"))
                findings["stats"]["backup_jobs"] = len(jobs)
                findings["stats"]["failed_jobs"] = failed
                if failed > 0:
                    findings["issues"].append(f"{failed} backup jobs failed")
            except Exception:
                pass
        if os.path.exists(ml2_file):
            try:
                data = json.load(open(ml2_file))
                checks = data if isinstance(data, list) else data.get("checks", [])
                passed = sum(1 for c in checks if c.get("status") in ("pass", "PASS", True))
                findings["stats"]["ml2_checks_total"] = len(checks)
                findings["stats"]["ml2_checks_passed"] = passed
            except Exception:
                pass

    # Determine overall status
    if findings["issues"]:
        findings["status"] = "needs_attention"
    elif findings["stats"]:
        findings["status"] = "healthy"

    return findings


def generate_unified_report(output_dir, results, company, timestamp):
    """Generate a combined HTML compliance dashboard."""

    bot_sections = []
    overall_issues = []
    controls_covered = []
    controls_with_issues = []

    for bot_key, (success, report_path, evidence_paths, findings) in results.items():
        cfg = BOTS[bot_key]
        controls_covered.extend(cfg["controls"])

        if not success:
            status_badge = '<span class="badge badge-error">Failed</span>'
            bot_html = f"""
            <div class="bot-card">
                <div class="bot-header">
                    <h3>{cfg['name']}</h3>
                    {status_badge}
                </div>
                <p class="bot-controls">{' · '.join(cfg['controls'])}</p>
                <p class="error-msg">Bot execution failed. Check logs above.</p>
            </div>"""
        else:
            if findings["issues"]:
                status_badge = '<span class="badge badge-warn">Needs Attention</span>'
                for ctrl in cfg["controls"]:
                    if ctrl not in controls_with_issues:
                        controls_with_issues.append(ctrl)
            else:
                status_badge = '<span class="badge badge-ok">Healthy</span>'

            overall_issues.extend(findings["issues"])

            # Stats table
            stats_rows = ""
            for k, v in findings["stats"].items():
                label = k.replace("_", " ").title()
                stats_rows += f"<tr><td>{label}</td><td><strong>{v}</strong></td></tr>\n"

            # Issues list
            issues_html = ""
            if findings["issues"]:
                issues_items = "".join(f"<li>⚠️ {i}</li>" for i in findings["issues"])
                issues_html = f'<div class="issues"><ul>{issues_items}</ul></div>'

            # Report link
            report_link = ""
            if report_path:
                rel = os.path.relpath(report_path, output_dir)
                report_link = f'<a href="{rel}" class="report-link">📄 View detailed report</a>'

            bot_html = f"""
            <div class="bot-card">
                <div class="bot-header">
                    <h3>{cfg['name']}</h3>
                    {status_badge}
                </div>
                <p class="bot-controls">{' · '.join(cfg['controls'])}</p>
                {issues_html}
                <table class="stats-table">
                    {stats_rows}
                </table>
                {report_link}
            </div>"""

        bot_sections.append(bot_html)

    # E8 coverage matrix
    e8_rows = ""
    for ctrl in E8_CONTROLS:
        if ctrl in controls_covered:
            if ctrl in controls_with_issues:
                icon = "⚠️"
                cls = "warn"
            else:
                icon = "✅"
                cls = "ok"
        else:
            icon = "⬜"
            cls = "skip"
        e8_rows += f'<tr class="e8-{cls}"><td>{icon}</td><td>{ctrl}</td></tr>\n'

    # Overall score
    total_controls = len(E8_CONTROLS)
    covered = sum(1 for c in E8_CONTROLS if c in controls_covered)
    ok = covered - len([c for c in controls_with_issues if c in E8_CONTROLS])
    score_pct = round(ok / total_controls * 100) if total_controls else 0

    if score_pct >= 80:
        score_color = "#22c55e"
        score_label = "Strong"
    elif score_pct >= 50:
        score_color = "#eab308"
        score_label = "Moderate"
    else:
        score_color = "#ef4444"
        score_label = "Needs Work"

    # Top issues
    top_issues_html = ""
    if overall_issues:
        items = "".join(f"<li>{i}</li>" for i in overall_issues[:10])
        top_issues_html = f"""
        <div class="section">
            <h2>⚠️ Priority Issues</h2>
            <ol class="priority-issues">{items}</ol>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>E8CR — Essential Eight Compliance Assessment</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: #0f172a;
        color: #e2e8f0;
        padding: 2rem;
        line-height: 1.6;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .header {{
        text-align: center;
        padding: 2rem 0;
        border-bottom: 1px solid #1e293b;
        margin-bottom: 2rem;
    }}
    .header h1 {{ font-size: 2rem; color: #f8fafc; margin-bottom: 0.5rem; }}
    .header .subtitle {{ color: #94a3b8; font-size: 1.1rem; }}
    .header .meta {{ color: #64748b; font-size: 0.85rem; margin-top: 0.5rem; }}

    .score-ring {{
        width: 160px; height: 160px;
        border-radius: 50%;
        background: conic-gradient({score_color} {score_pct * 3.6}deg, #1e293b {score_pct * 3.6}deg);
        display: flex; align-items: center; justify-content: center;
        margin: 1.5rem auto;
        position: relative;
    }}
    .score-inner {{
        width: 130px; height: 130px;
        border-radius: 50%;
        background: #0f172a;
        display: flex; flex-direction: column;
        align-items: center; justify-content: center;
    }}
    .score-pct {{ font-size: 2.5rem; font-weight: 700; color: {score_color}; }}
    .score-label {{ font-size: 0.85rem; color: #94a3b8; }}

    .summary-cards {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1rem;
        margin-bottom: 2rem;
    }}
    .summary-card {{
        background: #1e293b;
        border-radius: 8px;
        padding: 1.2rem;
        text-align: center;
    }}
    .summary-card .value {{ font-size: 1.8rem; font-weight: 700; }}
    .summary-card .label {{ color: #94a3b8; font-size: 0.85rem; }}

    .section {{ margin-bottom: 2rem; }}
    .section h2 {{ font-size: 1.4rem; margin-bottom: 1rem; color: #f8fafc; }}

    .e8-matrix {{
        background: #1e293b;
        border-radius: 8px;
        overflow: hidden;
    }}
    .e8-matrix table {{ width: 100%; border-collapse: collapse; }}
    .e8-matrix td {{ padding: 0.8rem 1rem; border-bottom: 1px solid #0f172a; }}
    .e8-matrix td:first-child {{ width: 40px; text-align: center; }}
    .e8-ok td {{ color: #22c55e; }}
    .e8-warn td {{ color: #eab308; }}
    .e8-skip td {{ color: #64748b; }}

    .bot-card {{
        background: #1e293b;
        border-radius: 8px;
        padding: 1.5rem;
        margin-bottom: 1rem;
    }}
    .bot-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.5rem;
    }}
    .bot-header h3 {{ font-size: 1.1rem; }}
    .bot-controls {{ color: #64748b; font-size: 0.85rem; margin-bottom: 1rem; }}
    .badge {{
        padding: 0.25rem 0.75rem;
        border-radius: 12px;
        font-size: 0.8rem;
        font-weight: 600;
    }}
    .badge-ok {{ background: #052e16; color: #22c55e; }}
    .badge-warn {{ background: #422006; color: #eab308; }}
    .badge-error {{ background: #450a0a; color: #ef4444; }}

    .stats-table {{ width: 100%; border-collapse: collapse; margin: 0.5rem 0; }}
    .stats-table td {{
        padding: 0.4rem 0;
        border-bottom: 1px solid #0f172a44;
        font-size: 0.9rem;
    }}
    .stats-table td:last-child {{ text-align: right; }}

    .issues {{ margin: 0.5rem 0; }}
    .issues ul {{ list-style: none; }}
    .issues li {{
        padding: 0.3rem 0;
        color: #eab308;
        font-size: 0.9rem;
    }}

    .priority-issues {{
        background: #1e293b;
        border-radius: 8px;
        padding: 1rem 1rem 1rem 2rem;
    }}
    .priority-issues li {{
        padding: 0.4rem 0;
        color: #eab308;
    }}

    .report-link {{
        display: inline-block;
        margin-top: 0.5rem;
        color: #60a5fa;
        text-decoration: none;
        font-size: 0.9rem;
    }}
    .report-link:hover {{ text-decoration: underline; }}

    .footer {{
        text-align: center;
        padding: 2rem 0;
        color: #475569;
        font-size: 0.8rem;
        border-top: 1px solid #1e293b;
        margin-top: 2rem;
    }}
    .footer a {{ color: #60a5fa; text-decoration: none; }}

    @media print {{
        body {{ background: white; color: #1e293b; padding: 1rem; }}
        .bot-card, .e8-matrix, .summary-card, .priority-issues {{
            background: #f8fafc; border: 1px solid #e2e8f0;
        }}
        .score-ring {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }}
    }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🛡️ Essential Eight Compliance Assessment</h1>
        <div class="subtitle">{company}</div>
        <div class="meta">Generated {timestamp} · E8CR Squad v1.0 · Maturity Level 2 target</div>
    </div>

    <div class="score-ring">
        <div class="score-inner">
            <div class="score-pct">{score_pct}%</div>
            <div class="score-label">{score_label}</div>
        </div>
    </div>

    <div class="summary-cards">
        <div class="summary-card">
            <div class="value">{covered}/{total_controls}</div>
            <div class="label">Controls Assessed</div>
        </div>
        <div class="summary-card">
            <div class="value">{ok}</div>
            <div class="label">Controls Healthy</div>
        </div>
        <div class="summary-card">
            <div class="value" style="color: #eab308">{len(overall_issues)}</div>
            <div class="label">Issues Found</div>
        </div>
        <div class="summary-card">
            <div class="value">{len([k for k, v in results.items() if v[0]])}/{len(results)}</div>
            <div class="label">Bots Completed</div>
        </div>
    </div>

    {top_issues_html}

    <div class="section">
        <h2>📋 Essential Eight Matrix</h2>
        <div class="e8-matrix">
            <table>
                {e8_rows}
            </table>
        </div>
    </div>

    <div class="section">
        <h2>🤖 Bot Results</h2>
        {''.join(bot_sections)}
    </div>

    <div class="footer">
        Generated by <a href="https://github.com/RADobson/e8cr-squad">E8CR Squad</a> ·
        Open-source Essential Eight compliance automation ·
        Apache-2.0 License
    </div>
</div>
</body>
</html>"""

    report_path = os.path.join(output_dir, "e8cr-assessment.html")
    with open(report_path, "w") as f:
        f.write(html)
    return report_path


def main():
    parser = argparse.ArgumentParser(
        description="E8CR Squad — Unified Essential Eight Compliance Assessment (4 bots: vmpm, identity, appcontrol, backup)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 run_all.py --demo --output /tmp/e8cr-assessment
  python3 run_all.py --demo --bots vmpm identity backup
  python3 run_all.py --demo --company "Acme Corp" --output ./report
        """
    )
    parser.add_argument("--demo", action="store_true",
                        help="Run in demo mode with synthetic data (no tenant needed)")
    parser.add_argument("--output", default="./e8cr-output",
                        help="Output directory for all reports and evidence (default: ./e8cr-output)")
    parser.add_argument("--bots", nargs="+", choices=list(BOTS.keys()),
                        help="Run specific bots only (default: all)")
    parser.add_argument("--company", default="Meridian Civil Group",
                        help="Company name for report branding")
    args = parser.parse_args()

    if not args.demo:
        # Check for required env vars in live mode
        required = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"]
        missing = [v for v in required if not os.environ.get(v)]
        if missing:
            print(f"❌ Live mode requires: {', '.join(missing)}")
            print("   Set these environment variables or use --demo for synthetic data.")
            sys.exit(1)

    bots_to_run = args.bots or list(BOTS.keys())
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print(f"""
╔══════════════════════════════════════════════════════════╗
║   E8CR Squad — Essential Eight Compliance Assessment     ║
║   4 Bots: VM+PM · Identity · App Control · Backup       ║
╠══════════════════════════════════════════════════════════╣
║   Company:  {args.company:<44s} ║
║   Mode:     {'Demo (synthetic data)' if args.demo else 'Live (tenant connected)':<44s} ║
║   Bots:     {', '.join(bots_to_run):<44s} ║
║   Output:   {output_dir:<44s} ║
║   Time:     {timestamp:<44s} ║
╚══════════════════════════════════════════════════════════╝
    """)

    results = {}
    for bot_key in bots_to_run:
        cfg = BOTS[bot_key]
        success, report_path, evidence_paths = run_bot(bot_key, cfg, output_dir, demo=args.demo)

        # Parse evidence for summary
        bot_output = os.path.join(output_dir, bot_key)
        findings = parse_bot_results(bot_key, bot_output)
        results[bot_key] = (success, report_path, evidence_paths, findings)

    # Generate unified report
    print(f"\n{'='*60}")
    print(f"  📊 Generating unified compliance report...")
    print(f"{'='*60}")

    report_path = generate_unified_report(output_dir, results, args.company, timestamp)

    # Summary
    succeeded = sum(1 for v in results.values() if v[0])
    total_issues = sum(len(v[3]["issues"]) for v in results.values())

    print(f"""
╔══════════════════════════════════════════════════════════╗
║                    Assessment Complete                    ║
╠══════════════════════════════════════════════════════════╣
║   Bots run:     {f"{succeeded}/{len(results)}":<42s} ║
║   Issues found: {f"{total_issues}":<42s} ║
║   Report:       {os.path.basename(report_path):<42s} ║
╚══════════════════════════════════════════════════════════╝

  📄 Open the report:  file://{report_path}

  Individual bot reports:""")

    for bot_key, (success, rpath, _, _) in results.items():
        if success and rpath:
            print(f"    • {BOTS[bot_key]['name']}: file://{rpath}")

    print()


if __name__ == "__main__":
    main()
