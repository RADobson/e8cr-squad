#!/usr/bin/env python3
"""Full EDR demo pipeline: alerts → triage → correlation → response → HTML report."""

import json
import os
import sys
from datetime import datetime

# Add script dir to path
sys.path.insert(0, os.path.dirname(__file__))

from defender_alerts import generate_demo_alerts, triage_alert
from defender_response import demo_response_actions
from incident_correlator import correlate
import importlib.util
_spec = importlib.util.spec_from_file_location("edr_report", os.path.join(os.path.dirname(__file__), "generate_report.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
generate_html = _mod.generate_html


def main():
    import argparse
    p = argparse.ArgumentParser(description="Generate full EDR demo artifacts")
    p.add_argument("--output-dir", default="/tmp/e8cr-demo/edr", help="Output directory")
    args = p.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # 1. Generate demo alerts
    raw_alerts = generate_demo_alerts()
    triaged = [triage_alert(a) for a in raw_alerts]
    triaged.sort(key=lambda x: x["priority"], reverse=True)

    actions_summary = {}
    for t in triaged:
        actions_summary[t["action"]] = actions_summary.get(t["action"], 0) + 1

    alerts_data = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "alertCount": len(raw_alerts),
        "summary": actions_summary,
        "triaged": triaged,
    }

    # 2. Correlate into incidents
    incidents = correlate(triaged)
    incidents_data = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "incidentCount": len(incidents),
        "attackChains": len([i for i in incidents if i["isAttackChain"]]),
        "incidents": incidents,
    }

    # 3. Demo response actions
    actions_data = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "actions": demo_response_actions(),
    }

    # 4. Write JSON artifacts
    for name, data in [("alerts.json", alerts_data), ("incidents.json", incidents_data), ("actions.json", actions_data)]:
        path = os.path.join(args.output_dir, name)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"  ✅ {path}")

    # 5. Generate HTML report
    html = generate_html(alerts_data, incidents_data, actions_data)
    report_path = os.path.join(args.output_dir, "edr-report.html")
    with open(report_path, "w") as f:
        f.write(html)
    print(f"  ✅ {report_path}")

    # Summary
    print(f"\n📊 EDR Demo Summary:")
    print(f"   Alerts: {len(raw_alerts)}")
    print(f"   Auto-resolved FPs: {actions_summary.get('auto_resolve', 0)}")
    print(f"   Escalated: {actions_summary.get('escalate_immediate', 0) + actions_summary.get('escalate', 0)}")
    print(f"   Incidents: {len(incidents)}")
    print(f"   Attack chains: {incidents_data['attackChains']}")
    print(f"   Response actions: {len(actions_data['actions'])}")
    print(f"\n   Report: {report_path}")


if __name__ == "__main__":
    main()
