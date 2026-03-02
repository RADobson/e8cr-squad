#!/usr/bin/env python3
"""Alert triage engine with threat intel enrichment and scoring."""

import argparse
import json
import os
from datetime import datetime
from threat_intel import sample_hash_intel, sample_ip_intel


def enrich_alert(alert, intel_data):
    """Combine alert with threat intelligence."""
    return {
        **alert,
        "enriched_at": datetime.now().isoformat() + "Z",
        "threat_intel": intel_data,
    }


def score_alert(alert):
    """Compute risk score (0-100) based on alert + intel."""
    base_score = {"low": 25, "medium": 50, "high": 75, "critical": 90}.get(alert["severity"], 50)
    
    intel = alert.get("threat_intel", {})
    if intel.get("known_malware"):
        base_score = min(100, base_score + 20)
    if intel.get("reputation") == "malicious":
        base_score = min(100, base_score + 15)
    
    return base_score


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="alerts JSON file")
    p.add_argument("--output", required=True, help="output triaged alerts")
    args = p.parse_args()

    with open(args.input, "r") as f:
        data = json.load(f)

    alerts = data.get("alerts", []) if isinstance(data, dict) else data

    triaged = []
    for alert in alerts:
        # Enrich with threat intel
        if "sha256" in alert:
            intel = sample_hash_intel(alert["sha256"])
        elif "ip" in alert:
            intel = sample_ip_intel(alert["ip"])
        else:
            intel = {}

        enriched = enrich_alert(alert, intel)
        enriched["risk_score"] = score_alert(enriched)
        triaged.append(enriched)

    out = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "total": len(triaged),
        "high_risk": len([a for a in triaged if a["risk_score"] >= 75]),
        "alerts": triaged,
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(out, f, indent=2)
    
    print(args.output)


if __name__ == "__main__":
    main()
