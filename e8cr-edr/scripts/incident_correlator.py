#!/usr/bin/env python3
"""Correlate related alerts into incidents and build attack timelines.

Groups alerts by device/user overlap, temporal proximity, and MITRE ATT&CK chain logic.
Produces incident objects with kill-chain stage mapping.
"""

import argparse
import json
from datetime import datetime, timedelta
from collections import defaultdict

# MITRE ATT&CK kill chain stages (ordered)
KILL_CHAIN = [
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution",
    "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
    "Discovery", "LateralMovement", "Collection", "CommandAndControl",
    "Exfiltration", "Impact",
]

CATEGORY_TO_STAGE = {
    "InitialAccess": "InitialAccess",
    "Execution": "Execution",
    "Persistence": "Persistence",
    "PrivilegeEscalation": "PrivilegeEscalation",
    "DefenseEvasion": "DefenseEvasion",
    "CredentialAccess": "CredentialAccess",
    "Discovery": "Discovery",
    "LateralMovement": "LateralMovement",
    "Collection": "Collection",
    "CommandAndControl": "CommandAndControl",
    "Exfiltration": "Exfiltration",
    "Impact": "Impact",
    "SuspiciousActivity": "Discovery",
}


def parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00").replace("+00:00", ""))
    except Exception:
        return datetime.min


def correlate(triaged_alerts: list, time_window_hours: int = 4) -> list:
    """Group alerts into incidents based on shared devices/users and temporal proximity."""

    # Build adjacency — alerts sharing devices or users within time window
    groups = []  # list of sets of alert indices
    alert_to_group = {}

    for i, a in enumerate(triaged_alerts):
        if a.get("action") == "auto_resolve":
            continue

        devices_a = set(a.get("devices", []))
        users_a = set(a.get("users", []))
        ts_a = parse_ts(a.get("created", ""))

        merged = False
        for gi, group in enumerate(groups):
            for j in group:
                b = triaged_alerts[j]
                devices_b = set(b.get("devices", []))
                users_b = set(b.get("users", []))
                ts_b = parse_ts(b.get("created", ""))

                # Check overlap
                device_overlap = bool(devices_a & devices_b)
                user_overlap = bool(users_a & users_b)
                time_close = abs((ts_a - ts_b).total_seconds()) < time_window_hours * 3600

                if (device_overlap or user_overlap) and time_close:
                    group.add(i)
                    alert_to_group[i] = gi
                    merged = True
                    break
            if merged:
                break

        if not merged:
            alert_to_group[i] = len(groups)
            groups.append({i})

    # Build incident objects
    incidents = []
    for gi, group in enumerate(groups):
        if len(group) < 1:
            continue

        alerts_in_group = [triaged_alerts[i] for i in sorted(group)]
        alerts_in_group.sort(key=lambda x: parse_ts(x.get("created", "")))

        # Determine kill chain stages
        stages = []
        for a in alerts_in_group:
            stage = CATEGORY_TO_STAGE.get(a.get("category", ""), "Unknown")
            if stage not in stages:
                stages.append(stage)

        # Sort stages by kill chain order
        stages.sort(key=lambda s: KILL_CHAIN.index(s) if s in KILL_CHAIN else 99)

        # Collect all devices and users
        all_devices = set()
        all_users = set()
        max_priority = 0
        for a in alerts_in_group:
            all_devices.update(a.get("devices", []))
            all_users.update(a.get("users", []))
            max_priority = max(max_priority, a.get("priority", 0))

        # Multi-stage attack chain?
        is_attack_chain = len(stages) >= 3

        incidents.append({
            "incidentId": f"INC-{gi + 1:04d}",
            "alertCount": len(alerts_in_group),
            "alerts": [a.get("id") for a in alerts_in_group],
            "killChainStages": stages,
            "isAttackChain": is_attack_chain,
            "devices": sorted(all_devices),
            "users": sorted(all_users),
            "maxPriority": max_priority,
            "severity": "critical" if is_attack_chain or max_priority >= 40 else
                        "high" if max_priority >= 30 else
                        "medium" if max_priority >= 20 else "low",
            "firstSeen": alerts_in_group[0].get("created", ""),
            "lastSeen": alerts_in_group[-1].get("created", ""),
            "timeline": [
                {
                    "time": a.get("created", ""),
                    "title": a.get("title", ""),
                    "stage": CATEGORY_TO_STAGE.get(a.get("category", ""), "Unknown"),
                    "severity": a.get("severity", ""),
                    "mitre": a.get("mitre_techniques", []),
                }
                for a in alerts_in_group
            ],
        })

    incidents.sort(key=lambda x: x["maxPriority"], reverse=True)
    return incidents


def main():
    p = argparse.ArgumentParser(description="Correlate alerts into incidents")
    p.add_argument("--input", required=True, help="Triaged alerts JSON file")
    p.add_argument("--window", type=int, default=4, help="Time window in hours for correlation")
    p.add_argument("--output", help="Output file")
    args = p.parse_args()

    with open(args.input, "r") as f:
        data = json.load(f)

    triaged = data.get("triaged", [])
    incidents = correlate(triaged, args.window)

    result = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "incidentCount": len(incidents),
        "attackChains": len([i for i in incidents if i["isAttackChain"]]),
        "incidents": incidents,
    }

    out = json.dumps(result, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(out)
        print(f"Written to {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
