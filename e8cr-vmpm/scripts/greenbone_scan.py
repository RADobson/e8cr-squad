#!/usr/bin/env python3
"""Greenbone/OpenVAS vulnerability scanning via GMP (Greenbone Management Protocol).

Usage:
    python3 greenbone_scan.py --action targets                           # List targets
    python3 greenbone_scan.py --action create-target --name "LAN" --hosts "192.168.1.0/24"
    python3 greenbone_scan.py --action scanners                          # List scanners
    python3 greenbone_scan.py --action configs                           # List scan configs
    python3 greenbone_scan.py --action scan --target-id <id>             # Start scan (full & fast)
    python3 greenbone_scan.py --action scan --target-id <id> --config-name "Full and deep"
    python3 greenbone_scan.py --action status --task-id <id>             # Check progress
    python3 greenbone_scan.py --action results --task-id <id>            # Get results
    python3 greenbone_scan.py --action results --task-id <id> --min-severity 7.0
    python3 greenbone_scan.py --action export --task-id <id> --output results.json

Requires: GREENBONE_HOST, GREENBONE_PORT, GREENBONE_USER, GREENBONE_PASSWORD env vars.
Also requires python-gvm: pip install python-gvm
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone

try:
    from gvm.connections import UnixSocketConnection, TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
    from lxml import etree
except ImportError:
    print("ERROR: python-gvm required. Install: pip install python-gvm lxml", file=sys.stderr)
    sys.exit(1)


def get_connection():
    """Create GMP connection based on env vars."""
    host = os.environ.get("GREENBONE_HOST", "127.0.0.1")
    port = int(os.environ.get("GREENBONE_PORT", "9390"))
    socket_path = os.environ.get("GREENBONE_SOCKET")

    if socket_path:
        return UnixSocketConnection(path=socket_path)
    else:
        return TLSConnection(hostname=host, port=port)


def get_credentials():
    user = os.environ.get("GREENBONE_USER", "admin")
    password = os.environ.get("GREENBONE_PASSWORD")
    if not password:
        print("ERROR: GREENBONE_PASSWORD not set", file=sys.stderr)
        sys.exit(1)
    return user, password


def xml_to_dict(element):
    """Convert lxml element to dict (simple)."""
    result = {}
    for child in element:
        tag = child.tag
        if len(child):
            result[tag] = xml_to_dict(child)
        else:
            result[tag] = child.text
    if element.attrib:
        result["_id"] = element.attrib.get("id", "")
    return result


def list_targets(gmp):
    resp = gmp.get_targets()
    targets = resp.findall("target")
    results = []
    for t in targets:
        results.append({
            "id": t.attrib.get("id"),
            "name": t.findtext("name"),
            "hosts": t.findtext("hosts"),
            "comment": t.findtext("comment", ""),
        })
    return results


def create_target(gmp, name, hosts, comment=""):
    resp = gmp.create_target(name=name, hosts=[hosts], comment=comment)
    target_id = resp.attrib.get("id")
    status = resp.attrib.get("status")
    return {"id": target_id, "status": status, "name": name, "hosts": hosts}


def list_scanners(gmp):
    resp = gmp.get_scanners()
    scanners = resp.findall("scanner")
    return [{"id": s.attrib.get("id"), "name": s.findtext("name"),
             "type": s.findtext("type")} for s in scanners]


def list_configs(gmp):
    resp = gmp.get_scan_configs()
    configs = resp.findall("config")
    return [{"id": c.attrib.get("id"), "name": c.findtext("name")} for c in configs]


def start_scan(gmp, target_id, config_name="Full and fast"):
    # Find config ID by name
    configs = list_configs(gmp)
    config = next((c for c in configs if config_name.lower() in c["name"].lower()), None)
    if not config:
        print(f"ERROR: Scan config '{config_name}' not found. Available:", file=sys.stderr)
        for c in configs:
            print(f"  - {c['name']} ({c['id']})", file=sys.stderr)
        sys.exit(1)

    # Find default scanner
    scanners = list_scanners(gmp)
    scanner = next((s for s in scanners if "openvas" in s["name"].lower()), scanners[0] if scanners else None)
    if not scanner:
        print("ERROR: No scanner found", file=sys.stderr)
        sys.exit(1)

    # Create task
    task_name = f"E8CR Scan {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}"
    resp = gmp.create_task(
        name=task_name,
        config_id=config["id"],
        target_id=target_id,
        scanner_id=scanner["id"],
    )
    task_id = resp.attrib.get("id")

    # Start the task
    gmp.start_task(task_id)

    return {"task_id": task_id, "task_name": task_name,
            "config": config["name"], "scanner": scanner["name"]}


def check_status(gmp, task_id):
    resp = gmp.get_task(task_id)
    task = resp.find("task")
    if task is None:
        return {"error": "Task not found"}

    status = task.findtext("status", "Unknown")
    progress_el = task.find("progress")
    progress = progress_el.text if progress_el is not None and progress_el.text else "0"

    return {
        "task_id": task_id,
        "name": task.findtext("name"),
        "status": status,
        "progress": f"{progress}%",
    }


def get_results(gmp, task_id, min_severity=0.0):
    """Get vulnerability results for a task."""
    resp = gmp.get_results(task_id=task_id)
    results_el = resp.findall("result")

    results = []
    for r in results_el:
        severity = float(r.findtext("severity", "0"))
        if severity < min_severity:
            continue

        host_el = r.find("host")
        host = host_el.text if host_el is not None else "Unknown"

        nvt = r.find("nvt")
        cve_list = []
        if nvt is not None:
            refs = nvt.find("refs")
            if refs is not None:
                for ref in refs.findall("ref"):
                    if ref.attrib.get("type") == "cve":
                        cve_list.append(ref.attrib.get("id", ""))

        results.append({
            "id": r.attrib.get("id"),
            "host": host,
            "port": r.findtext("port", ""),
            "severity": severity,
            "severity_label": severity_label(severity),
            "name": nvt.findtext("name", "") if nvt is not None else "",
            "oid": nvt.attrib.get("oid", "") if nvt is not None else "",
            "cves": cve_list,
            "solution": r.findtext("solution", ""),
            "description": r.findtext("description", "")[:500],
        })

    # Sort by severity descending
    results.sort(key=lambda x: x["severity"], reverse=True)
    return results


def severity_label(score):
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    return "Info"


def format_results(results):
    """Pretty-print scan results."""
    if not results:
        print("No results found.")
        return

    crit = sum(1 for r in results if r["severity"] >= 9.0)
    high = sum(1 for r in results if 7.0 <= r["severity"] < 9.0)
    med = sum(1 for r in results if 4.0 <= r["severity"] < 7.0)
    low = sum(1 for r in results if 0 < r["severity"] < 4.0)

    print(f"Total findings: {len(results)}  "
          f"[Critical: {crit} | High: {high} | Medium: {med} | Low: {low}]")
    print()
    print(f"{'Severity':<10} {'Host':<18} {'Port':<12} {'CVEs':<20} {'Name':<50}")
    print("-" * 110)

    for r in results[:50]:
        sev = f"{r['severity']:.1f} {r['severity_label']}"
        cves = ",".join(r["cves"][:2]) if r["cves"] else "-"
        name = r["name"][:49]
        print(f"{sev:<10} {r['host']:<18} {r['port']:<12} {cves:<20} {name:<50}")

    if len(results) > 50:
        print(f"\n... and {len(results) - 50} more findings")


def main():
    parser = argparse.ArgumentParser(description="Greenbone vulnerability scanning")
    parser.add_argument("--action", required=True,
                        choices=["targets", "create-target", "scanners", "configs",
                                 "scan", "status", "results", "export"])
    parser.add_argument("--name", help="Target name")
    parser.add_argument("--hosts", help="Target hosts (CIDR or comma-separated)")
    parser.add_argument("--target-id", help="Target ID for scan")
    parser.add_argument("--task-id", help="Task ID for status/results")
    parser.add_argument("--config-name", default="Full and fast", help="Scan config name")
    parser.add_argument("--min-severity", type=float, default=0.0,
                        help="Minimum severity filter")
    parser.add_argument("--output", help="Output file")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    connection = get_connection()
    user, password = get_credentials()

    with Gmp(connection=connection, transform=EtreeTransform()) as gmp:
        gmp.authenticate(user, password)

        if args.action == "targets":
            targets = list_targets(gmp)
            print(json.dumps(targets, indent=2))

        elif args.action == "create-target":
            if not args.name or not args.hosts:
                print("ERROR: --name and --hosts required", file=sys.stderr)
                sys.exit(1)
            result = create_target(gmp, args.name, args.hosts)
            print(json.dumps(result, indent=2))

        elif args.action == "scanners":
            print(json.dumps(list_scanners(gmp), indent=2))

        elif args.action == "configs":
            print(json.dumps(list_configs(gmp), indent=2))

        elif args.action == "scan":
            if not args.target_id:
                print("ERROR: --target-id required", file=sys.stderr)
                sys.exit(1)
            result = start_scan(gmp, args.target_id, args.config_name)
            print(json.dumps(result, indent=2))

        elif args.action == "status":
            if not args.task_id:
                print("ERROR: --task-id required", file=sys.stderr)
                sys.exit(1)
            print(json.dumps(check_status(gmp, args.task_id), indent=2))

        elif args.action == "results":
            if not args.task_id:
                print("ERROR: --task-id required", file=sys.stderr)
                sys.exit(1)
            results = get_results(gmp, args.task_id, args.min_severity)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                format_results(results)

        elif args.action == "export":
            if not args.task_id:
                print("ERROR: --task-id required", file=sys.stderr)
                sys.exit(1)
            results = get_results(gmp, args.task_id, args.min_severity)
            output = args.output or "scan-results.json"
            with open(output, "w") as f:
                json.dump({
                    "exported_at": datetime.now(timezone.utc).isoformat(),
                    "task_id": args.task_id,
                    "total_findings": len(results),
                    "results": results
                }, f, indent=2)
            print(f"Exported {len(results)} findings to {output}")


if __name__ == "__main__":
    main()
